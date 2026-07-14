//! BGP inbound TCP listener.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use crate::config::{
    TCP_AO_MAX_INSPECT_KEYS, TcpAoConfig, TcpAoKeyring, TcpAoRotationGeneration,
    TcpAoRotationPhase, TcpAoRotationStatus,
};
use crate::socket_opts::TcpAoInfoSnapshot;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, info, warn};

/// Match Tokio's default listener backlog.
const DEFAULT_LISTEN_BACKLOG: i32 = 1024;
const TCP_AO_ROTATION_CONTROL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// An accepted inbound TCP connection.
pub struct AcceptedConnection {
    /// The raw TCP stream for the accepted connection.
    pub stream: TcpStream,
    /// Socket address of the remote peer, including IPv6 scope when available.
    pub peer_addr: SocketAddr,
    /// Runtime TCP-AO socket information when the peer matched a configured
    /// listener MKT and Linux inspection succeeded.
    pub tcp_ao_info: Option<TcpAoInfoSnapshot>,
    /// Immutable listener generation against which this protected child was
    /// reconciled. `None` for plaintext/MD5 accepts.
    pub tcp_ao_generation: Option<TcpAoRotationGeneration>,
}

/// TCP-AO key to install on the inbound listener socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoListenerKey {
    /// Configuration owner kind. This remains explicit even for host-length
    /// dynamic ranges so passive-open resolution never infers ownership from
    /// prefix length.
    pub owner: TcpAoListenerOwnerKind,
    /// Remote network address matched by this listener MKT.
    pub peer: IpAddr,
    /// Prefix length for the remote network.
    pub prefix_len: u8,
    /// TCP-AO key configuration for the peer.
    pub config: TcpAoKeyring,
}

/// Configuration owner of a listener MKT selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpAoListenerOwnerKind {
    /// Exact static-neighbor address.
    Static,
    /// Dynamic-neighbor prefix, including `/32` and `/128` ranges.
    Dynamic,
}

/// Socket options installed before the BGP listener enters `listen(2)`.
#[derive(Clone, Default)]
pub struct ListenerSocketOptions {
    /// Static-neighbor TCP-AO MKTs for passive opens.
    pub tcp_ao_keys: Vec<TcpAoListenerKey>,
}

/// BGP inbound listener. Accepts TCP connections and forwards them
/// to the `PeerManager` for matching against known peers.
pub struct BgpListener {
    listener: TcpListener,
    accept_tx: mpsc::Sender<AcceptedConnection>,
    tcp_ao_keys: TcpAoListenerKeyIndex,
    /// Latest generation installed in the listener kernel inventory. This may
    /// lead the globally committed generation while sessions are applying.
    tcp_ao_generation: TcpAoRotationGeneration,
    /// Complete immediately previous listener generation retained only to
    /// reconcile children that completed before the last successful add-only
    /// listener flip. No older history is accepted.
    previous_tcp_ao_generation: Option<TcpAoPreviousListenerGeneration>,
    tcp_ao_committed_generation: TcpAoRotationGeneration,
    rotation_rx: mpsc::Receiver<TcpAoListenerCommand>,
    rotation_tx: mpsc::Sender<TcpAoListenerCommand>,
    rotation_status_tx: watch::Sender<TcpAoRotationStatus>,
    /// Exact desired inventory retained across a failed generation. A retry
    /// may reconcile partial kernel additions, but may not redefine what the
    /// generation means.
    pending_tcp_ao_generation: Option<TcpAoListenerGeneration>,
}

struct TcpAoPreviousListenerGeneration {
    generation: TcpAoRotationGeneration,
    keys: TcpAoListenerKeyIndex,
}

/// One immutable desired listener inventory for the add-only rotation phase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAoListenerGeneration {
    /// Global immutable inventory identity.
    pub generation: TcpAoRotationGeneration,
    /// Complete desired listener owner/key inventory.
    pub keys: Arc<[TcpAoListenerKey]>,
}

impl TcpAoListenerGeneration {
    #[must_use]
    pub fn new(generation: TcpAoRotationGeneration, keys: Vec<TcpAoListenerKey>) -> Self {
        Self {
            generation,
            keys: keys.into(),
        }
    }
}

enum TcpAoListenerCommand {
    PreflightAddOnly {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<()>>,
    },
    ApplyAddOnly {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<TcpAoRotationStatus>>,
    },
    MarkDependentFailure {
        generation: TcpAoRotationGeneration,
        error: String,
        reply: oneshot::Sender<std::io::Result<()>>,
    },
    AcknowledgeGlobalCommit {
        generation: TcpAoRotationGeneration,
        reply: oneshot::Sender<std::io::Result<TcpAoRotationStatus>>,
    },
}

/// Bounded control handle for listener-owned TCP-AO add-only generations.
#[derive(Clone)]
pub struct TcpAoListenerHandle {
    tx: mpsc::Sender<TcpAoListenerCommand>,
    status_rx: watch::Receiver<TcpAoRotationStatus>,
}

impl TcpAoListenerHandle {
    /// Validate the complete desired listener inventory against kernel state
    /// without issuing a target-socket `setsockopt`.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener task is unavailable, the control
    /// deadline expires, or metadata/kernel reconciliation fails closed.
    pub async fn preflight_add_only(
        &self,
        desired: TcpAoListenerGeneration,
    ) -> std::io::Result<()> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::PreflightAddOnly { desired, reply })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "TCP-AO listener rotation task exited",
                    )
                })?;
            response.await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "TCP-AO listener preflight reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener preflight timed out",
            )
        })?
    }

    /// Apply one immutable successor generation. Current/RNext are untouched;
    /// removal, deprecation and owner-boundary changes are rejected.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener task is unavailable or times out,
    /// the candidate is not a strict add-only successor, an MKT cannot be
    /// installed, or the complete kernel inventory cannot be verified.
    pub async fn apply_add_only(
        &self,
        desired: TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::ApplyAddOnly { desired, reply })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "TCP-AO listener rotation task exited",
                    )
                })?;
            response.await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "TCP-AO listener rotation reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener rotation control timed out",
            )
        })?
    }

    /// Latest secret-free desired/applied listener status.
    #[must_use]
    pub fn status(&self) -> TcpAoRotationStatus {
        self.status_rx.borrow().clone()
    }

    /// Mark a later global phase (currently established-session apply) failed
    /// after this listener installed but did not globally commit the desired
    /// generation. A retry reuses the same immutable generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener task is unavailable, the control
    /// deadline expires, or the generation is stale/already committed.
    pub async fn mark_dependent_failure(
        &self,
        generation: TcpAoRotationGeneration,
        error: String,
    ) -> std::io::Result<()> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::MarkDependentFailure {
                    generation,
                    error,
                    reply,
                })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "TCP-AO listener rotation task exited",
                    )
                })?;
            response.await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "TCP-AO listener dependent-failure reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener dependent-failure marker timed out",
            )
        })?
    }

    /// Publish a listener generation as applied only after every established
    /// session has acknowledged the same immutable global generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the listener task is unavailable, the control
    /// deadline expires, or the installed inventory does not exactly match
    /// the generation being committed.
    pub async fn acknowledge_global_commit(
        &self,
        generation: TcpAoRotationGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        let result = tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::AcknowledgeGlobalCommit { generation, reply })
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "TCP-AO listener rotation task exited",
                    )
                })?;
            response.await.map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "TCP-AO listener commit reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener commit acknowledgement timed out",
            )
        });
        match result {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(error)) | Err(error) => {
                let status = self.status();
                if status.phase == TcpAoRotationPhase::Idle
                    && status.desired == generation
                    && status.applied == generation
                {
                    Ok(status)
                } else {
                    Err(error)
                }
            }
        }
    }
}

/// Immutable, family-split owner index for listener MKTs.
///
/// Resolution is deterministic: static exact match first, otherwise dynamic
/// longest-prefix match. Owner kind is explicit so a dynamic `/32` or `/128`
/// remains dynamic and cannot shadow a static neighbor by insertion order.
struct TcpAoListenerKeyIndex {
    keys: Vec<TcpAoListenerKey>,
    v4: Vec<HashMap<u32, Vec<usize>>>,
    v6: Vec<HashMap<u128, Vec<usize>>>,
}

impl TcpAoListenerKeyIndex {
    fn new(keys: Vec<TcpAoListenerKey>) -> Self {
        let mut index = Self {
            v4: (0..=32).map(|_| HashMap::new()).collect(),
            v6: (0..=128).map(|_| HashMap::new()).collect(),
            keys,
        };
        for (key_index, key) in index.keys.iter().enumerate() {
            match key.peer {
                IpAddr::V4(addr) if key.prefix_len <= 32 => {
                    index.v4[usize::from(key.prefix_len)]
                        .entry(mask_v4(addr.into(), key.prefix_len))
                        .or_default()
                        .push(key_index);
                }
                IpAddr::V6(addr) if key.prefix_len <= 128 => {
                    index.v6[usize::from(key.prefix_len)]
                        .entry(mask_v6(addr.into(), key.prefix_len))
                        .or_default()
                        .push(key_index);
                }
                _ => {}
            }
        }
        index
    }

    fn resolve(&self, addr: IpAddr) -> Option<&TcpAoListenerKey> {
        let (static_exact, dynamic) = match addr {
            IpAddr::V4(addr) => {
                let value = u32::from(addr);
                let static_exact = self.v4[32]
                    .get(&value)
                    .into_iter()
                    .flatten()
                    .find(|index| self.keys[**index].owner == TcpAoListenerOwnerKind::Static)
                    .copied();
                let dynamic = self
                    .v4
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(prefix_len, bucket)| {
                        bucket
                            .get(&mask_v4(
                                value,
                                u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                            ))
                            .into_iter()
                            .flatten()
                            .find(|index| {
                                self.keys[**index].owner == TcpAoListenerOwnerKind::Dynamic
                            })
                            .copied()
                    });
                (static_exact, dynamic)
            }
            IpAddr::V6(addr) => {
                let value = u128::from(addr);
                let static_exact = self.v6[128]
                    .get(&value)
                    .into_iter()
                    .flatten()
                    .find(|index| self.keys[**index].owner == TcpAoListenerOwnerKind::Static)
                    .copied();
                let dynamic = self
                    .v6
                    .iter()
                    .enumerate()
                    .rev()
                    .find_map(|(prefix_len, bucket)| {
                        bucket
                            .get(&mask_v6(
                                value,
                                u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                            ))
                            .into_iter()
                            .flatten()
                            .find(|index| {
                                self.keys[**index].owner == TcpAoListenerOwnerKind::Dynamic
                            })
                            .copied()
                    });
                (static_exact, dynamic)
            }
        };
        static_exact
            .or(dynamic)
            .and_then(|index| self.keys.get(index))
    }

    /// Return every configured protected owner whose selector covers `addr`.
    /// Every returned owner's MKT inventory is expected on an accepted child;
    /// the resolved owner controls Current/RNext selection.
    fn owned_union(&self, addr: IpAddr) -> Vec<&TcpAoListenerKey> {
        match addr {
            IpAddr::V4(addr) => self
                .v4
                .iter()
                .enumerate()
                .flat_map(|(prefix_len, bucket)| {
                    bucket
                        .get(&mask_v4(
                            addr.into(),
                            u8::try_from(prefix_len).expect("IPv4 index is bounded to 32"),
                        ))
                        .into_iter()
                        .flatten()
                })
                .filter_map(|index| self.keys.get(*index))
                .collect(),
            IpAddr::V6(addr) => self
                .v6
                .iter()
                .enumerate()
                .flat_map(|(prefix_len, bucket)| {
                    bucket
                        .get(&mask_v6(
                            addr.into(),
                            u8::try_from(prefix_len).expect("IPv6 index is bounded to 128"),
                        ))
                        .into_iter()
                        .flatten()
                })
                .filter_map(|index| self.keys.get(*index))
                .collect(),
        }
    }
}

fn mask_v4(addr: u32, prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        addr & (u32::MAX << (32 - prefix_len))
    }
}

fn mask_v6(addr: u128, prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        addr & (u128::MAX << (128 - prefix_len))
    }
}

impl BgpListener {
    /// Create a new listener bound to the given address.
    ///
    /// # Errors
    ///
    /// Returns an error if binding fails.
    #[allow(
        clippy::unused_async,
        reason = "preserve the existing async public API for callers"
    )]
    pub async fn bind(
        addr: SocketAddr,
        accept_tx: mpsc::Sender<AcceptedConnection>,
    ) -> std::io::Result<Self> {
        Self::bind_with_options(addr, accept_tx, ListenerSocketOptions::default()).await
    }

    /// Create a new listener with explicit pre-listen socket options.
    ///
    /// # Errors
    ///
    /// Returns an error if binding or pre-listen option installation fails.
    #[allow(
        clippy::unused_async,
        reason = "preserve the existing async public API for callers"
    )]
    pub async fn bind_with_options(
        addr: SocketAddr,
        accept_tx: mpsc::Sender<AcceptedConnection>,
        options: ListenerSocketOptions,
    ) -> std::io::Result<Self> {
        let tcp_ao_keys = options.tcp_ao_keys.len();
        let listener = bind_socket2_listener(addr, &options)?;
        let bound_addr = listener.local_addr().unwrap_or(addr);
        info!(
            addr = %bound_addr,
            requested_addr = %addr,
            tcp_ao_keys,
            "BGP listener bound"
        );
        let (rotation_tx, rotation_rx) = mpsc::channel(4);
        let (rotation_status_tx, _) = watch::channel(TcpAoRotationStatus::default());
        Ok(Self {
            listener,
            accept_tx,
            tcp_ao_keys: TcpAoListenerKeyIndex::new(options.tcp_ao_keys),
            tcp_ao_generation: TcpAoRotationGeneration::STARTUP,
            previous_tcp_ao_generation: None,
            tcp_ao_committed_generation: TcpAoRotationGeneration::STARTUP,
            rotation_rx,
            rotation_tx,
            rotation_status_tx,
            pending_tcp_ao_generation: None,
        })
    }

    /// Control handle used by the serialized reload coordinator.
    #[must_use]
    pub fn tcp_ao_rotation_handle(&self) -> TcpAoListenerHandle {
        TcpAoListenerHandle {
            tx: self.rotation_tx.clone(),
            status_rx: self.rotation_status_tx.subscribe(),
        }
    }

    /// Return the local socket address the listener is bound to.
    ///
    /// This is primarily useful for tests that bind port `0`; production
    /// callers already know the configured listen address.
    ///
    /// # Errors
    ///
    /// Returns an error if the OS cannot report the listener's local address.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Run the accept loop until the channel is closed.
    pub async fn run(mut self) {
        loop {
            tokio::select! {
            command = self.rotation_rx.recv() => {
                let Some(command) = command else {
                    // Every external handle was dropped. Accept service remains
                    // valid at the last applied immutable generation.
                    continue;
                };
                match command {
                    TcpAoListenerCommand::PreflightAddOnly { desired, reply } => {
                        let result = self.preflight_add_only_generation(&desired);
                        let _ = reply.send(result);
                    }
                    TcpAoListenerCommand::ApplyAddOnly { desired, reply } => {
                        let result = self.apply_add_only_generation(&desired);
                        let _ = reply.send(result);
                    }
                    TcpAoListenerCommand::MarkDependentFailure { generation, error, reply } => {
                        let result = if generation == self.tcp_ao_generation
                            && generation != self.tcp_ao_committed_generation
                        {
                            let mut status = self.rotation_status_tx.borrow().clone();
                            status.desired = generation;
                            status.applied = self.tcp_ao_committed_generation;
                            status.phase = TcpAoRotationPhase::AddOnlyFailed;
                            status.last_error = Some(error);
                            self.rotation_status_tx.send_replace(status);
                            Ok(())
                        } else {
                            Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "TCP-AO dependent-failure generation is not the installed uncommitted generation",
                            ))
                        };
                        let _ = reply.send(result);
                    }
                    TcpAoListenerCommand::AcknowledgeGlobalCommit { generation, reply } => {
                        let result = self.acknowledge_global_commit_generation(generation);
                        let _ = reply.send(result);
                    }
                }
            }
            accepted = self.listener.accept() => match accepted {
                Ok((stream, peer_addr)) => {
                    let peer_ip = peer_addr.ip();
                    debug!(%peer_ip, "inbound TCP connection");
                    let tcp_ao_info = match self.inspect_tcp_ao_accept(&stream, peer_ip) {
                        Ok(info) => info,
                        Err(err) => {
                            warn!(peer = %peer_ip, error = %err, "rejecting TCP-AO-protected inbound connection");
                            continue;
                        }
                    };
                    let conn = AcceptedConnection {
                        stream,
                        peer_addr,
                        tcp_ao_generation: tcp_ao_info
                            .as_ref()
                            .map(|_| self.tcp_ao_generation),
                        tcp_ao_info,
                    };
                    if self.accept_tx.send(conn).await.is_err() {
                        warn!("accept channel closed, listener shutting down");
                        return;
                    }
                }
                Err(e) => {
                    error!(error = %e, "BGP listener accept error");
                }
            }}
        }
    }

    fn apply_add_only_generation(
        &mut self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        if desired.generation == self.tcp_ao_generation
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice()
        {
            retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
            let status = TcpAoRotationStatus {
                desired: desired.generation,
                applied: self.tcp_ao_committed_generation,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            };
            self.rotation_status_tx.send_replace(status.clone());
            return Ok(status);
        }

        let mut status = TcpAoRotationStatus {
            desired: desired.generation,
            applied: self.tcp_ao_committed_generation,
            phase: TcpAoRotationPhase::AddOnly,
            last_error: None,
        };
        self.rotation_status_tx.send_replace(status.clone());

        let apply = (|| {
            let _additions = plan_add_only_listener_generation(
                &self.tcp_ao_keys.keys,
                desired.keys.as_ref(),
                self.tcp_ao_generation,
                desired.generation,
            )?;
            retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
            let current_owners = self
                .tcp_ao_keys
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            let desired_owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            let preflight = crate::socket_opts::preflight_tcp_ao_add_only(
                &self.listener,
                &current_owners,
                &desired_owners,
                None,
            )?;
            crate::socket_opts::apply_tcp_ao_add_only(
                &self.listener,
                preflight,
                &desired_owners,
                None,
            )
            .map_err(|error| {
                let mutation_started = error.mutation_started();
                let error = error.into_inner();
                if mutation_started {
                    std::io::Error::new(
                        error.kind(),
                        format!(
                            "{error}; listener mutation may be partial, so affected protected passive accepts may reject until this generation is retried or the daemon restarts"
                        ),
                    )
                } else {
                    error
                }
            })?;
            Ok::<(), std::io::Error>(())
        })();

        match apply {
            Ok(()) => {
                let previous_keys = std::mem::replace(
                    &mut self.tcp_ao_keys,
                    TcpAoListenerKeyIndex::new(desired.keys.to_vec()),
                );
                self.previous_tcp_ao_generation = Some(TcpAoPreviousListenerGeneration {
                    generation: self.tcp_ao_generation,
                    keys: previous_keys,
                });
                self.tcp_ao_generation = desired.generation;
                status.applied = self.tcp_ao_committed_generation;
                status.phase = TcpAoRotationPhase::AddOnly;
                self.rotation_status_tx.send_replace(status.clone());
                Ok(status)
            }
            Err(error) => {
                status.phase = TcpAoRotationPhase::AddOnlyFailed;
                status.last_error = Some(error.to_string());
                self.rotation_status_tx.send_replace(status);
                Err(error)
            }
        }
    }

    fn preflight_add_only_generation(
        &self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<()> {
        let already_installed = desired.generation == self.tcp_ao_generation
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice();
        if !already_installed {
            let _ = plan_add_only_listener_generation(
                &self.tcp_ao_keys.keys,
                desired.keys.as_ref(),
                self.tcp_ao_generation,
                desired.generation,
            )?;
        }
        if self
            .pending_tcp_ao_generation
            .as_ref()
            .is_some_and(|retained| retained != desired)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO failed generation retry changed its immutable listener inventory",
            ));
        }
        let current = self
            .tcp_ao_keys
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        let desired = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        crate::socket_opts::preflight_tcp_ao_add_only(&self.listener, &current, &desired, None)
            .map(drop)
    }

    fn acknowledge_global_commit_generation(
        &mut self,
        generation: TcpAoRotationGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        self.acknowledge_global_commit_generation_with(generation, |listener, desired| {
            let owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            drop(crate::socket_opts::capture_tcp_ao_complete_owned_receipt(
                listener, &owners,
            )?);
            Ok(())
        })
    }

    fn acknowledge_global_commit_generation_with<F>(
        &mut self,
        generation: TcpAoRotationGeneration,
        verify_inventory: F,
    ) -> std::io::Result<TcpAoRotationStatus>
    where
        F: FnOnce(&TcpListener, &TcpAoListenerGeneration) -> std::io::Result<()>,
    {
        if generation == self.tcp_ao_committed_generation {
            let status = self.rotation_status_tx.borrow().clone();
            if status.phase == TcpAoRotationPhase::Idle
                && status.desired == generation
                && status.applied == generation
            {
                return Ok(status);
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "stale TCP-AO commit acknowledgement does not match current listener status",
            ));
        }
        if generation != self.tcp_ao_generation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO global commit does not match installed listener generation",
            ));
        }
        let desired = self.pending_tcp_ao_generation.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO listener has no retained uncommitted generation",
            )
        })?;
        verify_inventory(&self.listener, desired)?;
        self.tcp_ao_committed_generation = generation;
        self.pending_tcp_ao_generation = None;
        let status = TcpAoRotationStatus {
            desired: generation,
            applied: generation,
            phase: TcpAoRotationPhase::Idle,
            last_error: None,
        };
        self.rotation_status_tx.send_replace(status.clone());
        Ok(status)
    }

    fn inspect_tcp_ao_accept(
        &self,
        stream: &TcpStream,
        peer_ip: IpAddr,
    ) -> std::io::Result<Option<TcpAoInfoSnapshot>> {
        let Some(owner) = self.tcp_ao_keys.resolve(peer_ip) else {
            return Ok(None);
        };
        let key = owner;
        let covering_owners = self.tcp_ao_keys.owned_union(peer_ip);
        let previous_key_counts = accepted_previous_key_counts(
            &covering_owners,
            self.previous_tcp_ao_generation.as_ref(),
            self.tcp_ao_generation,
        );
        let receipt_owners = covering_owners
            .iter()
            .map(|owned| crate::socket_opts::TcpAoMktOwner {
                peer: owned.peer,
                prefix_len: owned.prefix_len,
                keyring: &owned.config,
            })
            .collect::<Vec<_>>();

        // Compare the accepted child's inventory to the union of every
        // configured owner whose selector covers this peer. No secret-bearing
        // receipt survives this accept operation.
        let receipt = crate::socket_opts::capture_tcp_ao_accepted_generation_receipt(
            &self.listener,
            &receipt_owners,
            previous_key_counts.as_deref(),
        )?;
        let accepted =
            crate::socket_opts::inspect_tcp_ao_accepted_generation(stream, &receipt, peer_ip)?;
        let (initial, reconcile_previous) = match accepted {
            crate::socket_opts::TcpAoAcceptedGeneration::Current(info) => (info, false),
            crate::socket_opts::TcpAoAcceptedGeneration::Previous(info) => (info, true),
        };
        // Validate the handshake-selected Current and initial RNext before
        // mutating either selection. Both must identify the resolved owner's
        // inherited MKT; a deprecated key remains valid when peer-selected.
        ensure_accepted_tcp_ao_info_valid(&initial, key, false)?;
        if reconcile_previous {
            let repaired = crate::socket_opts::reconcile_tcp_ao_accepted_previous(
                stream,
                &receipt,
                &receipt_owners,
                peer_ip,
                &initial,
            )
            .map_err(crate::socket_opts::TcpAoAddOnlyApplyError::into_inner)?;
            ensure_accepted_tcp_ao_info_valid(&repaired, key, false)?;
            info!(
                peer = %peer_ip,
                generation = self.tcp_ao_generation.as_u64(),
                "reconciled queued TCP-AO child to current listener generation"
            );
        }

        let selected_key = key.config.selected().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "TCP-AO listener keyring has no selectable non-deprecated key",
            )
        })?;
        crate::socket_opts::set_tcp_ao_rnext(stream, selected_key.recv_id)?;
        let info = crate::socket_opts::get_tcp_ao_info_for_accepted_generation_receipt(
            stream, &receipt, peer_ip,
        )?;
        ensure_accepted_tcp_ao_info_valid(&info, key, true)?;
        info!(
            peer = %peer_ip,
            current_key = info.current_key,
            rnext_key = info.rnext_key,
            has_current_key = info.has_current_key,
            has_rnext_key = info.has_rnext_key,
            ao_required = info.ao_required,
            accept_icmps = info.accept_icmps,
            pkt_good = info.pkt_good,
            pkt_bad = info.pkt_bad,
            pkt_key_not_found = info.pkt_key_not_found,
            pkt_ao_required = info.pkt_ao_required,
            pkt_dropped_icmp = info.pkt_dropped_icmp,
            "TCP-AO accepted socket inspected"
        );
        Ok(Some(info))
    }
}

fn accepted_previous_key_counts(
    current: &[&TcpAoListenerKey],
    previous: Option<&TcpAoPreviousListenerGeneration>,
    current_generation: TcpAoRotationGeneration,
) -> Option<Vec<usize>> {
    let previous = previous?;
    if previous.generation.next() != Some(current_generation) {
        return None;
    }
    current
        .iter()
        .map(|owner| {
            let identity = listener_owner_identity(owner);
            let mut matches = previous
                .keys
                .keys
                .iter()
                .filter(|candidate| listener_owner_identity(candidate) == identity);
            let prior = matches.next()?;
            if matches.next().is_some() || !owner.config.0.starts_with(&prior.config.0) {
                return None;
            }
            Some(prior.config.0.len())
        })
        .collect()
}

fn listener_owner_identity(key: &TcpAoListenerKey) -> (TcpAoListenerOwnerKind, IpAddr, u8) {
    (key.owner, key.peer, key.prefix_len)
}

fn retain_pending_listener_generation(
    retained: &mut Option<TcpAoListenerGeneration>,
    desired: &TcpAoListenerGeneration,
) -> std::io::Result<()> {
    match retained {
        Some(current) if current == desired => Ok(()),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO failed generation retry changed its immutable listener inventory",
        )),
        None => {
            *retained = Some(desired.clone());
            Ok(())
        }
    }
}

fn plan_add_only_listener_generation<'a>(
    current: &'a [TcpAoListenerKey],
    desired: &'a [TcpAoListenerKey],
    applied_generation: TcpAoRotationGeneration,
    desired_generation: TcpAoRotationGeneration,
) -> std::io::Result<Vec<(&'a TcpAoListenerKey, &'a TcpAoConfig)>> {
    if applied_generation.next() != Some(desired_generation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO listener generation is not the immediate applied successor",
        ));
    }
    let desired_identities = desired
        .iter()
        .map(listener_owner_identity)
        .collect::<HashSet<_>>();
    if desired_identities.len() != desired.len()
        || current
            .iter()
            .map(listener_owner_identity)
            .collect::<HashSet<_>>()
            != desired_identities
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO add-only generation may not add, remove, or duplicate listener owners",
        ));
    }

    let desired_options = ListenerSocketOptions {
        tcp_ao_keys: desired.to_vec(),
    };
    validate_listener_tcp_ao_capacity(&desired_options)?;
    let mut additions = Vec::new();
    for old_owner in current {
        let identity = listener_owner_identity(old_owner);
        let new_owner = desired
            .iter()
            .find(|candidate| listener_owner_identity(candidate) == identity)
            .expect("owner identity sets were compared");
        if !new_owner.config.0.starts_with(&old_owner.config.0) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO add-only generation may only append to each owner keyring",
            ));
        }
        if old_owner.config.selected() != new_owner.config.selected() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO add-only generation may not change selected-key policy",
            ));
        }
        for key in &new_owner.config.0[old_owner.config.0.len()..] {
            if key.preferred {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO add-only successor keys may not be preferred before selection phase",
                ));
            }
            additions.push((new_owner, key));
        }
    }
    Ok(additions)
}

fn ensure_accepted_tcp_ao_info_valid(
    info: &TcpAoInfoSnapshot,
    owner: &TcpAoListenerKey,
    require_nondeprecated_rnext: bool,
) -> std::io::Result<()> {
    if accepted_tcp_ao_info_is_valid(info, owner, require_nondeprecated_rnext) {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "TCP-AO accepted socket state is inconsistent: has_current_key={}, current_key={}, has_rnext_key={}, rnext_key={}, pkt_bad={}, pkt_key_not_found={}, pkt_ao_required={}",
                info.has_current_key,
                info.current_key,
                info.has_rnext_key,
                info.rnext_key,
                info.pkt_bad,
                info.pkt_key_not_found,
                info.pkt_ao_required
            ),
        ))
    }
}

fn accepted_tcp_ao_info_is_valid(
    info: &TcpAoInfoSnapshot,
    owner: &TcpAoListenerKey,
    require_nondeprecated_rnext: bool,
) -> bool {
    let selected_rnext = owner.config.selected().map(|key| key.recv_id);
    let belongs_to_owner = |state: &&crate::TcpAoKeyState| {
        owner.config.iter().any(|config| {
            config.send_id == state.send_id
                && config.recv_id == state.recv_id
                && config.algorithm == state.algorithm
        })
    };
    let current = info
        .keys
        .iter()
        .filter(|key| {
            key.peer == owner.peer
                && key.prefix_len == owner.prefix_len
                && key.is_current
                && key.send_id == info.current_key
                && belongs_to_owner(key)
        })
        .take(2)
        .count();
    let rnext = info
        .keys
        .iter()
        .filter(|key| {
            key.is_rnext
                && key.peer == owner.peer
                && key.prefix_len == owner.prefix_len
                && key.recv_id == info.rnext_key
                && belongs_to_owner(key)
                && (!require_nondeprecated_rnext
                    || (!key.deprecated && selected_rnext == Some(key.recv_id)))
        })
        .take(2)
        .count();
    info.has_current_key
        && info.has_rnext_key
        && info.pkt_bad == 0
        && info.pkt_key_not_found == 0
        && info.pkt_ao_required == 0
        && current == 1
        && rnext == 1
        && info.keys.iter().all(|key| key.pkt_bad == 0)
}

#[cfg(test)]
impl TcpAoListenerKey {
    fn covers(&self, addr: IpAddr) -> bool {
        match (self.peer, addr) {
            (IpAddr::V4(network), IpAddr::V4(addr)) if self.prefix_len <= 32 => {
                mask_v4(network.into(), self.prefix_len) == mask_v4(addr.into(), self.prefix_len)
            }
            (IpAddr::V6(network), IpAddr::V6(addr)) if self.prefix_len <= 128 => {
                mask_v6(network.into(), self.prefix_len) == mask_v6(addr.into(), self.prefix_len)
            }
            _ => false,
        }
    }
}

fn bind_socket2_listener(
    addr: SocketAddr,
    options: &ListenerSocketOptions,
) -> std::io::Result<TcpListener> {
    bind_socket2_listener_with(addr, options, install_listener_tcp_ao_key)
}

fn bind_socket2_listener_with<F>(
    addr: SocketAddr,
    options: &ListenerSocketOptions,
    mut install_tcp_ao: F,
) -> std::io::Result<TcpListener>
where
    F: FnMut(&Socket, &TcpAoListenerKey, &TcpAoConfig) -> std::io::Result<()>,
{
    validate_listener_tcp_ao_capacity(options)?;
    let domain = if addr.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.bind(&SockAddr::from(addr))?;
    for key in &options.tcp_ao_keys {
        // This installs a peer-specific MKT, not the socket-wide
        // `ao_required` bit. Linux tcp_ao_required() returns true for either
        // ao_info->ao_required or a matching MKT, and tcp_inbound_hash()
        // rejects unsigned packets in that case. A global requirement would
        // also reject non-AO peers on the shared BGP listener.
        for config in &key.config {
            install_tcp_ao(&socket, key, config)
                .map_err(|err| listener_tcp_ao_error(key, config, &err))?;
            debug!(peer = %key.peer, send_id = config.send_id, "TCP-AO listener key configured");
        }
    }
    socket.listen(DEFAULT_LISTEN_BACKLOG)?;
    socket.set_nonblocking(true)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}

fn validate_listener_tcp_ao_capacity(options: &ListenerSocketOptions) -> std::io::Result<()> {
    let key_count = options
        .tcp_ao_keys
        .iter()
        .try_fold(0usize, |count, owner| {
            count.checked_add(owner.config.0.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO listener key count overflow",
                )
            })
        })?;
    if key_count > TCP_AO_MAX_INSPECT_KEYS {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "TCP-AO listener key count {key_count} exceeds inspection limit \
                 {TCP_AO_MAX_INSPECT_KEYS}"
            ),
        ));
    }
    Ok(())
}

fn install_listener_tcp_ao_key(
    socket: &Socket,
    key: &TcpAoListenerKey,
    config: &TcpAoConfig,
) -> std::io::Result<()> {
    crate::socket_opts::set_tcp_ao_config(
        socket,
        key.peer,
        key.prefix_len,
        config,
        crate::socket_opts::TcpAoSocketRole::Listener,
    )
}

fn listener_tcp_ao_error(
    key: &TcpAoListenerKey,
    config: &TcpAoConfig,
    err: &std::io::Error,
) -> std::io::Error {
    std::io::Error::new(
        err.kind(),
        format!(
            "failed to install TCP-AO listener key for peer {}/{} \
             (send_id={}, recv_id={}, algorithm={}): {err}",
            key.peer,
            key.prefix_len,
            config.send_id,
            config.recv_id,
            config.algorithm.linux_name()
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{TcpAoAlgorithm, TcpAoConfig};
    use std::cell::RefCell;
    use std::net::Ipv4Addr;

    fn tcp_ao_config() -> TcpAoKeyring {
        TcpAoConfig {
            key: "secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }
        .into()
    }

    fn tcp_ao_owner() -> TcpAoListenerKey {
        let mut config = tcp_ao_config();
        config.0[0].send_id = 7;
        config.0[0].recv_id = 9;
        TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Static,
            peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            prefix_len: 32,
            config,
        }
    }

    fn listener_options_with_key_count(key_count: usize) -> ListenerSocketOptions {
        let tcp_ao_keys = (0..key_count.div_ceil(256))
            .map(|owner_index| {
                let owner_key_count = (key_count - owner_index * 256).min(256);
                let config = (0..owner_key_count)
                    .map(|key_id| TcpAoConfig {
                        key: "secret".into(),
                        send_id: u8::try_from(key_id).expect("owner key count is bounded to 256"),
                        recv_id: u8::try_from(key_id).expect("owner key count is bounded to 256"),
                        algorithm: TcpAoAlgorithm::HmacSha256,
                        preferred: false,
                        deprecated: false,
                    })
                    .collect();
                TcpAoListenerKey {
                    owner: TcpAoListenerOwnerKind::Static,
                    peer: IpAddr::V4(Ipv4Addr::new(
                        192,
                        0,
                        2,
                        u8::try_from(owner_index + 1).expect("test owner index fits IPv4"),
                    )),
                    prefix_len: 32,
                    config: TcpAoKeyring(config),
                }
            })
            .collect();
        ListenerSocketOptions { tcp_ao_keys }
    }

    #[test]
    fn add_only_generation_appends_without_changing_selection() {
        let old = tcp_ao_owner();
        let mut new = old.clone();
        let mut successor = new.config.0[0].clone();
        successor.key = "successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.preferred = false;
        new.config.0.push(successor);
        let additions = plan_add_only_listener_generation(
            std::slice::from_ref(&old),
            std::slice::from_ref(&new),
            TcpAoRotationGeneration::STARTUP,
            TcpAoRotationGeneration::new(2).unwrap(),
        )
        .unwrap();
        assert_eq!(additions.len(), 1);
        assert_eq!(additions[0].1.send_id, 11);
    }

    #[test]
    fn accepted_child_fallback_requires_exact_adjacent_owner_prefix() {
        let old = tcp_ao_owner();
        let mut current = old.clone();
        let mut successor = current.config.0[0].clone();
        successor.key = "successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.preferred = false;
        current.config.0.push(successor);
        let current_index = TcpAoListenerKeyIndex::new(vec![current]);
        let current_union = current_index.owned_union(old.peer);
        let previous = TcpAoPreviousListenerGeneration {
            generation: TcpAoRotationGeneration::STARTUP,
            keys: TcpAoListenerKeyIndex::new(vec![old.clone()]),
        };
        let generation_two = TcpAoRotationGeneration::new(2).unwrap();
        assert_eq!(
            accepted_previous_key_counts(&current_union, Some(&previous), generation_two),
            Some(vec![1])
        );

        assert_eq!(
            accepted_previous_key_counts(
                &current_union,
                Some(&previous),
                TcpAoRotationGeneration::new(3).unwrap()
            ),
            None,
            "an N-2 inventory must not be treated as the adjacent predecessor"
        );

        let mut redefined = old;
        redefined.config.0[0].key = "redefined".into();
        let redefined_previous = TcpAoPreviousListenerGeneration {
            generation: TcpAoRotationGeneration::STARTUP,
            keys: TcpAoListenerKeyIndex::new(vec![redefined]),
        };
        assert_eq!(
            accepted_previous_key_counts(&current_union, Some(&redefined_previous), generation_two),
            None
        );
    }

    #[test]
    fn add_only_generation_rejects_preferred_successor_and_owner_replacement() {
        let old = tcp_ao_owner();
        let mut preferred = old.clone();
        let mut successor = preferred.config.0[0].clone();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.preferred = true;
        preferred.config.0.push(successor);
        assert!(
            plan_add_only_listener_generation(
                std::slice::from_ref(&old),
                std::slice::from_ref(&preferred),
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_err()
        );

        let mut replacement = old.clone();
        replacement.peer = "192.0.2.2".parse().unwrap();
        assert!(
            plan_add_only_listener_generation(
                &[old],
                &[replacement],
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn add_only_generation_rejects_gap_removal_and_existing_key_redefinition() {
        let old = tcp_ao_owner();
        let generation_two = TcpAoRotationGeneration::new(2).unwrap();
        assert!(
            plan_add_only_listener_generation(
                std::slice::from_ref(&old),
                std::slice::from_ref(&old),
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(3).unwrap(),
            )
            .is_err()
        );
        assert!(
            plan_add_only_listener_generation(
                std::slice::from_ref(&old),
                &[],
                TcpAoRotationGeneration::STARTUP,
                generation_two,
            )
            .is_err()
        );

        let mut redefined = old.clone();
        redefined.config.0[0].key = "different-secret".into();
        assert!(
            plan_add_only_listener_generation(
                &[old],
                &[redefined],
                TcpAoRotationGeneration::STARTUP,
                generation_two,
            )
            .is_err()
        );
    }

    #[test]
    fn partial_apply_retry_cannot_redefine_failed_generation_inventory() {
        let mut desired_owner = tcp_ao_owner();
        let mut successor = desired_owner.config.0[0].clone();
        successor.key = "first-successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.preferred = false;
        desired_owner.config.0.push(successor);
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoListenerGeneration::new(generation, vec![desired_owner]);
        let mut retained = None;
        retain_pending_listener_generation(&mut retained, &desired).unwrap();

        let mut changed = desired.clone();
        Arc::make_mut(&mut changed.keys)[0].config.0[1].key = "different-successor".into();
        assert!(retain_pending_listener_generation(&mut retained, &changed).is_err());
        assert_eq!(retained.as_ref(), Some(&desired));
    }

    #[tokio::test]
    async fn staged_generation_failure_and_retry_keep_old_applied_generation() {
        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoListenerGeneration::new(generation, Vec::new());
        listener.tcp_ao_generation = generation;
        listener.pending_tcp_ao_generation = Some(desired.clone());
        listener
            .rotation_status_tx
            .send_replace(TcpAoRotationStatus {
                desired: generation,
                applied: TcpAoRotationGeneration::STARTUP,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            });
        let handle = listener.tcp_ao_rotation_handle();
        let task = tokio::spawn(listener.run());

        handle
            .mark_dependent_failure(generation, "session apply failed".to_string())
            .await
            .unwrap();
        assert_eq!(handle.status().phase, TcpAoRotationPhase::AddOnlyFailed);
        assert_eq!(handle.status().applied, TcpAoRotationGeneration::STARTUP);
        assert_eq!(
            handle.status().last_error.as_deref(),
            Some("session apply failed")
        );

        let status = handle.apply_add_only(desired).await.unwrap();
        assert_eq!(status.phase, TcpAoRotationPhase::AddOnly);
        assert_eq!(status.desired, generation);
        assert_eq!(status.applied, TcpAoRotationGeneration::STARTUP);
        assert!(status.last_error.is_none());

        task.abort();
    }

    #[tokio::test]
    async fn dropped_dependent_failure_reply_keeps_same_generation_retryable() {
        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoListenerGeneration::new(generation, Vec::new());
        listener.tcp_ao_generation = generation;
        listener.pending_tcp_ao_generation = Some(desired);
        listener
            .rotation_status_tx
            .send_replace(TcpAoRotationStatus {
                desired: generation,
                applied: TcpAoRotationGeneration::STARTUP,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            });
        let handle = listener.tcp_ao_rotation_handle();
        let mut status = handle.status_rx.clone();
        let task = tokio::spawn(listener.run());
        let (reply, response) = oneshot::channel();
        drop(response);
        handle
            .tx
            .send(TcpAoListenerCommand::MarkDependentFailure {
                generation,
                error: "injected lost marker reply".to_string(),
                reply,
            })
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), status.changed())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status.borrow().phase, TcpAoRotationPhase::AddOnlyFailed);
        assert_eq!(status.borrow().desired, generation);
        assert_eq!(status.borrow().applied, TcpAoRotationGeneration::STARTUP);

        task.abort();
    }

    #[tokio::test]
    async fn rejected_commit_ack_retries_same_installed_generation() {
        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoListenerGeneration::new(generation, Vec::new());
        listener.tcp_ao_generation = generation;
        listener.previous_tcp_ao_generation = Some(TcpAoPreviousListenerGeneration {
            generation: TcpAoRotationGeneration::STARTUP,
            keys: TcpAoListenerKeyIndex::new(Vec::new()),
        });
        listener.pending_tcp_ao_generation = Some(desired.clone());
        listener
            .rotation_status_tx
            .send_replace(TcpAoRotationStatus {
                desired: generation,
                applied: TcpAoRotationGeneration::STARTUP,
                phase: TcpAoRotationPhase::AddOnly,
                last_error: None,
            });

        let rejected = listener
            .acknowledge_global_commit_generation_with(generation, |_socket, _desired| {
                Err(std::io::Error::other("injected inventory rejection"))
            });
        assert!(rejected.is_err());
        assert_eq!(
            listener.rotation_status_tx.borrow().phase,
            TcpAoRotationPhase::AddOnly
        );
        assert_eq!(
            listener.rotation_status_tx.borrow().applied,
            TcpAoRotationGeneration::STARTUP
        );

        let staged = listener.apply_add_only_generation(&desired).unwrap();
        assert_eq!(staged.desired, generation);
        assert_eq!(staged.applied, TcpAoRotationGeneration::STARTUP);
        assert_eq!(staged.phase, TcpAoRotationPhase::AddOnly);
        assert_eq!(
            listener
                .previous_tcp_ao_generation
                .as_ref()
                .map(|previous| previous.generation),
            Some(TcpAoRotationGeneration::STARTUP),
            "same-generation retry must not replace the queued-child predecessor"
        );
        let committed = listener
            .acknowledge_global_commit_generation_with(generation, |_socket, _desired| Ok(()))
            .unwrap();
        assert_eq!(committed.desired, generation);
        assert_eq!(committed.applied, generation);
        assert_eq!(committed.phase, TcpAoRotationPhase::Idle);
        assert!(listener.pending_tcp_ao_generation.is_none());
        assert_eq!(
            listener
                .previous_tcp_ao_generation
                .as_ref()
                .map(|previous| previous.generation),
            Some(TcpAoRotationGeneration::STARTUP),
            "global commit must retain the predecessor for children still queued in the kernel"
        );
    }

    #[tokio::test]
    async fn lost_commit_ack_reply_uses_published_committed_status() {
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let (status_tx, status_rx) = watch::channel(TcpAoRotationStatus {
            desired: generation,
            applied: TcpAoRotationGeneration::STARTUP,
            phase: TcpAoRotationPhase::AddOnly,
            last_error: None,
        });
        let handle = TcpAoListenerHandle { tx, status_rx };
        let task = tokio::spawn(async move {
            let Some(TcpAoListenerCommand::AcknowledgeGlobalCommit {
                generation: requested,
                reply,
            }) = rx.recv().await
            else {
                panic!("expected listener commit acknowledgement command");
            };
            assert_eq!(requested, generation);
            status_tx.send_replace(TcpAoRotationStatus {
                desired: generation,
                applied: generation,
                phase: TcpAoRotationPhase::Idle,
                last_error: None,
            });
            drop(reply);
        });

        let status = handle.acknowledge_global_commit(generation).await.unwrap();
        assert_eq!(status.phase, TcpAoRotationPhase::Idle);
        assert_eq!(status.applied, generation);
        task.await.unwrap();
    }

    fn tcp_ao_info(current_key: u8, pkt_good: u64) -> TcpAoInfoSnapshot {
        TcpAoInfoSnapshot {
            has_current_key: true,
            has_rnext_key: false,
            ao_required: false,
            accept_icmps: false,
            current_key,
            rnext_key: 0,
            pkt_good,
            pkt_bad: 0,
            pkt_key_not_found: 0,
            pkt_ao_required: 0,
            pkt_dropped_icmp: 0,
            keys: vec![crate::TcpAoKeyState {
                peer: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                send_id: current_key,
                recv_id: 9,
                algorithm: TcpAoAlgorithm::HmacSha256,
                is_current: true,
                is_rnext: true,
                preferred: false,
                deprecated: false,
                vrf_ifindex: None,
                pkt_good,
                pkt_bad: 0,
            }],
        }
    }

    #[test]
    fn prefix_mkt_matching_covers_v4_and_v6_without_cross_family_matches() {
        let config = tcp_ao_config();
        let v4 = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: config.clone(),
        };
        let v6 = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "2001:db8::".parse().unwrap(),
            prefix_len: 32,
            config,
        };
        assert!(v4.covers("192.0.2.200".parse().unwrap()));
        assert!(!v4.covers("192.0.3.1".parse().unwrap()));
        assert!(v6.covers("2001:db8:ffff::1".parse().unwrap()));
        assert!(!v6.covers("2001:db9::1".parse().unwrap()));
        assert!(!v6.covers("192.0.2.1".parse().unwrap()));
    }

    #[test]
    fn listener_key_index_matches_linear_lookup_for_exact_prefix_miss_and_families() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "198.51.100.0".parse().unwrap(),
                prefix_len: 24,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "2001:db8:1::".parse().unwrap(),
                prefix_len: 48,
                config,
            },
        ];
        let probes = [
            "192.0.2.9",
            "192.0.2.10",
            "198.51.100.254",
            "198.51.101.1",
            "2001:db8:1::1234",
            "2001:db8:2::1",
        ];
        let index = TcpAoListenerKeyIndex::new(keys.clone());

        for probe in probes.map(|probe| probe.parse::<IpAddr>().unwrap()) {
            let linear = keys.iter().position(|key| key.covers(probe));
            let indexed = index
                .resolve(probe)
                .and_then(|owner| index.keys.iter().position(|key| std::ptr::eq(key, owner)));
            assert_eq!(indexed, linear, "{probe}");
        }
    }

    #[test]
    fn listener_owner_resolution_prefers_host_prefix_then_shorter_lpm() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "10.20.30.40".parse().unwrap(),
                prefix_len: 32,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys.clone());

        for (probe, expected, exact) in [
            ("10.20.30.40", 2, true),
            ("10.20.30.41", 1, false),
            ("10.21.0.1", 0, false),
        ] {
            let owner = index.resolve(probe.parse().unwrap()).unwrap();
            let actual = index
                .keys
                .iter()
                .position(|key| std::ptr::eq(key, owner))
                .unwrap();
            assert_eq!(actual, expected, "{probe}");
            assert_eq!(owner.owner == TcpAoListenerOwnerKind::Static, exact);
        }
        assert!(index.resolve("203.0.113.1".parse().unwrap()).is_none());
    }

    #[test]
    fn listener_owner_identity_keeps_host_length_dynamic_below_static_exact() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "192.0.2.9".parse().unwrap(),
                prefix_len: 32,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "2001:db8::9".parse().unwrap(),
                prefix_len: 128,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "2001:db8::9".parse().unwrap(),
                prefix_len: 128,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys);
        let reversed = TcpAoListenerKeyIndex::new(index.keys.iter().cloned().rev().collect());
        for candidate in [&index, &reversed] {
            for address in ["192.0.2.9", "2001:db8::9"] {
                let owner = candidate.resolve(address.parse().unwrap()).unwrap();
                assert_eq!(owner.owner, TcpAoListenerOwnerKind::Static, "{address}");
                assert_eq!(candidate.owned_union(address.parse().unwrap()).len(), 2);
            }
        }
    }

    #[test]
    fn listener_owner_index_retains_same_selector_keys_and_covering_union() {
        let config = tcp_ao_config();
        let keys = vec![
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.0.0.0".parse().unwrap(),
                prefix_len: 8,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config: config.clone(),
            },
            TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "10.20.0.0".parse().unwrap(),
                prefix_len: 16,
                config,
            },
        ];
        let index = TcpAoListenerKeyIndex::new(keys);
        let union = index.owned_union("10.20.30.40".parse().unwrap());
        assert_eq!(union.len(), 3, "all covering owners/MKTs must be retained");
        assert_eq!(union.iter().filter(|key| key.prefix_len == 16).count(), 2);
    }

    #[test]
    fn protected_accept_requires_expected_keys_and_clean_auth_counters() {
        let owner = tcp_ao_owner();
        let mut valid = tcp_ao_info(7, 0);
        valid.has_rnext_key = true;
        valid.rnext_key = 9;
        assert!(accepted_tcp_ao_info_is_valid(&valid, &owner, false));
        assert!(accepted_tcp_ao_info_is_valid(&valid, &owner, true));
        let mut bad = valid.clone();
        bad.pkt_bad = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&bad, &owner, false));
        let mut missing = valid;
        missing.pkt_key_not_found = 1;
        assert!(!accepted_tcp_ao_info_is_valid(&missing, &owner, false));

        let mut wrong_current = tcp_ao_info(7, 0);
        wrong_current.has_rnext_key = true;
        wrong_current.rnext_key = 9;
        wrong_current.current_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(
            &wrong_current,
            &owner,
            false
        ));

        let mut wrong_rnext = tcp_ao_info(7, 0);
        wrong_rnext.has_rnext_key = true;
        wrong_rnext.rnext_key = 8;
        assert!(!accepted_tcp_ao_info_is_valid(&wrong_rnext, &owner, false));
    }

    #[test]
    fn protected_accept_initial_validation_allows_deprecated_current() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 9;
        info.keys[0].deprecated = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, false));
        assert!(!accepted_tcp_ao_info_is_valid(&info, &owner, true));
    }

    #[test]
    fn protected_accept_allows_deprecated_current_but_requires_selected_final_rnext() {
        let mut owner = tcp_ao_owner();
        owner.config.0[0].deprecated = true;
        owner.config.0.push(TcpAoConfig {
            key: "selected".into(),
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        });
        owner.config.0.push(TcpAoConfig {
            key: "other".into(),
            send_id: 9,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        });
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 11;
        info.keys[0].deprecated = true;
        info.keys.push(crate::TcpAoKeyState {
            peer: info.keys[0].peer,
            prefix_len: info.keys[0].prefix_len,
            send_id: 9,
            recv_id: 11,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: true,
            preferred: false,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        info.keys.push(crate::TcpAoKeyState {
            peer: info.keys[0].peer,
            prefix_len: info.keys[0].prefix_len,
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: false,
            preferred: true,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        info.keys[0].is_rnext = false;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, false));
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, true),
            "an unselected non-deprecated RNext must not satisfy final validation"
        );

        info.rnext_key = 10;
        info.keys[1].is_rnext = false;
        info.keys[2].is_rnext = true;
        assert!(accepted_tcp_ao_info_is_valid(&info, &owner, true));
    }

    #[test]
    fn protected_accept_selection_must_belong_to_resolved_owner() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(7, 0);
        info.has_rnext_key = true;
        info.rnext_key = 9;
        info.keys[0].peer = "192.0.2.0".parse().unwrap();
        info.keys[0].prefix_len = 24;
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, false),
            "Current/RNext selected from a covering owner must not satisfy the static owner"
        );

        info.keys.push(crate::TcpAoKeyState {
            peer: owner.peer,
            prefix_len: owner.prefix_len,
            send_id: 8,
            recv_id: 10,
            algorithm: TcpAoAlgorithm::HmacSha256,
            is_current: false,
            is_rnext: false,
            preferred: true,
            deprecated: false,
            vrf_ifindex: None,
            pkt_good: 0,
            pkt_bad: 0,
        });
        assert!(!accepted_tcp_ao_info_is_valid(&info, &owner, false));
    }

    #[test]
    fn protected_accept_same_selector_selection_must_match_static_owner_keyring() {
        let owner = tcp_ao_owner();
        let mut info = tcp_ao_info(2, 0);
        info.has_rnext_key = true;
        info.rnext_key = 10;
        info.keys[0].send_id = 2;
        info.keys[0].recv_id = 10;
        assert_eq!(info.keys[0].peer, owner.peer);
        assert_eq!(info.keys[0].prefix_len, owner.prefix_len);
        assert!(
            !accepted_tcp_ao_info_is_valid(&info, &owner, false),
            "a same-selector dynamic owner's key must not satisfy static-owner selection"
        );
    }

    #[tokio::test]
    async fn bind_socket2_listener_installs_tcp_ao_keys_before_listen() {
        let installed = RefCell::new(Vec::new());
        let mut second = tcp_ao_config().0.remove(0);
        second.send_id = 2;
        second.recv_id = 2;
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: TcpAoKeyring(vec![tcp_ao_config().0.remove(0), second]),
            }],
        };

        let listener = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &options,
            |_socket, _key, config| {
                installed.borrow_mut().push(config.send_id);
                Ok(())
            },
        )
        .unwrap();

        assert!(listener.local_addr().unwrap().port() > 0);
        assert_eq!(installed.into_inner(), vec![1, 2]);
        tokio::task::yield_now().await;
    }

    #[tokio::test]
    async fn bind_socket2_listener_fails_when_tcp_ao_key_install_fails() {
        let installed = RefCell::new(Vec::new());
        let mut second = tcp_ao_config().0.remove(0);
        second.send_id = 2;
        second.recv_id = 2;
        let options = ListenerSocketOptions {
            tcp_ao_keys: vec![TcpAoListenerKey {
                owner: TcpAoListenerOwnerKind::Static,
                peer: IpAddr::from(Ipv4Addr::new(192, 0, 2, 1)),
                prefix_len: 32,
                config: TcpAoKeyring(vec![tcp_ao_config().0.remove(0), second]),
            }],
        };

        let err = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &options,
            |_socket, _key, config| {
                installed.borrow_mut().push(config.send_id);
                if config.send_id == 2 {
                    Err(std::io::Error::other("tcp-ao install failed"))
                } else {
                    Ok(())
                }
            },
        )
        .expect_err("listener bind must fail when TCP-AO key install fails");

        assert_eq!(err.kind(), std::io::ErrorKind::Other);
        let message = err.to_string();
        assert!(message.contains("192.0.2.1"), "{message}");
        assert!(message.contains("send_id=2"), "{message}");
        assert!(message.contains("recv_id=2"), "{message}");
        assert!(message.contains("hmac(sha256)"), "{message}");
        assert_eq!(installed.into_inner(), vec![1, 2]);
        tokio::task::yield_now().await;
    }

    #[test]
    fn listener_tcp_ao_capacity_accepts_4096_and_rejects_4097_before_install() {
        let at_limit = listener_options_with_key_count(TCP_AO_MAX_INSPECT_KEYS);
        validate_listener_tcp_ao_capacity(&at_limit).expect("4,096 listener MKTs must be valid");

        let over_limit = listener_options_with_key_count(TCP_AO_MAX_INSPECT_KEYS + 1);
        let installed = RefCell::new(0usize);
        let err = bind_socket2_listener_with(
            "127.0.0.1:0".parse().unwrap(),
            &over_limit,
            |_socket, _key, _config| {
                *installed.borrow_mut() += 1;
                Ok(())
            },
        )
        .expect_err("4,097 listener MKTs must fail before socket programming");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("4097"), "{err}");
        assert_eq!(*installed.borrow(), 0);
    }

    /// Deterministic Linux accept-queue receipt: complete the TCP-AO handshake
    /// through a dynamic `/24` owner before the listener actor accepts the
    /// child, then flip the listener to its add-only successor. Linux leaves
    /// the queued child at the previous inventory, so accept must reconcile it
    /// forward without changing key selection or dropping authenticated
    /// traffic.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a Linux kernel with CONFIG_TCP_AO=y"]
    #[expect(
        clippy::too_many_lines,
        reason = "kernel receipt keeps the queued handshake, listener flip, exact inventory, and traffic proof together"
    )]
    async fn queued_tcp_ao_child_reconciles_immediate_listener_successor() {
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let owner_prefix = Ipv4Addr::new(127, 0, 0, 0);
        let peer_ip = Ipv4Addr::new(127, 0, 0, 2);
        let current = TcpAoConfig {
            key: "queued-child-current-secret".into(),
            send_id: 21,
            recv_id: 31,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: true,
            deprecated: false,
        };
        let current_ring = TcpAoKeyring(vec![current.clone()]);
        let owner = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: owner_prefix.into(),
            prefix_len: 24,
            config: current_ring.clone(),
        };
        let (accept_tx, mut accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            ListenerSocketOptions {
                tcp_ao_keys: vec![owner.clone()],
            },
        )
        .await
        .unwrap();
        let destination = listener.local_addr().unwrap();

        let client = tokio::task::spawn_blocking(move || -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(peer_ip.into(), 0)))?;
            let client_key = TcpAoConfig {
                send_id: current.recv_id,
                recv_id: current.send_id,
                ..current
            };
            crate::socket_opts::set_tcp_ao_config(
                &socket,
                destination.ip(),
                32,
                &client_key,
                crate::socket_opts::TcpAoSocketRole::ActiveOpen,
            )?;
            socket.connect_timeout(&SockAddr::from(destination), Duration::from_secs(2))?;
            Ok(socket)
        })
        .await
        .unwrap()
        .unwrap();

        let mut desired_owner = owner;
        desired_owner.config.0.push(TcpAoConfig {
            key: "queued-child-successor-secret".into(),
            send_id: 22,
            recv_id: 32,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        });
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        listener
            .apply_add_only_generation(&TcpAoListenerGeneration::new(
                generation,
                vec![desired_owner],
            ))
            .unwrap();
        assert_eq!(listener.tcp_ao_generation, generation);
        assert_eq!(
            listener
                .previous_tcp_ao_generation
                .as_ref()
                .map(|previous| previous.generation),
            Some(TcpAoRotationGeneration::STARTUP)
        );

        let task = tokio::spawn(listener.run());
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.tcp_ao_generation, Some(generation));
        let info = accepted.tcp_ao_info.as_ref().unwrap();
        assert_eq!(info.keys.len(), 2);
        assert_eq!(info.current_key, 21);
        assert_eq!(info.rnext_key, 31);
        assert_eq!(info.pkt_bad, 0);
        assert_eq!(info.pkt_key_not_found, 0);
        assert_eq!(info.pkt_ao_required, 0);
        // The production snapshot accepts either the configured selector or a
        // kernel-normalized connected-host selector, then restores the logical
        // dynamic-owner metadata exposed to the session.
        assert!(info.keys.iter().any(|key| {
            key.peer == IpAddr::V4(owner_prefix)
                && key.prefix_len == 24
                && key.send_id == 22
                && key.recv_id == 32
        }));

        let std_client: std::net::TcpStream = client.into();
        std_client.set_nonblocking(true).unwrap();
        let mut client = TcpStream::from_std(std_client).unwrap();
        client
            .write_all(b"previous-generation traffic")
            .await
            .unwrap();
        let mut inbound = vec![0; b"previous-generation traffic".len()];
        tokio::time::timeout(
            Duration::from_secs(2),
            accepted.stream.read_exact(&mut inbound),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(inbound, b"previous-generation traffic");
        accepted
            .stream
            .write_all(b"reconciled traffic")
            .await
            .unwrap();
        let mut outbound = vec![0; b"reconciled traffic".len()];
        tokio::time::timeout(Duration::from_secs(2), client.read_exact(&mut outbound))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outbound, b"reconciled traffic");

        drop((client, accepted));
        task.abort();
    }

    /// Bounded privileged/kernel receipt for GitHub #158. Run on a Linux host
    /// with `CONFIG_TCP_AO=y`:
    /// `cargo test -p rustbgpd-transport overlapping_tcp_ao_owned_union_kernel_receipt -- --ignored`
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires a Linux kernel with CONFIG_TCP_AO=y"]
    #[expect(
        clippy::too_many_lines,
        reason = "privileged receipt covers overlapping owners and a two-key lifecycle"
    )]
    async fn overlapping_tcp_ao_owned_union_kernel_receipt() {
        use std::time::Duration;

        fn connect_from(
            source: Ipv4Addr,
            destination: SocketAddr,
            tcp_ao: Option<&TcpAoKeyring>,
        ) -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
            socket.bind(&SockAddr::from(SocketAddr::new(source.into(), 0)))?;
            if let Some(keyring) = tcp_ao {
                for (index, config) in keyring.startup_order().into_iter().enumerate() {
                    let role = if index == 0 {
                        crate::socket_opts::TcpAoSocketRole::ActiveOpen
                    } else {
                        crate::socket_opts::TcpAoSocketRole::Listener
                    };
                    crate::socket_opts::set_tcp_ao_config(
                        &socket,
                        destination.ip(),
                        32,
                        config,
                        role,
                    )?;
                }
            }
            socket.connect_timeout(&SockAddr::from(destination), Duration::from_secs(2))?;
            Ok(socket)
        }

        let covering_config = TcpAoKeyring(vec![TcpAoConfig {
            key: "kernel-receipt-covering-secret".into(),
            send_id: 1,
            recv_id: 1,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        }]);
        let static_config = TcpAoKeyring(vec![
            TcpAoConfig {
                key: "kernel-receipt-old-secret".into(),
                send_id: 2,
                recv_id: 2,
                algorithm: TcpAoAlgorithm::HmacSha256,
                preferred: false,
                deprecated: true,
            },
            TcpAoConfig {
                key: "kernel-receipt-next-secret".into(),
                send_id: 3,
                recv_id: 3,
                algorithm: TcpAoAlgorithm::HmacSha256,
                preferred: true,
                deprecated: false,
            },
        ]);
        let (accept_tx, mut accept_rx) = mpsc::channel(4);
        let listener = BgpListener::bind_with_options(
            "127.0.0.1:0".parse().unwrap(),
            accept_tx,
            ListenerSocketOptions {
                tcp_ao_keys: vec![
                    TcpAoListenerKey {
                        owner: TcpAoListenerOwnerKind::Dynamic,
                        peer: "127.0.0.0".parse().unwrap(),
                        prefix_len: 24,
                        config: covering_config.clone(),
                    },
                    TcpAoListenerKey {
                        owner: TcpAoListenerOwnerKind::Static,
                        peer: "127.0.0.2".parse().unwrap(),
                        prefix_len: 32,
                        config: static_config.clone(),
                    },
                ],
            },
        )
        .await
        .unwrap();
        let destination = listener.local_addr().unwrap();
        let task = tokio::spawn(listener.run());

        let signed_config = static_config.clone();
        let signed = tokio::task::spawn_blocking(move || {
            connect_from(
                "127.0.0.2".parse().unwrap(),
                destination,
                Some(&signed_config),
            )
        })
        .await
        .unwrap()
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.peer_addr.ip(),
            "127.0.0.2".parse::<IpAddr>().unwrap()
        );
        let info = accepted.tcp_ao_info.as_ref().expect("accepted AO snapshot");
        assert_eq!(info.current_key, 3);
        assert_eq!(info.rnext_key, 3);
        assert_eq!(
            info.keys.len(),
            3,
            "GET_KEYS must return the complete covering-owner union"
        );
        let find_key = |peer: &str, prefix_len, send_id, recv_id| {
            let peer = peer.parse::<IpAddr>().unwrap();
            info.keys
                .iter()
                .find(|key| {
                    key.peer == peer
                        && key.prefix_len == prefix_len
                        && key.send_id == send_id
                        && key.recv_id == recv_id
                })
                .unwrap_or_else(|| {
                    panic!(
                        "missing GET_KEYS entry {peer}/{prefix_len} \
                         send_id={send_id} recv_id={recv_id}: {:?}",
                        info.keys
                    )
                })
        };
        let covering = find_key("127.0.0.0", 24, 1, 1);
        assert_eq!(covering.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(!covering.is_current);
        assert!(!covering.is_rnext);
        let old = find_key("127.0.0.2", 32, 2, 2);
        assert_eq!(old.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(old.deprecated);
        assert!(!old.preferred);
        assert!(!old.is_current);
        assert!(!old.is_rnext);
        let selected = find_key("127.0.0.2", 32, 3, 3);
        assert_eq!(selected.algorithm, TcpAoAlgorithm::HmacSha256);
        assert!(selected.preferred);
        assert!(!selected.deprecated);
        assert!(selected.is_current);
        assert!(selected.is_rnext);
        let rendered = format!("{info:?}");
        assert!(!rendered.contains("kernel-receipt-covering-secret"));
        assert!(!rendered.contains("kernel-receipt-old-secret"));
        assert!(!rendered.contains("kernel-receipt-next-secret"));

        // Exercise the live connected-socket rotation path itself: complete
        // scratch normalization + INFO/GET_KEYS preflight, ADD_KEY, and final
        // INFO/GET_KEYS convergence without moving Current/RNext.
        let mut desired_static = static_config.clone();
        desired_static.0.push(TcpAoConfig {
            key: "kernel-receipt-live-successor".into(),
            send_id: 4,
            recv_id: 4,
            algorithm: TcpAoAlgorithm::HmacSha256,
            preferred: false,
            deprecated: false,
        });
        let current_owners = [
            crate::socket_opts::TcpAoMktOwner {
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 24,
                keyring: &covering_config,
            },
            crate::socket_opts::TcpAoMktOwner {
                peer: "127.0.0.2".parse().unwrap(),
                prefix_len: 32,
                keyring: &static_config,
            },
        ];
        let desired_owners = [
            crate::socket_opts::TcpAoMktOwner {
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 24,
                keyring: &covering_config,
            },
            crate::socket_opts::TcpAoMktOwner {
                peer: "127.0.0.2".parse().unwrap(),
                prefix_len: 32,
                keyring: &desired_static,
            },
        ];
        let preflight = crate::socket_opts::preflight_tcp_ao_add_only(
            &accepted.stream,
            &current_owners,
            &desired_owners,
            Some("127.0.0.2".parse().unwrap()),
        )
        .unwrap();
        let rotated = crate::socket_opts::apply_tcp_ao_add_only(
            &accepted.stream,
            preflight,
            &desired_owners,
            Some("127.0.0.2".parse().unwrap()),
        )
        .unwrap()
        .expect("connected live mutation returns INFO");
        assert_eq!(rotated.keys.len(), 4);
        assert_eq!(rotated.current_key, 3);
        assert_eq!(rotated.rnext_key, 3);
        assert!(
            rotated
                .keys
                .iter()
                .any(|key| key.send_id == 4 && key.recv_id == 4)
        );

        let mut mismatched = static_config.clone();
        mismatched.0[1].key = "kernel-receipt-wrong-secret".into();
        let protected_mismatch = tokio::task::spawn_blocking(move || {
            connect_from("127.0.0.2".parse().unwrap(), destination, Some(&mismatched))
        })
        .await
        .unwrap();
        assert!(
            protected_mismatch.is_err(),
            "selected-key secret mismatch must fail closed"
        );

        let protected_unsigned = tokio::task::spawn_blocking(move || {
            connect_from("127.0.0.2".parse().unwrap(), destination, None)
        })
        .await
        .unwrap();
        assert!(protected_unsigned.is_err());

        let unprotected = tokio::task::spawn_blocking(move || {
            connect_from("127.0.1.2".parse().unwrap(), destination, None)
        })
        .await
        .unwrap()
        .unwrap();
        let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            accepted.peer_addr.ip(),
            "127.0.1.2".parse::<IpAddr>().unwrap()
        );
        assert!(accepted.tcp_ao_info.is_none());

        drop((signed, unprotected));
        task.abort();
    }
}
