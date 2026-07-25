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

/// Explicit listener owner selected for one accepted TCP-AO socket.
///
/// This identity is kept separate from the full covering-owner inventory so
/// same-prefix static and dynamic owners cannot be confused by ordering or a
/// longest-prefix-only heuristic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpAoSelectedOwner {
    pub owner: TcpAoListenerOwnerKind,
    pub peer: IpAddr,
    pub prefix_len: u8,
}

impl From<&TcpAoListenerKey> for TcpAoSelectedOwner {
    fn from(key: &TcpAoListenerKey) -> Self {
        Self {
            owner: key.owner,
            peer: key.peer,
            prefix_len: key.prefix_len,
        }
    }
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
    /// reconcile children that completed before the last successful listener
    /// inventory flip. No older history is accepted.
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

/// One immutable desired listener inventory for live TCP-AO rotation.
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
    PreflightSelection {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<()>>,
    },
    BeginSelection {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<TcpAoRotationStatus>>,
    },
    FinalizeSelection {
        generation: TcpAoRotationGeneration,
        reply: oneshot::Sender<std::io::Result<TcpAoRotationStatus>>,
    },
    PreflightDelete {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<()>>,
    },
    ApplyDelete {
        desired: TcpAoListenerGeneration,
        reply: oneshot::Sender<std::io::Result<TcpAoRotationStatus>>,
    },
    MarkAwaitingPeer {
        generation: TcpAoRotationGeneration,
        detail: String,
        reply: oneshot::Sender<std::io::Result<()>>,
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

/// Bounded control handle for listener-owned live TCP-AO rotation generations.
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

    /// Validate an already-installed successor-selection generation without
    /// mutating listener kernel state.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate is invalid or listener control
    /// delivery, acknowledgement, or completion times out.
    pub async fn preflight_selection(
        &self,
        desired: TcpAoListenerGeneration,
    ) -> std::io::Result<()> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::PreflightSelection { desired, reply })
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
                    "TCP-AO listener selection preflight reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener selection preflight timed out",
            )
        })?
    }

    /// Stage successor preference metadata for future accepted children.
    ///
    /// # Errors
    ///
    /// Returns an error when the candidate is invalid or listener control
    /// delivery, acknowledgement, or completion times out.
    pub async fn begin_selection(
        &self,
        desired: TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::BeginSelection { desired, reply })
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
                    "TCP-AO listener selection reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener selection control timed out",
            )
        })?
    }

    /// Commit final declaration metadata after every affected session has
    /// observed generation-relative successor traffic.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation cannot commit or listener control
    /// delivery, acknowledgement, or completion times out.
    pub async fn finalize_selection(
        &self,
        generation: TcpAoRotationGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::FinalizeSelection { generation, reply })
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
                    "TCP-AO listener metadata commit reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener metadata commit timed out",
            )
        })?
    }

    /// Validate a strict current-to-survivor listener generation without
    /// mutating the listener.
    ///
    /// # Errors
    ///
    /// Returns an error when owner identity changes, a survivor is reordered
    /// or redefined, a non-deprecated/selected key would be removed, or the
    /// exact kernel inventory cannot be proved before the control deadline.
    pub async fn preflight_delete(&self, desired: TcpAoListenerGeneration) -> std::io::Result<()> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::PreflightDelete { desired, reply })
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
                    "TCP-AO listener deletion preflight reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener deletion preflight timed out",
            )
        })?
    }

    /// Remove one immutable set of deprecated, unselected listener MKTs and
    /// retain the exact adjacent old inventory for queued-child repair.
    ///
    /// # Errors
    ///
    /// Returns an error when control fails or exact pre/post-delete kernel
    /// inventory cannot be proved.
    pub async fn apply_delete(
        &self,
        desired: TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::ApplyDelete { desired, reply })
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
                    "TCP-AO listener deletion reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener deletion control timed out",
            )
        })?
    }

    /// Publish a one-shot observation miss without polling in the actor.
    ///
    /// # Errors
    ///
    /// Returns an error when the generation is invalid or listener control
    /// delivery, acknowledgement, or completion times out.
    pub async fn mark_awaiting_peer(
        &self,
        generation: TcpAoRotationGeneration,
        detail: String,
    ) -> std::io::Result<()> {
        tokio::time::timeout(TCP_AO_ROTATION_CONTROL_TIMEOUT, async {
            let (reply, response) = oneshot::channel();
            self.tx
                .send(TcpAoListenerCommand::MarkAwaitingPeer {
                    generation,
                    detail,
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
                    "TCP-AO listener awaiting-peer reply dropped",
                )
            })?
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "TCP-AO listener awaiting-peer marker timed out",
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
                        // Every external handle was dropped. Accept service
                        // remains valid at the last applied generation.
                        continue;
                    };
                    self.handle_rotation_command(command);
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
                            tcp_ao_generation: tcp_ao_info.as_ref().map(|_| self.tcp_ao_generation),
                            tcp_ao_info,
                        };
                        if self.accept_tx.send(conn).await.is_err() {
                            warn!("accept channel closed, listener shutting down");
                            return;
                        }
                    }
                    Err(e) => error!(error = %e, "BGP listener accept error"),
                }
            }
        }
    }

    fn handle_rotation_command(&mut self, command: TcpAoListenerCommand) {
        match command {
            TcpAoListenerCommand::PreflightAddOnly { desired, reply } => {
                let _ = reply.send(self.preflight_add_only_generation(&desired));
            }
            TcpAoListenerCommand::ApplyAddOnly { desired, reply } => {
                let _ = reply.send(self.apply_add_only_generation(&desired));
            }
            TcpAoListenerCommand::PreflightSelection { desired, reply } => {
                let _ = reply.send(self.preflight_selection_generation(&desired));
            }
            TcpAoListenerCommand::BeginSelection { desired, reply } => {
                let _ = reply.send(self.begin_selection_generation(&desired));
            }
            TcpAoListenerCommand::FinalizeSelection { generation, reply } => {
                let _ = reply.send(self.finalize_selection_generation(generation));
            }
            TcpAoListenerCommand::PreflightDelete { desired, reply } => {
                let _ = reply.send(self.preflight_delete_generation(&desired));
            }
            TcpAoListenerCommand::ApplyDelete { desired, reply } => {
                let _ = reply.send(self.apply_delete_generation(&desired));
            }
            TcpAoListenerCommand::MarkAwaitingPeer {
                generation,
                detail,
                reply,
            } => {
                let _ = reply.send(self.mark_awaiting_peer_generation(generation, detail));
            }
            TcpAoListenerCommand::MarkDependentFailure {
                generation,
                error,
                reply,
            } => {
                let result = self.mark_dependent_failure_generation(generation, error);
                let _ = reply.send(result);
            }
            TcpAoListenerCommand::AcknowledgeGlobalCommit { generation, reply } => {
                let _ = reply.send(self.acknowledge_global_commit_generation(generation));
            }
        }
    }

    fn mark_dependent_failure_generation(
        &mut self,
        generation: TcpAoRotationGeneration,
        error: String,
    ) -> std::io::Result<()> {
        if generation != self.tcp_ao_generation || generation == self.tcp_ao_committed_generation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO dependent-failure generation is not the installed uncommitted generation",
            ));
        }
        let mut status = self.rotation_status_tx.borrow().clone();
        status.desired = generation;
        status.applied = self.tcp_ao_committed_generation;
        status.phase = match status.phase {
            TcpAoRotationPhase::Selecting
            | TcpAoRotationPhase::AwaitingPeer
            | TcpAoRotationPhase::SelectionFailed => TcpAoRotationPhase::SelectionFailed,
            TcpAoRotationPhase::Deleting | TcpAoRotationPhase::DeleteFailed => {
                TcpAoRotationPhase::DeleteFailed
            }
            _ => TcpAoRotationPhase::AddOnlyFailed,
        };
        status.last_error = Some(error);
        self.rotation_status_tx.send_replace(status);
        Ok(())
    }

    fn preflight_selection_generation(
        &self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<()> {
        if self
            .pending_tcp_ao_generation
            .as_ref()
            .is_some_and(|retained| retained != desired)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO selection retry changed its immutable listener inventory",
            ));
        }
        if desired.generation == self.tcp_ao_generation {
            if self.pending_tcp_ao_generation.as_ref() != Some(desired) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO selection retry lacks its retained listener generation",
                ));
            }
            validate_selection_progress(&self.tcp_ao_keys.keys, desired.keys.as_ref())?;
        } else {
            drop(plan_selection_listener_generation(
                &self.tcp_ao_keys.keys,
                desired.keys.as_ref(),
                self.tcp_ao_generation,
                desired.generation,
            )?);
        }
        let owners = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        drop(crate::socket_opts::capture_tcp_ao_complete_owned_receipt(
            &self.listener,
            &owners,
        )?);
        Ok(())
    }

    fn begin_selection_generation(
        &mut self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        if desired.generation == self.tcp_ao_generation {
            self.preflight_selection_generation(desired)?;
        } else {
            let staged = plan_selection_listener_generation(
                &self.tcp_ao_keys.keys,
                desired.keys.as_ref(),
                self.tcp_ao_generation,
                desired.generation,
            )?;
            retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
            let owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    owner: owner.owner,
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            drop(crate::socket_opts::capture_tcp_ao_complete_owned_receipt(
                &self.listener,
                &owners,
            )?);
            self.tcp_ao_keys = TcpAoListenerKeyIndex::new(staged);
            self.previous_tcp_ao_generation = None;
            self.tcp_ao_generation = desired.generation;
        }
        retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
        let status = TcpAoRotationStatus {
            desired: desired.generation,
            applied: self.tcp_ao_committed_generation,
            phase: TcpAoRotationPhase::Selecting,
            last_error: None,
        };
        self.rotation_status_tx.send_replace(status.clone());
        Ok(status)
    }

    fn finalize_selection_generation(
        &mut self,
        generation: TcpAoRotationGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        if generation != self.tcp_ao_generation || generation == self.tcp_ao_committed_generation {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO selection metadata commit is not the installed uncommitted generation",
            ));
        }
        let desired = self.pending_tcp_ao_generation.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO selection metadata commit lacks its retained listener generation",
            )
        })?;
        validate_selection_progress(&self.tcp_ao_keys.keys, desired.keys.as_ref())?;
        let owners = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        drop(crate::socket_opts::capture_tcp_ao_complete_owned_receipt(
            &self.listener,
            &owners,
        )?);
        self.tcp_ao_keys = TcpAoListenerKeyIndex::new(desired.keys.to_vec());
        let status = TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_committed_generation,
            phase: TcpAoRotationPhase::Selecting,
            last_error: None,
        };
        self.rotation_status_tx.send_replace(status.clone());
        Ok(status)
    }

    fn mark_awaiting_peer_generation(
        &mut self,
        generation: TcpAoRotationGeneration,
        detail: String,
    ) -> std::io::Result<()> {
        if generation != self.tcp_ao_generation
            || generation == self.tcp_ao_committed_generation
            || self.pending_tcp_ao_generation.is_none()
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO awaiting-peer marker is not the installed uncommitted selection",
            ));
        }
        self.rotation_status_tx.send_replace(TcpAoRotationStatus {
            desired: generation,
            applied: self.tcp_ao_committed_generation,
            phase: TcpAoRotationPhase::AwaitingPeer,
            last_error: Some(detail),
        });
        Ok(())
    }

    fn preflight_delete_generation(
        &self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<()> {
        self.preflight_delete_generation_with(desired, verify_complete_listener_inventory)
    }

    fn preflight_delete_generation_with<F>(
        &self,
        desired: &TcpAoListenerGeneration,
        verify_exact: F,
    ) -> std::io::Result<()>
    where
        F: FnOnce(&TcpListener, &[crate::socket_opts::TcpAoMktOwner<'_>]) -> std::io::Result<()>,
    {
        if desired.generation == self.tcp_ao_generation
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice()
        {
            if self.pending_tcp_ao_generation.as_ref() != Some(desired) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO deletion retry lacks its retained listener generation",
                ));
            }
            let owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    owner: owner.owner,
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            return verify_exact(&self.listener, &owners);
        }
        if self.tcp_ao_generation.next() == Some(desired.generation)
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice()
        {
            if self
                .pending_tcp_ao_generation
                .as_ref()
                .is_some_and(|retained| retained != desired)
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "TCP-AO deletion retry changed its immutable listener inventory",
                ));
            }
            let owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    owner: owner.owner,
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            return verify_exact(&self.listener, &owners);
        }
        if self
            .pending_tcp_ao_generation
            .as_ref()
            .is_some_and(|retained| retained != desired)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO deletion retry changed its immutable listener inventory",
            ));
        }
        plan_delete_listener_generation(
            &self.tcp_ao_keys.keys,
            desired.keys.as_ref(),
            self.tcp_ao_generation,
            desired.generation,
        )?;
        let current = self
            .tcp_ao_keys
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        let desired = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        crate::socket_opts::preflight_tcp_ao_delete(&self.listener, &current, &desired, None)
            .map(drop)
    }

    fn apply_delete_generation(
        &mut self,
        desired: &TcpAoListenerGeneration,
    ) -> std::io::Result<TcpAoRotationStatus> {
        self.apply_delete_generation_with(desired, verify_complete_listener_inventory)
    }

    fn apply_delete_generation_with<F>(
        &mut self,
        desired: &TcpAoListenerGeneration,
        verify_exact: F,
    ) -> std::io::Result<TcpAoRotationStatus>
    where
        F: FnOnce(&TcpListener, &[crate::socket_opts::TcpAoMktOwner<'_>]) -> std::io::Result<()>,
    {
        self.apply_delete_generation_with_operations(
            desired,
            verify_exact,
            |listener, current, desired| {
                crate::socket_opts::preflight_tcp_ao_delete(listener, current, desired, None)
                    .map_err(crate::socket_opts::TcpAoDeleteApplyError::before_mutation)
            },
            |listener, preflight, desired| {
                crate::socket_opts::apply_tcp_ao_delete(listener, preflight, desired).map(
                    |snapshot| match snapshot {
                        None => (),
                        Some(_) => {
                            unreachable!("listener deletion cannot return a connected snapshot")
                        }
                    },
                )
            },
            |listener, current| {
                crate::socket_opts::preflight_tcp_ao_add_only(listener, &[], current, None)
            },
            |listener, preflight, current| {
                crate::socket_opts::apply_tcp_ao_add_only(listener, preflight, current, None)
                    .map(drop)
                    .map_err(crate::socket_opts::TcpAoAddOnlyApplyError::into_inner)
            },
        )
    }

    #[expect(
        clippy::too_many_lines,
        reason = "listener deletion keeps exact apply, adjacent-generation retention, and prior-inventory restoration in one transaction boundary"
    )]
    fn apply_delete_generation_with_operations<F, P, D, RP, RA, T, RT>(
        &mut self,
        desired: &TcpAoListenerGeneration,
        verify_exact: F,
        preflight_delete: P,
        apply_delete: D,
        preflight_restore: RP,
        apply_restore: RA,
    ) -> std::io::Result<TcpAoRotationStatus>
    where
        F: FnOnce(&TcpListener, &[crate::socket_opts::TcpAoMktOwner<'_>]) -> std::io::Result<()>,
        P: FnOnce(
            &TcpListener,
            &[crate::socket_opts::TcpAoMktOwner<'_>],
            &[crate::socket_opts::TcpAoMktOwner<'_>],
        ) -> Result<T, crate::socket_opts::TcpAoDeleteApplyError>,
        D: FnOnce(
            &TcpListener,
            T,
            &[crate::socket_opts::TcpAoMktOwner<'_>],
        ) -> Result<(), crate::socket_opts::TcpAoDeleteApplyError>,
        RP: FnOnce(&TcpListener, &[crate::socket_opts::TcpAoMktOwner<'_>]) -> std::io::Result<RT>,
        RA: FnOnce(
            &TcpListener,
            RT,
            &[crate::socket_opts::TcpAoMktOwner<'_>],
        ) -> std::io::Result<()>,
    {
        if desired.generation == self.tcp_ao_generation
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice()
        {
            self.preflight_delete_generation_with(desired, verify_exact)?;
            let status = TcpAoRotationStatus {
                desired: desired.generation,
                applied: self.tcp_ao_committed_generation,
                phase: TcpAoRotationPhase::Deleting,
                last_error: None,
            };
            self.rotation_status_tx.send_replace(status.clone());
            return Ok(status);
        }
        if self.tcp_ao_generation.next() == Some(desired.generation)
            && desired.keys.as_ref() == self.tcp_ao_keys.keys.as_slice()
        {
            self.preflight_delete_generation_with(desired, verify_exact)?;
            retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
            self.previous_tcp_ao_generation = None;
            self.tcp_ao_generation = desired.generation;
            let status = TcpAoRotationStatus {
                desired: desired.generation,
                applied: self.tcp_ao_committed_generation,
                phase: TcpAoRotationPhase::Deleting,
                last_error: None,
            };
            self.rotation_status_tx.send_replace(status.clone());
            return Ok(status);
        }

        plan_delete_listener_generation(
            &self.tcp_ao_keys.keys,
            desired.keys.as_ref(),
            self.tcp_ao_generation,
            desired.generation,
        )?;
        retain_pending_listener_generation(&mut self.pending_tcp_ao_generation, desired)?;
        let current = self
            .tcp_ao_keys
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        let desired_owners = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        let result = preflight_delete(&self.listener, &current, &desired_owners)
            .and_then(|preflight| apply_delete(&self.listener, preflight, &desired_owners));

        match result {
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
                let status = TcpAoRotationStatus {
                    desired: desired.generation,
                    applied: self.tcp_ao_committed_generation,
                    phase: TcpAoRotationPhase::Deleting,
                    last_error: None,
                };
                self.rotation_status_tx.send_replace(status.clone());
                Ok(status)
            }
            Err(error) => {
                let mutation_started = error.mutation_started();
                let mut detail = error.into_inner().to_string();
                if mutation_started {
                    // Reconstitute the exact old listener inventory before
                    // returning whenever possible. The removed MKTs were
                    // already deprecated and unselected; restoring them keeps
                    // the last committed generation usable and makes the
                    // identical deletion retryable.
                    let recovery = preflight_restore(&self.listener, &current)
                        .and_then(|preflight| apply_restore(&self.listener, preflight, &current));
                    if let Err(recovery) = recovery {
                        detail = format!(
                            "{detail}; failed to restore the exact prior listener inventory: \
                             {recovery}; the exact prior inventory must be re-established and \
                             verified before retry; restart the daemon if the kernel inventory \
                             remains partial or cannot be proven exact"
                        );
                    }
                }
                let status = TcpAoRotationStatus {
                    desired: desired.generation,
                    applied: self.tcp_ao_committed_generation,
                    phase: TcpAoRotationPhase::DeleteFailed,
                    last_error: Some(detail.clone()),
                };
                self.rotation_status_tx.send_replace(status);
                Err(std::io::Error::other(detail))
            }
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
                    owner: owner.owner,
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            let desired_owners = desired
                .keys
                .iter()
                .map(|owner| crate::socket_opts::TcpAoMktOwner {
                    owner: owner.owner,
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
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                keyring: &owner.config,
            })
            .collect::<Vec<_>>();
        let desired = desired
            .keys
            .iter()
            .map(|owner| crate::socket_opts::TcpAoMktOwner {
                owner: owner.owner,
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
                    owner: owner.owner,
                    peer: owner.peer,
                    prefix_len: owner.prefix_len,
                    keyring: &owner.config,
                })
                .collect::<Vec<_>>();
            verify_complete_listener_inventory(listener, &owners)
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
        let previous_delete_owners = accepted_previous_delete_owners(
            &covering_owners,
            self.previous_tcp_ao_generation.as_ref(),
            self.tcp_ao_generation,
        );
        let previous_key_counts = accepted_previous_key_counts(
            &covering_owners,
            self.previous_tcp_ao_generation.as_ref(),
            self.tcp_ao_generation,
        );
        let receipt_owners = covering_owners
            .iter()
            .map(|owned| crate::socket_opts::TcpAoMktOwner {
                owner: owned.owner,
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
            crate::socket_opts::inspect_tcp_ao_accepted_generation(stream, &receipt, peer_ip);
        let (initial, reconcile_previous) = resolve_accepted_tcp_ao_generation(
            accepted,
            previous_delete_owners.as_deref(),
            |previous| {
                self.reconcile_queued_tcp_ao_deletion(stream, peer_ip, previous, &receipt_owners)
            },
        )?;
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

    fn reconcile_queued_tcp_ao_deletion(
        &self,
        stream: &TcpStream,
        peer_ip: IpAddr,
        previous: &[&TcpAoListenerKey],
        desired: &[crate::socket_opts::TcpAoMktOwner<'_>],
    ) -> std::io::Result<TcpAoInfoSnapshot> {
        let previous_owners = previous
            .iter()
            .map(|owned| crate::socket_opts::TcpAoMktOwner {
                owner: owned.owner,
                peer: owned.peer,
                prefix_len: owned.prefix_len,
                keyring: &owned.config,
            })
            .collect::<Vec<_>>();
        let preflight = crate::socket_opts::preflight_tcp_ao_delete(
            stream,
            &previous_owners,
            desired,
            Some(peer_ip),
        )?;
        let repaired = crate::socket_opts::apply_tcp_ao_delete(stream, preflight, desired)
            .map_err(crate::socket_opts::TcpAoDeleteApplyError::into_inner)?
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "TCP-AO queued-child deletion returned no connected snapshot",
                )
            })?;
        info!(
            peer = %peer_ip,
            generation = self.tcp_ao_generation.as_u64(),
            "reconciled queued TCP-AO child through adjacent deletion generation"
        );
        Ok(repaired)
    }
}

fn verify_complete_listener_inventory(
    listener: &TcpListener,
    owners: &[crate::socket_opts::TcpAoMktOwner<'_>],
) -> std::io::Result<()> {
    match crate::socket_opts::capture_tcp_ao_complete_owned_receipt(listener, owners) {
        Ok(_) => Ok(()),
        Err(error) if owners.is_empty() && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn resolve_accepted_tcp_ao_generation<F>(
    accepted: std::io::Result<crate::socket_opts::TcpAoAcceptedGeneration>,
    previous_delete_owners: Option<&[&TcpAoListenerKey]>,
    repair_deleted_child: F,
) -> std::io::Result<(TcpAoInfoSnapshot, bool)>
where
    F: FnOnce(&[&TcpAoListenerKey]) -> std::io::Result<TcpAoInfoSnapshot>,
{
    match accepted {
        Ok(crate::socket_opts::TcpAoAcceptedGeneration::Current(info)) => Ok((info, false)),
        Ok(crate::socket_opts::TcpAoAcceptedGeneration::Previous(info)) => Ok((info, true)),
        Err(current_error) => {
            let Some(previous) = previous_delete_owners else {
                return Err(current_error);
            };
            repair_deleted_child(previous).map(|repaired| (repaired, false))
        }
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

fn accepted_previous_delete_owners<'a>(
    current: &[&TcpAoListenerKey],
    previous: Option<&'a TcpAoPreviousListenerGeneration>,
    current_generation: TcpAoRotationGeneration,
) -> Option<Vec<&'a TcpAoListenerKey>> {
    let previous = previous?;
    if previous.generation.next() != Some(current_generation) {
        return None;
    }
    let previous_covering = previous
        .keys
        .keys
        .iter()
        .filter(|owner| {
            current.iter().any(|candidate| {
                listener_owner_identity(candidate) == listener_owner_identity(owner)
            })
        })
        .collect::<Vec<_>>();
    if previous_covering.len() != current.len() {
        return None;
    }
    let mut removed = false;
    for current_owner in current {
        let mut matches = previous_covering.iter().filter(|previous_owner| {
            listener_owner_identity(previous_owner) == listener_owner_identity(current_owner)
        });
        let previous_owner = *matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        let survivors =
            deletion_survivor_indices(&previous_owner.config, &current_owner.config).ok()?;
        removed |= survivors.len() != previous_owner.config.0.len();
    }
    removed.then_some(previous_covering)
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

fn tcp_ao_key_core_eq(current: &TcpAoConfig, desired: &TcpAoConfig) -> bool {
    current.key == desired.key
        && current.send_id == desired.send_id
        && current.recv_id == desired.recv_id
        && current.algorithm == desired.algorithm
}

fn selected_key_index(keyring: &TcpAoKeyring) -> Option<usize> {
    let selected = keyring.selected()?;
    keyring
        .iter()
        .position(|candidate| std::ptr::eq(candidate, selected))
}

fn validate_selection_progress(
    current: &[TcpAoListenerKey],
    desired: &[TcpAoListenerKey],
) -> std::io::Result<()> {
    if current.len() != desired.len()
        || current
            .iter()
            .map(listener_owner_identity)
            .collect::<HashSet<_>>()
            != desired
                .iter()
                .map(listener_owner_identity)
                .collect::<HashSet<_>>()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO selection may not add, remove, move, or duplicate listener owners",
        ));
    }
    for owner in current {
        let desired_owner = desired
            .iter()
            .find(|candidate| listener_owner_identity(candidate) == listener_owner_identity(owner))
            .expect("owner identity sets were compared");
        if owner.config.0.len() != desired_owner.config.0.len()
            || !owner
                .config
                .iter()
                .zip(desired_owner.config.iter())
                .all(|(current, desired)| {
                    tcp_ao_key_core_eq(current, desired)
                        && (!current.deprecated || desired.deprecated)
                        && current.preferred == desired.preferred
                })
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO selection progress changed kernel MKT identity or successor preference",
            ));
        }
    }
    Ok(())
}

fn deletion_survivor_indices(
    current: &TcpAoKeyring,
    desired: &TcpAoKeyring,
) -> std::io::Result<Vec<usize>> {
    if desired.0.is_empty() || desired.0.len() > current.0.len() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion requires a nonempty survivor keyring",
        ));
    }
    let mut survivors = Vec::with_capacity(desired.0.len());
    let mut search_from = 0;
    for desired_key in &desired.0 {
        let matches = current
            .0
            .iter()
            .enumerate()
            .skip(search_from)
            .filter(|(_, current_key)| *current_key == desired_key)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO deletion reorders, redefines, duplicates, or adds an MKT",
            ));
        }
        survivors.push(matches[0]);
        search_from = matches[0] + 1;
    }
    if current.selected() != desired.selected() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion may not remove or change the selected MKT",
        ));
    }
    if current
        .0
        .iter()
        .enumerate()
        .any(|(index, key)| !survivors.contains(&index) && !key.deprecated)
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion may remove only deprecated MKTs",
        ));
    }
    Ok(survivors)
}

fn plan_delete_listener_generation(
    current: &[TcpAoListenerKey],
    desired: &[TcpAoListenerKey],
    applied_generation: TcpAoRotationGeneration,
    desired_generation: TcpAoRotationGeneration,
) -> std::io::Result<()> {
    if applied_generation.next() != Some(desired_generation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion generation is not the immediate applied successor",
        ));
    }
    let current_identities = current
        .iter()
        .map(listener_owner_identity)
        .collect::<HashSet<_>>();
    let desired_identities = desired
        .iter()
        .map(listener_owner_identity)
        .collect::<HashSet<_>>();
    if current_identities.len() != current.len()
        || desired_identities.len() != desired.len()
        || current_identities != desired_identities
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion may not add, remove, move, or duplicate listener owners",
        ));
    }
    let mut removed = false;
    for current_owner in current {
        let desired_owner = desired
            .iter()
            .find(|candidate| {
                listener_owner_identity(candidate) == listener_owner_identity(current_owner)
            })
            .expect("owner identity sets were compared");
        let survivors = deletion_survivor_indices(&current_owner.config, &desired_owner.config)?;
        removed |= survivors.len() != current_owner.config.0.len();
    }
    if !removed {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO deletion generation does not remove an MKT",
        ));
    }
    Ok(())
}

fn plan_selection_listener_generation(
    current: &[TcpAoListenerKey],
    desired: &[TcpAoListenerKey],
    applied_generation: TcpAoRotationGeneration,
    desired_generation: TcpAoRotationGeneration,
) -> std::io::Result<Vec<TcpAoListenerKey>> {
    if applied_generation.next() != Some(desired_generation) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO selection generation is not the immediate applied successor",
        ));
    }
    if current.len() != desired.len()
        || current
            .iter()
            .map(listener_owner_identity)
            .collect::<HashSet<_>>()
            != desired
                .iter()
                .map(listener_owner_identity)
                .collect::<HashSet<_>>()
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO selection may not add, remove, move, or duplicate listener owners",
        ));
    }
    let mut staged = desired.to_vec();
    let mut changed_owner = false;
    for current_owner in current {
        let desired_owner = desired
            .iter()
            .find(|candidate| {
                listener_owner_identity(candidate) == listener_owner_identity(current_owner)
            })
            .expect("owner identity sets were compared");
        if current_owner.config == desired_owner.config {
            continue;
        }
        changed_owner = true;
        if current_owner.config.0.len() != desired_owner.config.0.len()
            || !current_owner
                .config
                .iter()
                .zip(desired_owner.config.iter())
                .all(|(current, desired)| {
                    tcp_ao_key_core_eq(current, desired)
                        && (!current.deprecated || desired.deprecated)
                })
            || selected_key_index(&current_owner.config)
                == selected_key_index(&desired_owner.config)
            || selected_key_index(&desired_owner.config)
                .is_none_or(|index| !desired_owner.config.0[index].preferred)
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "TCP-AO selection must keep the exact installed MKT order and select an already-installed successor",
            ));
        }
        let staged_owner = staged
            .iter_mut()
            .find(|candidate| {
                listener_owner_identity(candidate) == listener_owner_identity(current_owner)
            })
            .expect("owner identity sets were compared");
        for (staged_key, current_key) in staged_owner
            .config
            .0
            .iter_mut()
            .zip(&current_owner.config.0)
        {
            staged_key.deprecated = current_key.deprecated;
        }
    }
    if !changed_owner {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "TCP-AO selection generation does not select a successor",
        ));
    }
    Ok(staged)
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
    // Must precede bind(). The daemon is normally the active closer at
    // shutdown, so on an ordinary restart-under-traffic a connection the
    // previous generation accepted still holds the listen port in
    // FIN_WAIT/TIME_WAIT and the bind fails EADDRINUSE. `socket2` builds a
    // raw socket, so it does not get the SO_REUSEADDR that `std`/`mio`
    // apply for us on the gRPC and metrics listeners.
    //
    // SO_REUSEADDR only, never SO_REUSEPORT: SO_REUSEPORT permits
    // concurrent binds, which would let two daemon generations serve the
    // listen port at once and split inbound sessions between them.
    socket.set_reuse_address(true)?;
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

    fn tcp_ao_delete_generations() -> (TcpAoListenerKey, TcpAoListenerGeneration) {
        let mut current = tcp_ao_owner();
        current.config.0[0].deprecated = true;

        let mut successor = current.config.0[0].clone();
        successor.key = "successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.preferred = true;
        successor.deprecated = false;

        let mut retired_tail = current.config.0[0].clone();
        retired_tail.key = "retired-tail".into();
        retired_tail.send_id = 17;
        retired_tail.recv_id = 19;
        current.config.0.push(successor.clone());
        current.config.0.push(retired_tail);

        let mut desired = current.clone();
        desired.config = TcpAoKeyring(vec![successor]);
        (
            current,
            TcpAoListenerGeneration::new(TcpAoRotationGeneration::new(2).unwrap(), vec![desired]),
        )
    }

    fn listener_owner_inventory(
        owners: &[crate::socket_opts::TcpAoMktOwner<'_>],
    ) -> Vec<TcpAoListenerKey> {
        owners
            .iter()
            .map(|owner| TcpAoListenerKey {
                owner: owner.owner,
                peer: owner.peer,
                prefix_len: owner.prefix_len,
                config: owner.keyring.clone(),
            })
            .collect()
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
    fn selection_generation_stages_deprecation_until_observation_commit() {
        let mut current = tcp_ao_owner();
        let mut successor = current.config.0[0].clone();
        successor.key = "successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        current.config.0.push(successor);

        let mut desired = current.clone();
        desired.config.0[0].deprecated = true;
        desired.config.0[1].preferred = true;
        let staged = plan_selection_listener_generation(
            std::slice::from_ref(&current),
            std::slice::from_ref(&desired),
            TcpAoRotationGeneration::STARTUP,
            TcpAoRotationGeneration::new(2).unwrap(),
        )
        .unwrap();
        assert!(staged[0].config.0[1].preferred);
        assert!(!staged[0].config.0[0].deprecated);
        validate_selection_progress(&staged, std::slice::from_ref(&desired)).unwrap();

        let mut add_and_select = desired.clone();
        let mut third = add_and_select.config.0[1].clone();
        third.key = "third".into();
        third.send_id = 12;
        third.recv_id = 14;
        third.preferred = false;
        add_and_select.config.0.push(third);
        assert!(
            plan_selection_listener_generation(
                &[current],
                &[add_and_select],
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_err()
        );
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
    fn deletion_generation_keeps_owner_and_selection_and_removes_only_deprecated_keys() {
        let mut current = tcp_ao_owner();
        current.config.0[0].deprecated = true;
        let mut successor = current.config.0[0].clone();
        successor.key = "successor".into();
        successor.send_id = 11;
        successor.recv_id = 13;
        successor.deprecated = false;
        successor.preferred = true;
        current.config.0.push(successor.clone());
        let mut desired = current.clone();
        desired.config.0.remove(0);

        plan_delete_listener_generation(
            std::slice::from_ref(&current),
            std::slice::from_ref(&desired),
            TcpAoRotationGeneration::STARTUP,
            TcpAoRotationGeneration::new(2).unwrap(),
        )
        .unwrap();

        let mut unsafe_current = current.clone();
        unsafe_current.config.0[0].deprecated = false;
        assert!(
            plan_delete_listener_generation(
                &[unsafe_current],
                std::slice::from_ref(&desired),
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_err()
        );
        let mut moved = desired;
        moved.peer = "192.0.2.2".parse().unwrap();
        assert!(
            plan_delete_listener_generation(
                &[current],
                &[moved],
                TcpAoRotationGeneration::STARTUP,
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_err()
        );
    }

    #[test]
    fn accepted_deletion_fallback_retains_complete_overlapping_owner_superset() {
        let accepted_peer: IpAddr = "192.0.2.9".parse().unwrap();
        let mut covering = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: tcp_ao_config(),
        };
        covering.config.0[0].deprecated = true;
        let mut covering_successor = covering.config.0[0].clone();
        covering_successor.key = "covering-successor".into();
        covering_successor.send_id = 2;
        covering_successor.recv_id = 2;
        covering_successor.deprecated = false;
        covering_successor.preferred = true;
        covering.config.0.push(covering_successor);

        let mut exact = tcp_ao_owner();
        exact.peer = accepted_peer;
        exact.config.0[0].send_id = 7;
        exact.config.0[0].recv_id = 9;
        let previous_keys = vec![covering.clone(), exact.clone()];
        let mut desired_covering = covering;
        desired_covering.config.0.remove(0);
        let current_index = TcpAoListenerKeyIndex::new(vec![desired_covering, exact.clone()]);
        let current_union = current_index.owned_union(accepted_peer);
        assert_eq!(
            current_union.len(),
            2,
            "the current receipt must be a union"
        );
        let previous = TcpAoPreviousListenerGeneration {
            generation: TcpAoRotationGeneration::STARTUP,
            keys: TcpAoListenerKeyIndex::new(previous_keys),
        };
        let fallback = accepted_previous_delete_owners(
            &current_union,
            Some(&previous),
            TcpAoRotationGeneration::new(2).unwrap(),
        )
        .expect("the exact adjacent superset must remain repairable");
        assert_eq!(fallback.len(), 2);
        assert_eq!(
            fallback
                .iter()
                .map(|owner| owner.config.0.len())
                .sum::<usize>(),
            3
        );

        let incomplete_previous = TcpAoPreviousListenerGeneration {
            generation: TcpAoRotationGeneration::STARTUP,
            keys: TcpAoListenerKeyIndex::new(vec![exact]),
        };
        assert!(
            accepted_previous_delete_owners(
                &current_union,
                Some(&incomplete_previous),
                TcpAoRotationGeneration::new(2).unwrap(),
            )
            .is_none(),
            "dropping a covering owner must make the adjacent repair fail closed"
        );
    }

    #[test]
    fn accepted_child_bridge_invokes_exact_adjacent_deletion_repair() {
        let covering = TcpAoListenerKey {
            owner: TcpAoListenerOwnerKind::Dynamic,
            peer: "192.0.2.0".parse().unwrap(),
            prefix_len: 24,
            config: tcp_ao_config(),
        };
        let exact = tcp_ao_owner();
        let previous = vec![&covering, &exact];
        let called = std::cell::Cell::new(false);
        let expected = tcp_ao_info(2, 41);

        let (repaired, reconcile_add_only) = resolve_accepted_tcp_ao_generation(
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "child is not the current deletion generation",
            )),
            Some(&previous),
            |owners| {
                called.set(true);
                assert_eq!(
                    owners.len(),
                    2,
                    "repair must receive the complete owner union"
                );
                Ok(expected.clone())
            },
        )
        .unwrap();
        assert!(called.get());
        assert_eq!(repaired, expected);
        assert!(!reconcile_add_only);

        let without_adjacent = resolve_accepted_tcp_ao_generation(
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "child is not current",
            )),
            None,
            |_| panic!("repair must not run without an exact adjacent inventory"),
        );
        assert!(without_adjacent.is_err());
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
    async fn deletion_generation_advances_when_only_opposite_family_static_socket_changes() {
        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        let startup = TcpAoRotationGeneration::STARTUP;
        let generation = TcpAoRotationGeneration::new(2).unwrap();
        let desired = TcpAoListenerGeneration::new(generation, Vec::new());
        let verification_calls = std::cell::Cell::new(0_u8);

        listener
            .preflight_delete_generation_with(&desired, |_socket, owners| {
                verification_calls.set(verification_calls.get() + 1);
                assert!(owners.is_empty());
                Ok(())
            })
            .unwrap();
        let staged = listener
            .apply_delete_generation_with(&desired, |_socket, owners| {
                verification_calls.set(verification_calls.get() + 1);
                assert!(owners.is_empty());
                Ok(())
            })
            .unwrap();
        assert_eq!(verification_calls.get(), 2);
        assert_eq!(listener.tcp_ao_generation, generation);
        assert_eq!(listener.tcp_ao_committed_generation, startup);
        assert_eq!(listener.pending_tcp_ao_generation.as_ref(), Some(&desired));
        assert!(listener.previous_tcp_ao_generation.is_none());
        assert_eq!(staged.desired, generation);
        assert_eq!(staged.applied, startup);
        assert_eq!(staged.phase, TcpAoRotationPhase::Deleting);

        let committed = listener
            .acknowledge_global_commit_generation_with(generation, |_socket, _desired| Ok(()))
            .unwrap();
        assert_eq!(committed.applied, generation);
        assert_eq!(committed.phase, TcpAoRotationPhase::Idle);

        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut rejected = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        let injected = || std::io::Error::other("injected exact-inventory rejection");
        assert!(
            rejected
                .preflight_delete_generation_with(&desired, |_socket, _owners| Err(injected()))
                .is_err()
        );
        assert!(
            rejected
                .apply_delete_generation_with(&desired, |_socket, _owners| Err(injected()))
                .is_err()
        );
        assert_eq!(rejected.tcp_ao_generation, startup);
        assert_eq!(rejected.tcp_ao_committed_generation, startup);
        assert!(rejected.pending_tcp_ao_generation.is_none());
        assert_eq!(
            rejected.rotation_status_tx.borrow().phase,
            TcpAoRotationPhase::Idle
        );
    }

    /// Load-bearing: removing the mutating-failure restoration makes the
    /// same-generation retry fail its exact-current assertion.
    #[tokio::test]
    async fn partial_listener_deletion_restores_exact_inventory_before_retry() {
        let (current, desired) = tcp_ao_delete_generations();
        let prior_inventory = vec![current.clone()];
        let desired_inventory = desired.keys.to_vec();
        assert_eq!(
            prior_inventory[0]
                .config
                .iter()
                .map(|config| config.send_id)
                .collect::<Vec<_>>(),
            vec![7, 11, 17]
        );

        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        listener.tcp_ao_keys = TcpAoListenerKeyIndex::new(vec![current]);

        let kernel_inventory = RefCell::new(prior_inventory.clone());
        let delete_mutations = std::cell::Cell::new(0_u8);
        let restore_preflights = std::cell::Cell::new(0_u8);
        let restore_applies = std::cell::Cell::new(0_u8);
        let error = listener
            .apply_delete_generation_with_operations(
                &desired,
                |_, _| panic!("real deletion must not take the metadata-only path"),
                |_, current, desired| {
                    assert_eq!(listener_owner_inventory(current), prior_inventory);
                    assert_eq!(listener_owner_inventory(desired), desired_inventory);
                    assert_eq!(*kernel_inventory.borrow(), prior_inventory);
                    Ok(())
                },
                |_, (), _| {
                    delete_mutations.set(delete_mutations.get() + 1);
                    kernel_inventory.borrow_mut()[0].config.0.remove(0);
                    Err(crate::socket_opts::TcpAoDeleteApplyError::after_mutation(
                        std::io::Error::other("injected second deletion failure"),
                    ))
                },
                |_, current| {
                    restore_preflights.set(restore_preflights.get() + 1);
                    assert_eq!(
                        listener_owner_inventory(current),
                        prior_inventory,
                        "restore preflight lost owner or key declaration order"
                    );
                    Ok(())
                },
                |_, (), current| {
                    restore_applies.set(restore_applies.get() + 1);
                    *kernel_inventory.borrow_mut() = listener_owner_inventory(current);
                    Ok(())
                },
            )
            .unwrap_err();
        assert!(error.to_string().contains("second deletion failure"));
        assert_eq!(restore_preflights.get(), 1);
        assert_eq!(restore_applies.get(), 1);
        assert_eq!(*kernel_inventory.borrow(), prior_inventory);
        assert_eq!(listener.tcp_ao_generation, TcpAoRotationGeneration::STARTUP);
        assert_eq!(listener.pending_tcp_ao_generation.as_ref(), Some(&desired));

        let status = listener
            .apply_delete_generation_with_operations(
                &desired,
                |_, _| panic!("retry must not take the metadata-only path"),
                |_, current, desired| {
                    assert_eq!(listener_owner_inventory(current), prior_inventory);
                    assert_eq!(
                        *kernel_inventory.borrow(),
                        prior_inventory,
                        "retry did not begin from the restored exact inventory"
                    );
                    assert_eq!(listener_owner_inventory(desired), desired_inventory);
                    Ok(())
                },
                |_, (), desired| {
                    delete_mutations.set(delete_mutations.get() + 1);
                    *kernel_inventory.borrow_mut() = listener_owner_inventory(desired);
                    Ok(())
                },
                |_, _| -> std::io::Result<()> {
                    panic!("successful retry must not preflight restoration")
                },
                |_, (), _| panic!("successful retry must not apply restoration"),
            )
            .unwrap();
        assert_eq!(delete_mutations.get(), 2);
        assert_eq!(*kernel_inventory.borrow(), desired_inventory);
        assert_eq!(status.phase, TcpAoRotationPhase::Deleting);
        assert_eq!(listener.tcp_ao_generation, desired.generation);
        assert_eq!(listener.tcp_ao_keys.keys.as_slice(), desired.keys.as_ref());
    }

    /// Load-bearing: removing the recovery diagnostic or bypassing the retry's
    /// exact-current preflight makes this test fail.
    #[tokio::test]
    async fn failed_listener_restoration_requires_exact_reinspection_before_retry() {
        let (current, desired) = tcp_ao_delete_generations();
        let prior_inventory = vec![current.clone()];
        let (accept_tx, _accept_rx) = mpsc::channel(1);
        let mut listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
            .await
            .unwrap();
        listener.tcp_ao_keys = TcpAoListenerKeyIndex::new(vec![current]);

        let kernel_inventory = RefCell::new(prior_inventory.clone());
        let delete_preflights = std::cell::Cell::new(0_u8);
        let delete_mutations = std::cell::Cell::new(0_u8);
        let restore_preflights = std::cell::Cell::new(0_u8);
        let restore_applies = std::cell::Cell::new(0_u8);
        let error = listener
            .apply_delete_generation_with_operations(
                &desired,
                |_, _| panic!("real deletion must not take the metadata-only path"),
                |_, current, _| {
                    delete_preflights.set(delete_preflights.get() + 1);
                    assert_eq!(listener_owner_inventory(current), prior_inventory);
                    assert_eq!(*kernel_inventory.borrow(), prior_inventory);
                    Ok(())
                },
                |_, (), _| {
                    delete_mutations.set(delete_mutations.get() + 1);
                    kernel_inventory.borrow_mut()[0].config.0.remove(0);
                    Err(crate::socket_opts::TcpAoDeleteApplyError::after_mutation(
                        std::io::Error::other("injected partial deletion"),
                    ))
                },
                |_, current| {
                    restore_preflights.set(restore_preflights.get() + 1);
                    assert_eq!(listener_owner_inventory(current), prior_inventory);
                    Ok(())
                },
                |_, (), current| {
                    restore_applies.set(restore_applies.get() + 1);
                    assert_eq!(listener_owner_inventory(current), prior_inventory);
                    Err(std::io::Error::other("injected restoration refusal"))
                },
            )
            .unwrap_err();
        let detail = error.to_string();
        assert!(detail.contains("failed to restore the exact prior listener inventory"));
        assert!(detail.contains("must be re-established and verified before retry"));
        assert!(detail.contains("restart the daemon if the kernel inventory remains partial"));
        assert_eq!(delete_mutations.get(), 1);
        assert_eq!(restore_preflights.get(), 1);
        assert_eq!(restore_applies.get(), 1);

        let retry = listener
            .apply_delete_generation_with_operations(
                &desired,
                |_, _| panic!("retry must not take the metadata-only path"),
                |_, current, _| {
                    delete_preflights.set(delete_preflights.get() + 1);
                    if *kernel_inventory.borrow() != listener_owner_inventory(current) {
                        return Err(crate::socket_opts::TcpAoDeleteApplyError::before_mutation(
                            std::io::Error::new(
                                std::io::ErrorKind::PermissionDenied,
                                "injected exact-current preflight rejection",
                            ),
                        ));
                    }
                    Ok(())
                },
                |_, (), _| {
                    delete_mutations.set(delete_mutations.get() + 1);
                    Err(crate::socket_opts::TcpAoDeleteApplyError::after_mutation(
                        std::io::Error::other(
                            "injected exact-current preflight rejection was bypassed; partial \
                             inventory reached a second deletion mutation",
                        ),
                    ))
                },
                |_, _| Ok(()),
                |_, (), _| Ok(()),
            )
            .unwrap_err();
        assert!(retry.to_string().contains("exact-current preflight"));
        assert_eq!(delete_preflights.get(), 2);
        assert_eq!(delete_mutations.get(), 1);
        assert_eq!(restore_preflights.get(), 1);
        assert_eq!(restore_applies.get(), 1);
        assert_eq!(listener.tcp_ao_generation, TcpAoRotationGeneration::STARTUP);
        assert_eq!(listener.pending_tcp_ao_generation.as_ref(), Some(&desired));
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

    /// Restart-under-traffic: the daemon is the active closer at shutdown,
    /// so a connection it accepted on the listen port lingers in
    /// `FIN_WAIT`/`TIME_WAIT` while the next generation binds. Without
    /// `SO_REUSEADDR` on both generations that bind fails `EADDRINUSE`.
    #[tokio::test]
    async fn bind_socket2_listener_rebinds_over_a_lingering_accepted_connection() {
        let options = ListenerSocketOptions::default();
        let listener = bind_socket2_listener("127.0.0.1:0".parse().unwrap(), &options)
            .expect("first generation binds");
        let addr = listener.local_addr().expect("listener local addr");

        let client = std::net::TcpStream::connect(addr).expect("inbound connection");
        let (accepted, _) = listener.accept().await.expect("accept the connection");

        // Close the accepted socket first (daemon-as-active-closer), then
        // the peer, then the listener: the accepted endpoint is left
        // holding `addr` in a post-close state.
        drop(accepted);
        drop(client);
        drop(listener);

        bind_socket2_listener(addr, &options)
            .expect("second generation rebinds over the lingering connection");
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
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

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
        let mut accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
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
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 24,
                keyring: &covering_config,
            },
            crate::socket_opts::TcpAoMktOwner {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "127.0.0.2".parse().unwrap(),
                prefix_len: 32,
                keyring: &static_config,
            },
        ];
        let desired_owners = [
            crate::socket_opts::TcpAoMktOwner {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 24,
                keyring: &covering_config,
            },
            crate::socket_opts::TcpAoMktOwner {
                owner: TcpAoListenerOwnerKind::Static,
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

        // Select the newly installed static-exact successor on the accepted
        // socket while retaining the covering dynamic owner. The predecessor
        // remains non-deprecated through the one-shot peer-use proof; final
        // deprecation is an application-metadata-only commit afterward.
        let mut staged_static = desired_static.clone();
        staged_static.0[1].preferred = false;
        staged_static.0[1].deprecated = false;
        staged_static.0[2].preferred = true;
        let selected_owner = TcpAoSelectedOwner {
            owner: TcpAoListenerOwnerKind::Static,
            peer: "127.0.0.2".parse().unwrap(),
            prefix_len: 32,
        };
        let selection_owners = [
            crate::socket_opts::TcpAoMktOwner {
                owner: TcpAoListenerOwnerKind::Dynamic,
                peer: "127.0.0.0".parse().unwrap(),
                prefix_len: 24,
                keyring: &covering_config,
            },
            crate::socket_opts::TcpAoMktOwner {
                owner: TcpAoListenerOwnerKind::Static,
                peer: "127.0.0.2".parse().unwrap(),
                prefix_len: 32,
                keyring: &staged_static,
            },
        ];
        let selection_preflight = crate::socket_opts::preflight_tcp_ao_rnext(
            &accepted.stream,
            &selection_owners,
            selected_owner,
            "127.0.0.2".parse().unwrap(),
        )
        .unwrap();
        let selection = crate::socket_opts::apply_tcp_ao_rnext(
            &accepted.stream,
            &selection_preflight,
            selected_owner,
            "127.0.0.2".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(selection.snapshot.keys.len(), 4);
        assert_eq!(selection.snapshot.current_key, 3);
        assert_eq!(selection.snapshot.rnext_key, 4);

        let client_successor = desired_static.0[2].clone();
        crate::socket_opts::set_tcp_ao_config(
            &signed,
            destination.ip(),
            32,
            &client_successor,
            crate::socket_opts::TcpAoSocketRole::Listener,
        )
        .unwrap();
        crate::socket_opts::set_tcp_ao_rnext(&signed, 4).unwrap();
        let std_signed: std::net::TcpStream = signed.into();
        std_signed.set_nonblocking(true).unwrap();
        let mut signed = TcpStream::from_std(std_signed).unwrap();

        // The first client packet carries RNext=4 so the server sends with
        // key 4. After receiving that response, the client sends one packet
        // authenticated with key 4, strictly increasing the server's target
        // key pkt_good counter beyond the pre-SET_RNEXT baseline.
        signed.write_all(b"request-successor").await.unwrap();
        let mut request = vec![0; b"request-successor".len()];
        tokio::time::timeout(
            Duration::from_secs(2),
            accepted.stream.read_exact(&mut request),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(request, b"request-successor");
        accepted
            .stream
            .write_all(b"server-uses-successor")
            .await
            .unwrap();
        let mut response = vec![0; b"server-uses-successor".len()];
        tokio::time::timeout(Duration::from_secs(2), signed.read_exact(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"server-uses-successor");
        signed.write_all(b"verified-successor").await.unwrap();
        let mut verified = vec![0; b"verified-successor".len()];
        tokio::time::timeout(
            Duration::from_secs(2),
            accepted.stream.read_exact(&mut verified),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(verified, b"verified-successor");

        let observed = crate::socket_opts::observe_tcp_ao_successor(
            &accepted.stream,
            &selection_owners,
            selected_owner,
            "127.0.0.2".parse().unwrap(),
            selection.successor_pkt_good_baseline,
        )
        .unwrap_or_else(|error| panic!("successor observation failed: {error}"));
        assert_eq!(observed.current_key, 4);
        assert_eq!(observed.rnext_key, 4);
        assert_eq!(observed.keys.len(), 4);
        assert_eq!(
            observed
                .keys
                .iter()
                .map(|key| (key.peer, key.prefix_len, key.send_id, key.recv_id))
                .collect::<Vec<_>>(),
            vec![
                ("127.0.0.0".parse().unwrap(), 24, 1, 1),
                ("127.0.0.2".parse().unwrap(), 32, 2, 2),
                ("127.0.0.2".parse().unwrap(), 32, 3, 3),
                ("127.0.0.2".parse().unwrap(), 32, 4, 4),
            ]
        );
        assert_eq!(observed.pkt_bad, 0);
        assert_eq!(observed.pkt_key_not_found, 0);
        assert_eq!(observed.pkt_ao_required, 0);
        let predecessor = observed
            .keys
            .iter()
            .find(|key| key.send_id == 3 && key.recv_id == 3)
            .unwrap();
        assert!(!predecessor.is_rnext);
        assert!(!predecessor.deprecated);
        let successor = observed
            .keys
            .iter()
            .find(|key| key.send_id == 4 && key.recv_id == 4)
            .unwrap();
        assert!(successor.is_current);
        assert!(successor.is_rnext);
        assert!(
            successor.pkt_good > selection.successor_pkt_good_baseline,
            "successor traffic proof must be generation-relative"
        );
        let mut committed_static = staged_static.clone();
        committed_static.0[1].deprecated = true;
        assert!(
            committed_static.0[1].deprecated,
            "predecessor metadata becomes deprecated only after observation"
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
