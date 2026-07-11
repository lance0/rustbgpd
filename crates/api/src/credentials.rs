//! Atomic management-plane credential generations.

use std::fs;
use std::io::{BufReader, Cursor};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};

use crate::authz_runtime::BearerAuthSecret;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CredentialSource {
    pub token_file: Option<PathBuf>,
    pub tls: Option<TlsSource>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsSource {
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
    pub client_ca_file: PathBuf,
}

#[derive(Clone)]
pub struct ListenerCredentials {
    pub(crate) bearer: Option<BearerAuthSecret>,
    pub(crate) tls: Option<Arc<ServerConfig>>,
}

impl std::fmt::Debug for ListenerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerCredentials")
            .field("bearer", &self.bearer.is_some())
            .field("tls", &self.tls.is_some())
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct CredentialGeneration {
    sequence: u64,
    listeners: Arc<[ListenerCredentials]>,
}

#[derive(Clone, Debug)]
pub(crate) struct PinnedCredentialGeneration {
    generation: Arc<CredentialGeneration>,
    listener: usize,
}

impl PinnedCredentialGeneration {
    pub(crate) fn new(generation: Arc<CredentialGeneration>, listener: usize) -> Self {
        Self {
            generation,
            listener,
        }
    }

    pub(crate) fn bearer(&self) -> Option<&BearerAuthSecret> {
        self.generation.listener(self.listener).bearer.as_ref()
    }
}

impl CredentialGeneration {
    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub(crate) fn listener(&self, index: usize) -> &ListenerCredentials {
        &self.listeners[index]
    }
}

#[derive(Clone)]
pub struct CredentialStore {
    sources: Arc<[CredentialSource]>,
    active: Arc<ArcSwap<CredentialGeneration>>,
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialStore")
            .field("listeners", &self.sources.len())
            .field("sequence", &self.load().sequence())
            .finish_non_exhaustive()
    }
}

impl PartialEq for CredentialStore {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.active, &other.active)
    }
}

impl Eq for CredentialStore {}

impl CredentialStore {
    /// Load and validate the initial immutable generation.
    ///
    /// # Errors
    /// Returns a redacted error when any configured file cannot be read or its
    /// credential material is invalid.
    pub fn stage(sources: Vec<CredentialSource>) -> Result<Self, String> {
        let sources: Arc<[CredentialSource]> = sources.into();
        let generation = Arc::new(stage_generation(&sources, 1)?);
        Ok(Self {
            sources,
            active: Arc::new(ArcSwap::from(generation)),
        })
    }

    #[must_use]
    pub fn load(&self) -> Arc<CredentialGeneration> {
        self.active.load_full()
    }

    /// Stage all configured files, then atomically publish one generation.
    ///
    /// # Errors
    /// Returns a redacted error when any listener fails staging. The active
    /// generation is left unchanged.
    pub fn reload(&self) -> Result<u64, String> {
        let sequence = self.load().sequence.saturating_add(1);
        let candidate = Arc::new(stage_generation(&self.sources, sequence)?);
        self.active.store(candidate);
        Ok(sequence)
    }
}

fn stage_generation(
    sources: &[CredentialSource],
    sequence: u64,
) -> Result<CredentialGeneration, String> {
    let listeners = sources
        .iter()
        .enumerate()
        .map(|(index, source)| stage_listener(index, source))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CredentialGeneration {
        sequence,
        listeners: listeners.into(),
    })
}

fn stage_listener(index: usize, source: &CredentialSource) -> Result<ListenerCredentials, String> {
    let bearer = source
        .token_file
        .as_ref()
        .map(|path| {
            let token = fs::read_to_string(path).map_err(|e| {
                format!(
                    "listener {index}: failed to read token file {}: {e}",
                    path.display()
                )
            })?;
            let token = token.trim_end();
            if token.is_empty() {
                return Err(format!(
                    "listener {index}: token file {} is empty",
                    path.display()
                ));
            }
            Ok(BearerAuthSecret::from_token(token))
        })
        .transpose()?;
    let tls = source
        .tls
        .as_ref()
        .map(|source| build_tls(index, source))
        .transpose()?;
    Ok(ListenerCredentials { bearer, tls })
}

fn read_file(index: usize, label: &str, path: &Path) -> Result<Vec<u8>, String> {
    let bytes = fs::read(path).map_err(|e| {
        format!(
            "listener {index}: failed to read {label} file {}: {e}",
            path.display()
        )
    })?;
    if bytes.is_empty() {
        return Err(format!(
            "listener {index}: {label} file {} is empty",
            path.display()
        ));
    }
    Ok(bytes)
}

fn build_tls(index: usize, source: &TlsSource) -> Result<Arc<ServerConfig>, String> {
    let cert_bytes = read_file(index, "certificate", &source.cert_file)?;
    let key_bytes = read_file(index, "private key", &source.key_file)?;
    let ca_bytes = read_file(index, "client CA", &source.client_ca_file)?;
    let certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(cert_bytes)))
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| format!("listener {index}: invalid certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "listener {index}: certificate PEM contains no certificates"
        ));
    }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(Cursor::new(key_bytes)))
            .map_err(|e| format!("listener {index}: invalid private-key PEM: {e}"))?
            .ok_or_else(|| format!("listener {index}: private-key PEM contains no key"))?;
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(Cursor::new(ca_bytes)))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("listener {index}: invalid client-CA PEM: {e}"))?;
    let mut roots = RootCertStore::empty();
    let (accepted, rejected) = roots.add_parsable_certificates(ca_certs);
    if accepted == 0 || rejected != 0 {
        return Err(format!(
            "listener {index}: client-CA PEM contains invalid certificates"
        ));
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| format!("listener {index}: invalid client-CA verifier: {e}"))?;
    let config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("listener {index}: certificate/private-key mismatch: {e}"))?;
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};
    use std::sync::Barrier;
    use std::thread;

    use rcgen::{
        BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
        Issuer, KeyPair, KeyUsagePurpose, SanType,
    };
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::rustls::ClientConfig;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tonic::metadata::MetadataMap;
    use tonic::transport::server::Connected;

    use super::*;

    fn token_file(value: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(value.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    fn metadata(token: &str) -> MetadataMap {
        let mut metadata = MetadataMap::new();
        metadata.insert("authorization", format!("Bearer {token}").parse().unwrap());
        metadata
    }

    struct TlsBundle {
        ca_pem: String,
        server_pem: String,
        server_key_pem: String,
        client: Arc<ClientConfig>,
    }

    fn signed_leaf(
        issuer: &Issuer<'static, KeyPair>,
        name: &str,
        eku: ExtendedKeyUsagePurpose,
    ) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.subject_alt_names = vec![SanType::DnsName("localhost".try_into().unwrap())];
        params.distinguished_name.push(DnType::CommonName, name);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params.extended_key_usages.push(eku);
        let key = KeyPair::generate().unwrap();
        (params.signed_by(&key, issuer).unwrap(), key)
    }

    fn tls_bundle(name: &str) -> TlsBundle {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let mut params = CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{name} CA"));
        params.key_usages.extend([
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
        ]);
        let ca_key = KeyPair::generate().unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(params, ca_key);
        let (server, server_key) = signed_leaf(&issuer, name, ExtendedKeyUsagePurpose::ServerAuth);
        let (client, client_key) = signed_leaf(&issuer, name, ExtendedKeyUsagePurpose::ClientAuth);
        let mut roots = RootCertStore::empty();
        roots.add(ca.der().clone()).unwrap();
        let client_config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(
                vec![client.der().clone()],
                PrivateKeyDer::Pkcs8(client_key.serialize_der().into()),
            )
            .unwrap();
        TlsBundle {
            ca_pem: ca.pem(),
            server_pem: server.pem(),
            server_key_pem: server_key.serialize_pem(),
            client: Arc::new(client_config),
        }
    }

    fn overwrite(file: &mut NamedTempFile, bytes: &[u8]) {
        file.as_file_mut().set_len(0).unwrap();
        file.rewind().unwrap();
        file.write_all(bytes).unwrap();
        file.flush().unwrap();
    }

    async fn connect(
        config: Arc<ClientConfig>,
        addr: std::net::SocketAddr,
    ) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        let stream = TcpStream::connect(addr).await.unwrap();
        TlsConnector::from(config)
            .connect("localhost".to_string().try_into().unwrap(), stream)
            .await
    }

    #[test]
    fn bearer_reload_is_new_rpc_visible_and_old_snapshot_survives() {
        let mut token = token_file("old\n");
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: Some(token.path().to_path_buf()),
            tls: None,
        }])
        .unwrap();
        let old_generation = store.load();
        old_generation
            .listener(0)
            .bearer
            .as_ref()
            .unwrap()
            .authenticate_metadata(&metadata("old"))
            .unwrap();

        token.as_file_mut().set_len(0).unwrap();
        token.rewind().unwrap();
        token.write_all(b"new\n").unwrap();
        token.flush().unwrap();
        assert_eq!(store.reload().unwrap(), 2);

        let new_generation = store.load();
        assert!(
            new_generation
                .listener(0)
                .bearer
                .as_ref()
                .unwrap()
                .authenticate_metadata(&metadata("old"))
                .is_err()
        );
        new_generation
            .listener(0)
            .bearer
            .as_ref()
            .unwrap()
            .authenticate_metadata(&metadata("new"))
            .unwrap();
        old_generation
            .listener(0)
            .bearer
            .as_ref()
            .unwrap()
            .authenticate_metadata(&metadata("old"))
            .unwrap();
    }

    #[test]
    fn partial_stage_failure_preserves_complete_last_known_good() {
        let mut first = token_file("first-old");
        let mut second = token_file("second-old");
        let store = CredentialStore::stage(vec![
            CredentialSource {
                token_file: Some(first.path().to_path_buf()),
                tls: None,
            },
            CredentialSource {
                token_file: Some(second.path().to_path_buf()),
                tls: None,
            },
        ])
        .unwrap();
        first.as_file_mut().set_len(0).unwrap();
        first.rewind().unwrap();
        first.write_all(b"first-new").unwrap();
        first.flush().unwrap();
        second.as_file_mut().set_len(0).unwrap();
        second.rewind().unwrap();
        second.flush().unwrap();

        assert!(store.reload().is_err());
        assert_eq!(store.load().sequence(), 1);
        store
            .load()
            .listener(0)
            .bearer
            .as_ref()
            .unwrap()
            .authenticate_metadata(&metadata("first-old"))
            .unwrap();
        store
            .load()
            .listener(1)
            .bearer
            .as_ref()
            .unwrap()
            .authenticate_metadata(&metadata("second-old"))
            .unwrap();
    }

    #[test]
    fn concurrent_readers_observe_only_complete_generations() {
        let mut first = token_file("a-old");
        let mut second = token_file("b-old");
        let store = CredentialStore::stage(vec![
            CredentialSource {
                token_file: Some(first.path().to_path_buf()),
                tls: None,
            },
            CredentialSource {
                token_file: Some(second.path().to_path_buf()),
                tls: None,
            },
        ])
        .unwrap();
        first.as_file_mut().set_len(0).unwrap();
        first.rewind().unwrap();
        first.write_all(b"a-new").unwrap();
        first.flush().unwrap();
        second.as_file_mut().set_len(0).unwrap();
        second.rewind().unwrap();
        second.write_all(b"b-new").unwrap();
        second.flush().unwrap();

        let barrier = Arc::new(Barrier::new(2));
        let reader_store = store.clone();
        let reader_barrier = barrier.clone();
        let reader = thread::spawn(move || {
            reader_barrier.wait();
            for _ in 0..10_000 {
                let generation = reader_store.load();
                let old = generation
                    .listener(0)
                    .bearer
                    .as_ref()
                    .unwrap()
                    .authenticate_metadata(&metadata("a-old"))
                    .is_ok();
                let other_old = generation
                    .listener(1)
                    .bearer
                    .as_ref()
                    .unwrap()
                    .authenticate_metadata(&metadata("b-old"))
                    .is_ok();
                assert_eq!(old, other_old);
            }
        });
        barrier.wait();
        store.reload().unwrap();
        reader.join().unwrap();
    }

    #[tokio::test]
    async fn mtls_rotation_applies_to_new_handshakes_and_keeps_old_connection_alive() {
        let old = tls_bundle("old");
        let new = tls_bundle("new");
        let mut cert = token_file(&old.server_pem);
        let mut key = token_file(&old.server_key_pem);
        let mut ca = token_file(&old.ca_pem);
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: None,
            tls: Some(TlsSource {
                cert_file: cert.path().to_path_buf(),
                key_file: key.path().to_path_buf(),
                client_ca_file: ca.path().to_path_buf(),
            }),
        }])
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let old_server_config = store.load().listener(0).tls.clone().unwrap();
        let old_server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(old_server_config)
                .accept(tcp)
                .await
                .unwrap()
        });
        let mut old_client = connect(old.client.clone(), addr).await.unwrap();
        let old_server = old_server.await.unwrap();
        let wrapped = crate::connect_info::RustbgpdTcpStream::from_tls(old_server);
        let mut extensions = tonic::codegen::http::Extensions::new();
        extensions.insert(wrapped.connect_info());
        let context = crate::authz_runtime::GrpcAuthAuditContext::new(
            "tcp://127.0.0.1:0",
            "read_write",
            crate::authz::AuthTier::OperatorOnly,
            crate::authz_runtime::GrpcAuthnKind::Mtls,
            "mtls-unresolved",
        )
        .with_mtls_peer_principal();
        assert_eq!(context.principal_for_extensions(&extensions), "old");
        let mut old_server = wrapped;

        overwrite(&mut cert, new.server_pem.as_bytes());
        overwrite(&mut key, new.server_key_pem.as_bytes());
        overwrite(&mut ca, new.ca_pem.as_bytes());
        store.reload().unwrap();
        old_client.write_all(b"x").await.unwrap();
        let mut byte = [0];
        old_server.read_exact(&mut byte).await.unwrap();
        assert_eq!(byte, *b"x");

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let new_server_config = store.load().listener(0).tls.clone().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(new_server_config).accept(tcp).await
        });
        assert!(connect(old.client.clone(), addr).await.is_err());
        assert!(server.await.unwrap().is_err());

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let new_server_config = store.load().listener(0).tls.clone().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            TlsAcceptor::from(new_server_config)
                .accept(tcp)
                .await
                .unwrap()
        });
        let _new_client = connect(new.client, addr).await.unwrap();
        let _new_server = server.await.unwrap();
    }
}
