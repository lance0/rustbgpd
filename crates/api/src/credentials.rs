//! Atomic management-plane credential generations.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use prometheus::core::{Collector, Desc};
use prometheus::proto::MetricFamily;
use prometheus::{IntGaugeVec, Opts, Registry};
use tokio_rustls::rustls::pki_types::pem::PemObject;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio_rustls::rustls::server::WebPkiClientVerifier;
use tokio_rustls::rustls::{RootCertStore, ServerConfig};
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroizing;

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
    tls_expiry: Option<TlsExpiry>,
}

/// Raw certificate notAfter metadata, in signed Unix seconds. Bundle minima
/// include every supplied certificate; they are not effective path cutoffs.
/// A value is absent when metadata cannot be parsed, without changing rustls
/// credential acceptance. An incomplete bundle has no reported minimum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsExpiry {
    pub server_leaf: Option<i64>,
    pub server_bundle_min: Option<i64>,
    pub client_ca_bundle_min: Option<i64>,
}

impl TlsExpiry {
    pub fn values(self) -> impl Iterator<Item = (&'static str, i64)> {
        [
            ("server_leaf", self.server_leaf),
            ("server_bundle_min", self.server_bundle_min),
            ("client_ca_bundle_min", self.client_ca_bundle_min),
        ]
        .into_iter()
        .filter_map(|(kind, value)| value.map(|value| (kind, value)))
    }

    /// Available expiry values inside the opt-in warning window, using the
    /// current wall clock. This includes dates already in the past.
    pub fn warnings(self, warning_seconds: u32) -> impl Iterator<Item = (&'static str, i64)> {
        let now = x509_parser::time::ASN1Time::now().timestamp();
        self.values()
            .filter(move |(_, not_after)| tls_expiry_warning_due(*not_after, now, warning_seconds))
    }
}

/// Zero disables warnings, including for past dates. Signed subtraction keeps
/// expired certificates inside every positive warning window.
#[must_use]
pub fn tls_expiry_warning_due(not_after: i64, now: i64, warning_seconds: u32) -> bool {
    warning_seconds != 0 && not_after.saturating_sub(now) <= i64::from(warning_seconds)
}

pub(crate) fn certificate_not_after(cert: &CertificateDer<'_>) -> Option<i64> {
    X509Certificate::from_der(cert.as_ref())
        .ok()
        .map(|(_, certificate)| certificate.validity().not_after.timestamp())
}

struct TlsExpiryCollector {
    store: CredentialStore,
    listener: usize,
    desc: Desc,
}

const TLS_EXPIRY_METRIC: &str = "bgp_grpc_tls_certificate_not_after_seconds";
const TLS_EXPIRY_HELP: &str = "Active native gRPC TLS certificate notAfter in Unix seconds. Bundle minima cover supplied certificates, not effective peer path cutoffs.";

impl TlsExpiryCollector {
    fn new(store: CredentialStore, listener: usize) -> Result<Self, prometheus::Error> {
        Ok(Self {
            store,
            listener,
            desc: Desc::new(
                TLS_EXPIRY_METRIC.into(),
                TLS_EXPIRY_HELP.into(),
                vec!["kind".into()],
                std::collections::HashMap::new(),
            )?,
        })
    }
}

impl Collector for TlsExpiryCollector {
    fn desc(&self) -> Vec<&Desc> {
        vec![&self.desc]
    }

    fn collect(&self) -> Vec<MetricFamily> {
        let generation = self.store.load();
        let Some(expiry) = generation.tls_expiry(self.listener) else {
            return Vec::new();
        };
        let gauges = IntGaugeVec::new(
            Opts::new(
                "bgp_grpc_tls_certificate_not_after_seconds",
                "Active native gRPC TLS certificate notAfter in Unix seconds. Bundle minima cover supplied certificates, not effective peer path cutoffs.",
            ),
            &["kind"],
        )
        .expect("valid metric definition");
        for (kind, not_after) in expiry.values() {
            gauges.with_label_values(&[kind]).set(not_after);
        }
        gauges.collect()
    }
}

impl std::fmt::Debug for ListenerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ListenerCredentials")
            .field("bearer", &self.bearer.is_some())
            .field("tls", &self.tls.is_some())
            .field("tls_expiry", &self.tls_expiry)
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
    pub fn tls_expiry(&self, index: usize) -> Option<TlsExpiry> {
        self.listeners
            .get(index)
            .and_then(|listener| listener.tls_expiry)
    }

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
    /// Serializes [`Self::reload`]'s read-increment-publish so
    /// concurrent reloads can never mint duplicate sequences or
    /// publish out of order. Readers stay lock-free via `active`.
    reload_lock: Arc<Mutex<()>>,
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
    /// Register the single native TCP listener's active credential metadata.
    ///
    /// # Errors
    /// Returns a Prometheus registration error, including duplicate registration.
    pub fn register_tls_expiry_metrics(
        &self,
        registry: &Registry,
        listener: usize,
    ) -> Result<(), prometheus::Error> {
        registry.register(Box::new(TlsExpiryCollector::new(self.clone(), listener)?))
    }

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
            reload_lock: Arc::new(Mutex::new(())),
        })
    }

    #[must_use]
    pub fn load(&self) -> Arc<CredentialGeneration> {
        self.active.load_full()
    }

    /// Stage all configured files, then atomically publish one generation.
    ///
    /// Reloads are serialized: concurrent callers each publish a distinct,
    /// strictly increasing sequence (the SIGHUP path happens to serialize
    /// reloads already, but the store does not rely on that).
    ///
    /// # Errors
    /// Returns a redacted error when any listener fails staging. The active
    /// generation is left unchanged.
    pub fn reload(&self) -> Result<u64, String> {
        let _guard = self
            .reload_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
            // Zeroizing scrubs this transient read when it drops; the
            // retained copy inside `BearerAuthSecret` scrubs on its own drop.
            let raw = Zeroizing::new(fs::read_to_string(path).map_err(|e| {
                format!(
                    "listener {index}: failed to read token file {}: {e}",
                    path.display()
                )
            })?);
            let token = raw.trim_end();
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
    let (tls, tls_expiry) = match tls {
        Some((config, expiry)) => (Some(config), Some(expiry)),
        None => (None, None),
    };
    Ok(ListenerCredentials {
        bearer,
        tls,
        tls_expiry,
    })
}

/// Read a credential file into a buffer that is scrubbed on drop (the TLS
/// private key in particular must not linger in freed heap after parsing).
fn read_file(index: usize, label: &str, path: &Path) -> Result<Zeroizing<Vec<u8>>, String> {
    let bytes = Zeroizing::new(fs::read(path).map_err(|e| {
        format!(
            "listener {index}: failed to read {label} file {}: {e}",
            path.display()
        )
    })?);
    if bytes.is_empty() {
        return Err(format!(
            "listener {index}: {label} file {} is empty",
            path.display()
        ));
    }
    Ok(bytes)
}

fn build_tls(index: usize, source: &TlsSource) -> Result<(Arc<ServerConfig>, TlsExpiry), String> {
    let cert_bytes = read_file(index, "certificate", &source.cert_file)?;
    let key_bytes = read_file(index, "private key", &source.key_file)?;
    let ca_bytes = read_file(index, "client CA", &source.client_ca_file)?;
    let certs = CertificateDer::pem_slice_iter(&cert_bytes)
        .collect::<Result<Vec<CertificateDer<'static>>, _>>()
        .map_err(|e| format!("listener {index}: invalid certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err(format!(
            "listener {index}: certificate PEM contains no certificates"
        ));
    }
    let key = PrivateKeyDer::from_pem_slice(&key_bytes)
        .map_err(|e| format!("listener {index}: invalid private-key PEM: {e}"))?;
    let ca_certs = CertificateDer::pem_slice_iter(&ca_bytes)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| format!("listener {index}: invalid client-CA PEM: {e}"))?;
    // Metadata is observational. A parser difference must not reject TLS
    // material accepted by rustls. Never publish a partial bundle minimum.
    let bundle_min = |certs: &[CertificateDer<'_>]| {
        certs
            .iter()
            .map(certificate_not_after)
            .collect::<Option<Vec<_>>>()
            .and_then(|dates| dates.into_iter().min())
    };
    let tls_expiry = TlsExpiry {
        server_leaf: certificate_not_after(&certs[0]),
        server_bundle_min: bundle_min(&certs),
        client_ca_bundle_min: bundle_min(&ca_certs),
    };
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
    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| format!("listener {index}: certificate/private-key mismatch: {e}"))?;
    // tonic's `ServerTlsConfig` advertises HTTP/2 over ALPN; the manual
    // rustls config must do the same, or ALPN-strict gRPC clients
    // (grpc-go: gnmic, gobgp) refuse to negotiate h2 on the TLS session.
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((Arc::new(config), tls_expiry))
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

    fn dated_certificate(year: i32, ca: bool) -> (Certificate, KeyPair) {
        let mut params = CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(1960, 1, 1);
        params.not_after = rcgen::date_time_ymd(year, 1, 1);
        if ca {
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        }
        let key = KeyPair::generate().unwrap();
        (params.self_signed(&key).unwrap(), key)
    }

    #[allow(
        clippy::cast_possible_truncation,
        reason = "test fixtures use whole Unix seconds exactly representable by Prometheus doubles"
    )]
    fn expiry_metrics(registry: &Registry) -> std::collections::BTreeMap<String, i64> {
        registry
            .gather()
            .into_iter()
            .filter(|family| family.name() == TLS_EXPIRY_METRIC)
            .flat_map(|family| family.get_metric().to_vec())
            .map(|metric| {
                assert_eq!(metric.get_label().len(), 1);
                assert_eq!(metric.get_label()[0].name(), "kind");
                (
                    metric.get_label()[0].value().into(),
                    metric.get_gauge().value() as i64,
                )
            })
            .collect()
    }

    #[test]
    fn tls_expiry_warning_boundaries_are_signed_and_opt_in() {
        for not_after in [i64::MIN, -1, 0, 100, i64::MAX] {
            assert!(!tls_expiry_warning_due(not_after, 100, 0));
        }
        assert!(tls_expiry_warning_due(-1, 100, 10));
        assert!(tls_expiry_warning_due(100, 100, 10));
        assert!(tls_expiry_warning_due(110, 100, 10));
        assert!(!tls_expiry_warning_due(111, 100, 10));
        assert!(tls_expiry_warning_due(i64::MIN, i64::MAX, 1));
        assert!(!tls_expiry_warning_due(i64::MAX, i64::MIN, u32::MAX));
    }

    #[test]
    fn tls_expiry_metrics_are_absent_without_tls() {
        let store = CredentialStore::stage(vec![CredentialSource::default()]).unwrap();
        let registry = Registry::new();
        store.register_tls_expiry_metrics(&registry, 0).unwrap();
        assert!(registry.gather().is_empty());
        assert_eq!(store.load().tls_expiry(0), None);
    }

    #[test]
    fn tls_expiry_unparseable_extra_chain_preserves_tls_acceptance() {
        let bundle = tls_bundle("observational metadata");
        let cert = token_file(&format!(
            "{}-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n",
            bundle.server_pem
        ));
        let key = token_file(&bundle.server_key_pem);
        let ca = token_file(&bundle.ca_pem);
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: None,
            tls: Some(TlsSource {
                cert_file: cert.path().into(),
                key_file: key.path().into(),
                client_ca_file: ca.path().into(),
            }),
        }])
        .unwrap();
        assert!(store.load().listener(0).tls.is_some());
        let expiry = store.load().tls_expiry(0).unwrap();
        assert!(expiry.server_leaf.is_some());
        assert_eq!(expiry.server_bundle_min, None);
        assert!(expiry.client_ca_bundle_min.is_some());
        let registry = Registry::new();
        store.register_tls_expiry_metrics(&registry, 0).unwrap();
        assert_eq!(expiry_metrics(&registry).len(), 2);
    }

    #[test]
    fn tls_expiry_metrics_follow_atomic_generation_and_ignore_old_snapshots() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (leaf, key) = dated_certificate(2032, false);
        let (chain, _) = dated_certificate(2029, true);
        let (ca, _) = dated_certificate(2030, true);
        let (other_ca, _) = dated_certificate(2031, true);
        let mut cert_file = token_file(&format!("{}{}", leaf.pem(), chain.pem()));
        let mut key_file = token_file(&key.serialize_pem());
        let mut ca_file = token_file(&format!("{}{}", other_ca.pem(), ca.pem()));
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: None,
            tls: Some(TlsSource {
                cert_file: cert_file.path().into(),
                key_file: key_file.path().into(),
                client_ca_file: ca_file.path().into(),
            }),
        }])
        .unwrap();
        let old = store.load();
        let expected = TlsExpiry {
            server_leaf: Some(rcgen::date_time_ymd(2032, 1, 1).unix_timestamp()),
            server_bundle_min: Some(rcgen::date_time_ymd(2029, 1, 1).unix_timestamp()),
            client_ca_bundle_min: Some(rcgen::date_time_ymd(2030, 1, 1).unix_timestamp()),
        };
        assert_eq!(old.tls_expiry(0), Some(expected));
        let registry = Registry::new();
        store.register_tls_expiry_metrics(&registry, 0).unwrap();
        let old_metrics = expiry_metrics(&registry);
        assert_eq!(
            old_metrics,
            expected.values().map(|(k, v)| (k.into(), v)).collect()
        );

        // File edits cannot alter a scrape before staging succeeds. An expired
        // certificate remains observable without imposing a new startup policy.
        let (new_leaf, new_key) = dated_certificate(1965, false);
        let (new_ca, _) = dated_certificate(2040, true);
        overwrite(&mut cert_file, new_leaf.pem().as_bytes());
        overwrite(&mut ca_file, new_ca.pem().as_bytes());
        assert!(store.reload().is_err()); // The old private key does not match.
        assert_eq!(store.load().sequence(), 1);
        assert_eq!(expiry_metrics(&registry), old_metrics);
        overwrite(&mut key_file, new_key.serialize_pem().as_bytes());
        assert_eq!(expiry_metrics(&registry), old_metrics);
        assert_eq!(store.reload().unwrap(), 2);
        let new_expiry = store.load().tls_expiry(0).unwrap();
        assert_eq!(
            new_expiry.server_leaf,
            Some(rcgen::date_time_ymd(1965, 1, 1).unix_timestamp())
        );
        assert_eq!(new_expiry.server_bundle_min, new_expiry.server_leaf);
        assert_eq!(
            new_expiry.client_ca_bundle_min,
            Some(rcgen::date_time_ymd(2040, 1, 1).unix_timestamp())
        );
        assert_eq!(new_expiry.warnings(0).count(), 0);
        assert!(
            new_expiry
                .warnings(1)
                .any(|(kind, _)| kind == "server_leaf")
        );
        assert_eq!(
            expiry_metrics(&registry),
            new_expiry.values().map(|(k, v)| (k.into(), v)).collect()
        );
        assert_eq!(old.tls_expiry(0), Some(expected));
        drop(old);
        assert_eq!(
            expiry_metrics(&registry)["server_leaf"],
            new_expiry.server_leaf.unwrap()
        );
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

    #[test]
    fn concurrent_reloads_publish_unique_increasing_sequences() {
        const THREADS: usize = 8;
        const RELOADS: usize = 25;
        let token = token_file("tok");
        let store = CredentialStore::stage(vec![CredentialSource {
            token_file: Some(token.path().to_path_buf()),
            tls: None,
        }])
        .unwrap();

        let barrier = Arc::new(Barrier::new(THREADS));
        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let store = store.clone();
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    (0..RELOADS)
                        .map(|_| store.reload().unwrap())
                        .collect::<Vec<u64>>()
                })
            })
            .collect();
        let mut sequences: Vec<u64> = handles
            .into_iter()
            .flat_map(|handle| handle.join().unwrap())
            .collect();
        sequences.sort_unstable();
        // Serialized reloads mint every sequence exactly once: the initial
        // generation is 1, so the published set is exactly 2..=total+1.
        let total = u64::try_from(THREADS * RELOADS).unwrap();
        let expected: Vec<u64> = (2..=total + 1).collect();
        assert_eq!(sequences, expected);
        assert_eq!(store.load().sequence(), total + 1);
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
        assert_eq!(old_server_config.alpn_protocols, vec![b"h2".to_vec()]);
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
