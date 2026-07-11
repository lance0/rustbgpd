use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use tonic::Status;
use tonic::codegen::http;
use tonic::transport::server::{TcpConnectInfo, TlsConnectInfo};
use tracing::debug;

use crate::authz::{AuthEnforcement, AuthTier, PrincipalRole};
use crate::authz_principal::{PrincipalExtractionError, principal_from_peer_certs};
use crate::connect_info::RustbgpdTcpConnectInfo;
use crate::credentials::{CredentialStore, PinnedCredentialGeneration};

use super::decision::RoleDenial;

/// Bounded set of listener authentication surfaces for audit labels.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrpcAuthnKind {
    /// TCP listener with mTLS enabled.
    Mtls,
    /// Listener protected by the existing bearer-token interceptor.
    BearerToken,
    /// Unix domain socket protected by filesystem permissions.
    Uds,
    /// No listener authentication configured.
    None,
}

impl GrpcAuthnKind {
    /// Stable metrics/log label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mtls => "mtls",
            Self::BearerToken => "bearer_token",
            Self::Uds => "uds",
            Self::None => "none",
        }
    }
}

/// Per-listener audit context attached to every runtime decision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpcAuthAuditContext {
    pub(super) listener: String,
    pub(super) access_mode: &'static str,
    pub(super) max_tier: AuthTier,
    pub(super) authn: GrpcAuthnKind,
    principal: String,
    pub(super) enforcement: AuthEnforcement,
    roles: Arc<BTreeMap<String, PrincipalRole>>,
    resolve_mtls_principal: bool,
    expected_bearer_header: Option<BearerAuthSecret>,
    dynamic_bearer: Option<(CredentialStore, usize)>,
}

impl GrpcAuthAuditContext {
    /// Build a context for a single resolved listener.
    #[must_use]
    pub fn new(
        listener: impl Into<String>,
        access_mode: &'static str,
        max_tier: AuthTier,
        authn: GrpcAuthnKind,
        principal: impl Into<String>,
    ) -> Self {
        Self {
            listener: listener.into(),
            access_mode,
            max_tier,
            authn,
            principal: principal.into(),
            enforcement: AuthEnforcement::Legacy,
            roles: Arc::new(BTreeMap::new()),
            resolve_mtls_principal: false,
            expected_bearer_header: None,
            dynamic_bearer: None,
        }
    }

    /// Attach the global ADR-0064 enforcement mode and principal-role map.
    #[must_use]
    pub fn with_role_enforcement(
        mut self,
        enforcement: AuthEnforcement,
        roles: Arc<BTreeMap<String, PrincipalRole>>,
    ) -> Self {
        self.enforcement = enforcement;
        self.roles = roles;
        self
    }

    /// Mark this context as an mTLS listener whose per-request
    /// principal should be derived from the peer certificate.
    #[must_use]
    pub fn with_mtls_peer_principal(mut self) -> Self {
        self.resolve_mtls_principal = true;
        self
    }

    #[must_use]
    pub fn with_bearer_token(mut self, token: Option<&str>) -> Self {
        self.expected_bearer_header = token.map(BearerAuthSecret::from_token);
        self
    }

    #[must_use]
    pub fn with_dynamic_bearer(mut self, store: CredentialStore, listener: usize) -> Self {
        self.dynamic_bearer = Some((store, listener));
        self
    }

    #[cfg(test)]
    pub(crate) fn authn(&self) -> GrpcAuthnKind {
        self.authn
    }

    #[cfg(test)]
    pub(crate) fn principal(&self) -> &str {
        &self.principal
    }

    #[cfg(test)]
    pub(crate) fn max_tier(&self) -> AuthTier {
        self.max_tier
    }

    pub(super) fn pin_credentials(&self, extensions: &mut http::Extensions) {
        if let Some((store, listener)) = &self.dynamic_bearer {
            extensions.insert(PinnedCredentialGeneration::new(store.load(), *listener));
        }
    }

    pub(super) fn bearer_auth_error(
        &self,
        headers: &http::HeaderMap,
        extensions: &http::Extensions,
    ) -> Option<Status> {
        if let Some(pinned) = extensions.get::<PinnedCredentialGeneration>() {
            return pinned
                .bearer()
                .and_then(|expected| expected.auth_error_from_http_headers(headers));
        }
        if let Some((store, listener)) = &self.dynamic_bearer {
            let generation = store.load();
            return generation
                .listener(*listener)
                .bearer
                .as_ref()
                .and_then(|expected| expected.auth_error_from_http_headers(headers));
        }
        let expected = self.expected_bearer_header.as_ref()?;
        expected.auth_error_from_http_headers(headers)
    }

    pub(super) fn role_denial(&self, principal: &str, tier: AuthTier) -> Option<RoleDenial> {
        if self.enforcement != AuthEnforcement::Tier {
            return None;
        }
        let Some(role) = self.roles.get(principal).copied() else {
            return Some(RoleDenial::PrincipalUnmapped);
        };
        if tier > role.max_tier() {
            return Some(RoleDenial::RoleTierDenied { role });
        }
        None
    }

    pub(super) fn role_label(&self, principal: &str) -> &'static str {
        if self.enforcement != AuthEnforcement::Tier {
            return "legacy";
        }
        self.roles
            .get(principal)
            .map_or("unmapped", |role| role.as_str())
    }

    pub(super) fn principal_for_extensions<'a>(
        &'a self,
        extensions: &http::Extensions,
    ) -> Cow<'a, str> {
        if !self.resolve_mtls_principal {
            return Cow::Borrowed(self.principal.as_str());
        }
        match mtls_principal_from_extensions(extensions) {
            Ok(principal) => Cow::Owned(principal),
            Err(error) => {
                debug!(
                    target: "grpc_authz",
                    error = %error,
                    fallback = %self.principal,
                    "failed to extract mTLS peer principal for gRPC audit"
                );
                Cow::Borrowed(self.principal.as_str())
            }
        }
    }
}

fn mtls_principal_from_extensions(
    extensions: &http::Extensions,
) -> Result<String, PrincipalExtractionError> {
    if let Some(info) = extensions.get::<RustbgpdTcpConnectInfo>() {
        let certs = info
            .peer_certs()
            .ok_or(PrincipalExtractionError::MissingPeerCertificate)?;
        return info
            .mtls_principal(certs)
            .map(|principal| principal.to_string());
    }
    if let Some(connect_info) = extensions.get::<TlsConnectInfo<RustbgpdTcpConnectInfo>>() {
        let certs = connect_info
            .peer_certs()
            .ok_or(PrincipalExtractionError::MissingPeerCertificate)?;
        return connect_info
            .get_ref()
            .mtls_principal(certs.as_ref())
            .map(|principal| principal.to_string());
    }
    let certs = extensions
        .get::<TlsConnectInfo<TcpConnectInfo>>()
        .and_then(TlsConnectInfo::peer_certs)
        .ok_or(PrincipalExtractionError::MissingPeerCertificate)?;
    principal_from_peer_certs(certs.as_ref())
}

/// Redacted bearer-token verifier shared by the audit layer and tonic interceptor.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct BearerAuthSecret {
    expected_header: Arc<String>,
}

impl BearerAuthSecret {
    pub(crate) fn from_token(token: &str) -> Self {
        Self {
            expected_header: Arc::new(format!("Bearer {token}")),
        }
    }

    pub(crate) fn authenticate_metadata(
        &self,
        metadata: &tonic::metadata::MetadataMap,
    ) -> Result<(), Status> {
        let value = metadata
            .get("authorization")
            .ok_or_else(|| Status::unauthenticated("missing authorization metadata"))?;
        let actual = value
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be ASCII"))?;
        self.authenticate_str(actual)
    }

    fn auth_error_from_http_headers(&self, headers: &http::HeaderMap) -> Option<Status> {
        let Some(value) = headers.get("authorization") else {
            return Some(Status::unauthenticated("missing authorization metadata"));
        };
        let actual = value
            .to_str()
            .map_err(|_| Status::unauthenticated("authorization metadata must be ASCII"))
            .and_then(|actual| self.authenticate_str(actual));
        actual.err()
    }

    fn authenticate_str(&self, actual: &str) -> Result<(), Status> {
        if constant_time_eq(actual.as_bytes(), self.expected_header.as_bytes()) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid bearer token"))
        }
    }
}

impl fmt::Debug for BearerAuthSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BearerAuthSecret(<redacted>)")
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let max_len = a.len().max(b.len());
    let mut diff = a.len() ^ b.len();
    for idx in 0..max_len {
        let lhs = a.get(idx).copied().unwrap_or(0);
        let rhs = b.get(idx).copied().unwrap_or(0);
        diff |= usize::from(lhs ^ rhs);
    }
    diff == 0
}
