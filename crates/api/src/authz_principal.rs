//! ADR-0064 authenticated-principal extraction helpers.
//!
//! Native gRPC mTLS validates the client certificate at the tonic/rustls
//! boundary. This module only derives the stable audit/authorization
//! principal string from the already-validated peer certificate.

use thiserror::Error;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

const RUSTBGPD_URI_SCHEME: &str = "rustbgpd";
const MAX_PRINCIPAL_LEN: usize = 256;

#[derive(Debug, Error, Eq, PartialEq)]
pub enum PrincipalExtractionError {
    #[error("mTLS peer certificate chain is empty")]
    MissingPeerCertificate,
    #[error("failed to parse mTLS peer certificate: {0}")]
    InvalidCertificate(String),
    #[error("mTLS peer certificate has no rustbgpd URI SAN, email SAN, or Subject CN principal")]
    MissingPrincipal,
    #[error("mTLS peer certificate principal is too long or contains embedded control characters")]
    UnsafePrincipal,
}

/// Extract the ADR-0064 principal from the first peer certificate in
/// a validated mTLS chain.
///
/// Priority order is URI SAN with `rustbgpd` scheme, then email SAN,
/// then Subject Common Name. The full URI SAN string is used as the
/// principal so role-map entries can distinguish URI namespaces. Unsafe
/// candidate values are skipped so a malformed higher-priority name cannot
/// mask a later safe principal.
///
/// # Errors
///
/// Returns [`PrincipalExtractionError::MissingPeerCertificate`] when
/// the chain is empty, or propagates the first certificate's extraction
/// error from [`principal_from_der`].
pub fn principal_from_peer_certs<C>(certs: &[C]) -> Result<String, PrincipalExtractionError>
where
    C: AsRef<[u8]>,
{
    let Some(first) = certs.first() else {
        return Err(PrincipalExtractionError::MissingPeerCertificate);
    };
    principal_from_der(first.as_ref())
}

/// Extract the ADR-0064 principal from one DER-encoded X.509 certificate.
///
/// # Errors
///
/// Returns [`PrincipalExtractionError::InvalidCertificate`] when the
/// DER cannot be parsed as X.509, or
/// [`PrincipalExtractionError::MissingPrincipal`] when no supported
/// principal field is present. Returns
/// [`PrincipalExtractionError::UnsafePrincipal`] when supported principal
/// fields exist but none are safe to log or match.
pub fn principal_from_der(der: &[u8]) -> Result<String, PrincipalExtractionError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|err| PrincipalExtractionError::InvalidCertificate(err.to_string()))?;
    let san = cert
        .subject_alternative_name()
        .map_err(|err| PrincipalExtractionError::InvalidCertificate(err.to_string()))?;
    let mut tracker = PrincipalScan::default();

    if let Some(san) = san.as_ref() {
        if let Some(principal) = rustbgpd_uri_san(&san.value.general_names, &mut tracker) {
            return Ok(principal);
        }
        if let Some(principal) = email_san(&san.value.general_names, &mut tracker) {
            return Ok(principal);
        }
    }
    if let Some(principal) = subject_common_name(&cert, &mut tracker)? {
        return Ok(principal);
    }
    if tracker.unsafe_candidate {
        return Err(PrincipalExtractionError::UnsafePrincipal);
    }
    Err(PrincipalExtractionError::MissingPrincipal)
}

#[derive(Default)]
struct PrincipalScan {
    unsafe_candidate: bool,
}

fn rustbgpd_uri_san(names: &[GeneralName<'_>], scan: &mut PrincipalScan) -> Option<String> {
    for name in names {
        let candidate = match name {
            GeneralName::URI(uri)
                if uri_scheme(uri).is_some_and(|scheme| scheme == RUSTBGPD_URI_SCHEME) =>
            {
                Some(*uri)
            }
            _ => None,
        };
        if let Some(principal) = sanitize_principal(candidate, scan) {
            return Some(principal);
        }
    }
    None
}

fn email_san(names: &[GeneralName<'_>], scan: &mut PrincipalScan) -> Option<String> {
    for name in names {
        if let GeneralName::RFC822Name(email) = name
            && let Some(principal) = sanitize_principal(Some(*email), scan)
        {
            return Some(principal);
        }
    }
    None
}

fn subject_common_name(
    cert: &X509Certificate<'_>,
    scan: &mut PrincipalScan,
) -> Result<Option<String>, PrincipalExtractionError> {
    for cn in cert.subject().iter_common_name() {
        let cn = cn
            .as_str()
            .map_err(|err| PrincipalExtractionError::InvalidCertificate(err.to_string()))?;
        if let Some(principal) = sanitize_principal(Some(cn), scan) {
            return Ok(Some(principal));
        }
    }
    Ok(None)
}

fn uri_scheme(uri: &str) -> Option<&str> {
    uri.split_once(':').map(|(scheme, _)| scheme)
}

fn sanitize_principal(value: Option<&str>, scan: &mut PrincipalScan) -> Option<String> {
    let value = value?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.len() > MAX_PRINCIPAL_LEN || trimmed.chars().any(char::is_control) {
        scan.unsafe_candidate = true;
        return None;
    }
    Some(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use rcgen::{CertificateParams, DnType, KeyPair, SanType};

    use super::*;

    fn cert_der(mut params: CertificateParams) -> Vec<u8> {
        let key = KeyPair::generate().unwrap();
        params
            .distinguished_name
            .push(DnType::OrganizationName, "rustbgpd test");
        params.self_signed(&key).unwrap().der().to_vec()
    }

    fn cert_with_sans(sans: Vec<SanType>, cn: &str) -> Vec<u8> {
        let mut params = CertificateParams::default();
        params.subject_alt_names = sans;
        params.distinguished_name.push(DnType::CommonName, cn);
        cert_der(params)
    }

    #[test]
    fn principal_prefers_rustbgpd_uri_san() {
        let der = cert_with_sans(
            vec![
                SanType::URI("spiffe://example/ignored".try_into().unwrap()),
                SanType::URI("rustbgpd://operator/alice".try_into().unwrap()),
                SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
            ],
            "alice-cn",
        );

        assert_eq!(
            principal_from_der(&der).unwrap(),
            "rustbgpd://operator/alice"
        );
    }

    #[test]
    fn principal_uses_email_san_before_cn() {
        let der = cert_with_sans(
            vec![
                SanType::URI("spiffe://example/ignored".try_into().unwrap()),
                SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
            ],
            "alice-cn",
        );

        assert_eq!(principal_from_der(&der).unwrap(), "alice@example.com");
    }

    #[test]
    fn principal_skips_unsafe_uri_san_for_safe_email_san() {
        let unsafe_uri = format!("rustbgpd://{}", "a".repeat(MAX_PRINCIPAL_LEN + 1));
        let der = cert_with_sans(
            vec![
                SanType::URI(unsafe_uri.try_into().unwrap()),
                SanType::Rfc822Name("alice@example.com".try_into().unwrap()),
            ],
            "alice-cn",
        );

        assert_eq!(principal_from_der(&der).unwrap(), "alice@example.com");
    }

    #[test]
    fn principal_skips_unsafe_email_san_for_safe_cn() {
        let unsafe_email = format!("{}@example.com", "a".repeat(MAX_PRINCIPAL_LEN + 1));
        let der = cert_with_sans(
            vec![SanType::Rfc822Name(unsafe_email.try_into().unwrap())],
            "alice-cn",
        );

        assert_eq!(principal_from_der(&der).unwrap(), "alice-cn");
    }

    #[test]
    fn principal_uses_subject_cn_when_sans_absent() {
        let der = cert_with_sans(Vec::new(), "alice-cn");

        assert_eq!(principal_from_der(&der).unwrap(), "alice-cn");
    }

    #[test]
    fn principal_reports_missing_when_no_supported_name_exists() {
        let mut params = CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        let der = cert_der(params);

        assert_eq!(
            principal_from_der(&der).unwrap_err(),
            PrincipalExtractionError::MissingPrincipal
        );
    }

    #[test]
    fn principal_rejects_control_character_cn() {
        let der = cert_with_sans(Vec::new(), "alice\noperator");

        assert_eq!(
            principal_from_der(&der).unwrap_err(),
            PrincipalExtractionError::UnsafePrincipal
        );
    }

    #[test]
    fn principal_rejects_overlong_cn() {
        let der = cert_with_sans(Vec::new(), &"a".repeat(MAX_PRINCIPAL_LEN + 1));

        assert_eq!(
            principal_from_der(&der).unwrap_err(),
            PrincipalExtractionError::UnsafePrincipal
        );
    }

    #[test]
    fn principal_reports_empty_peer_chain() {
        let certs: Vec<Vec<u8>> = Vec::new();

        assert_eq!(
            principal_from_peer_certs(&certs).unwrap_err(),
            PrincipalExtractionError::MissingPeerCertificate
        );
    }
}
