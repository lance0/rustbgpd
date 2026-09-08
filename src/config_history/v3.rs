//! Canonical, bounded audit metadata. No rollback payload or source roster.

use super::v2::hex_digest;
use serde::{Deserialize, Serialize};
use std::io;

pub(super) const MAX_ENVELOPE: usize = 64 * 1024;
pub(super) const MAX_SUMMARY: usize = 4 * 1024;
pub(super) const REASON: &str = "normalized_toml_exceeds_v2_payload_limit";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Envelope {
    pub(crate) version: u32,
    pub(crate) sequence: u64,
    pub(crate) timestamp_unix_seconds: u64,
    pub(crate) normalized_toml_bytes: u64,
    #[serde(with = "hex_digest")]
    pub(crate) sha256: [u8; 32],
    #[serde(with = "hex_digest")]
    pub(crate) source_sha256: [u8; 32],
    pub(crate) summary: String,
    pub(crate) metadata_only_reason: String,
}

pub(super) fn from_snapshot(
    snapshot: &crate::config::AcceptedConfigSnapshot,
) -> io::Result<Envelope> {
    let config = snapshot.config_ref();
    // Parse the already validated identity to its bounded numeric type rather
    // than formatting a caller-owned string or cloning the accepted config.
    let router_id: std::net::Ipv4Addr = config.global.router_id.parse().map_err(invalid)?;
    let summary = format!(
        "asn {}, router-id {router_id}, {} neighbor(s), {} dynamic range(s), {} fib table(s), {} policy definition(s)",
        config.global.asn,
        config.neighbors.len(),
        config.dynamic_neighbors.len(),
        config.fib_tables.len(),
        config.policy.definitions.len(),
    );
    let envelope = Envelope {
        version: 3,
        sequence: 0,
        timestamp_unix_seconds: 0,
        normalized_toml_bytes: snapshot.normalized_toml().len() as u64,
        sha256: snapshot.source_manifest().toml_sha256,
        source_sha256: snapshot.source_sha256(),
        summary,
        metadata_only_reason: REASON.to_string(),
    };
    validate(&envelope)?;
    Ok(envelope)
}

fn validate(envelope: &Envelope) -> io::Result<()> {
    if envelope.version != 3
        || envelope.normalized_toml_bytes <= super::v2::MAX_TOML as u64
        || envelope.metadata_only_reason != REASON
    {
        return Err(invalid("invalid metadata-only config history envelope"));
    }
    validate_summary(&envelope.summary)?;
    Ok(())
}

// The retained summary is an output trust boundary too. Canonical JSON alone
// must not turn arbitrary owner-written paths, descriptions or config excerpts
// into a verified redacted API summary.
fn validate_summary(summary: &str) -> io::Result<()> {
    if summary.len() > MAX_SUMMARY {
        return Err(invalid("metadata-only summary exceeds 4096 bytes"));
    }
    let bad = || invalid("invalid redacted metadata-only summary");
    let mut fields = summary.split(", ");
    let asn = fields
        .next()
        .and_then(|field| field.strip_prefix("asn "))
        .ok_or_else(bad)?;
    let parsed_asn: u32 = asn.parse().map_err(|_| bad())?;
    if parsed_asn == 0 || parsed_asn.to_string() != asn {
        return Err(bad());
    }
    let router = fields
        .next()
        .and_then(|field| field.strip_prefix("router-id "))
        .ok_or_else(bad)?;
    let parsed_router: std::net::Ipv4Addr = router.parse().map_err(|_| bad())?;
    if parsed_router.to_string() != router {
        return Err(bad());
    }
    for suffix in [
        " neighbor(s)",
        " dynamic range(s)",
        " fib table(s)",
        " policy definition(s)",
    ] {
        let count = fields
            .next()
            .and_then(|field| field.strip_suffix(suffix))
            .ok_or_else(bad)?;
        let parsed: u64 = count.parse().map_err(|_| bad())?;
        if parsed.to_string() != count {
            return Err(bad());
        }
    }
    if fields.next().is_some() {
        return Err(bad());
    }
    Ok(())
}

pub(super) fn encode_envelope(envelope: &Envelope) -> io::Result<Vec<u8>> {
    validate(envelope)?;
    let mut bytes = serde_json::to_vec(envelope).map_err(invalid)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ENVELOPE {
        return Err(invalid("metadata-only envelope exceeds 65536 bytes"));
    }
    Ok(bytes)
}

pub(super) fn decode_envelope(bytes: &[u8]) -> io::Result<Envelope> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(invalid("metadata-only envelope exceeds 65536 bytes"));
    }
    let envelope = serde_json::from_slice(bytes).map_err(invalid)?;
    if encode_envelope(&envelope)? != bytes {
        return Err(invalid("non-canonical metadata-only envelope"));
    }
    Ok(envelope)
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        Envelope {
            version: 3, sequence: 7, timestamp_unix_seconds: 9,
            normalized_toml_bytes: super::super::v2::MAX_TOML as u64 + 1,
            sha256: [0x11; 32], source_sha256: [0x22; 32],
            summary: "asn 65001, router-id 192.0.2.1, 0 neighbor(s), 0 dynamic range(s), 0 fib table(s), 0 policy definition(s)".into(),
            metadata_only_reason: REASON.into(),
        }
    }

    #[test]
    fn canonical_metadata_rejects_unknown_duplicate_bad_identity_and_unbounded_text() {
        let row = sample();
        let bytes = encode_envelope(&row).unwrap();
        assert_eq!(decode_envelope(&bytes).unwrap(), row);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("{\"version\":3,\"sequence\":7,\"timestamp_unix_seconds\":9,\"normalized_toml_bytes\":10485761,\"sha256\":"));
        for broken in [
            format!(" {text}"),
            text.trim_end().to_string(),
            text.replacen('{', "{\"extra\":0,", 1),
            text.replacen('{', "{\"version\":3,", 1),
            text.replace("\"version\":3", "\"version\":2"),
            text.replace("10485761", "10485760"),
            text.replace(REASON, "unknown"),
            text.replace(&"11".repeat(32), &"AA".repeat(32)),
            text.replace(&"11".repeat(32), &"11".repeat(31)),
            text.replace("asn 65001", "asn\\n65001"),
        ] {
            assert!(decode_envelope(broken.as_bytes()).is_err(), "{broken}");
        }
        let mut row = sample();
        row.summary = "é".repeat(MAX_SUMMARY / 2);
        assert!(
            !encode_envelope(&row)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        row.summary.push('x');
        assert!(
            encode_envelope(&row)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        for summary in [
            "/secret/config.toml",
            "password = secret",
            "description: private",
            "asn 1, router-id 10.0.0.1, 00 neighbor(s), 0 dynamic range(s), 0 fib table(s), 0 policy definition(s)",
        ] {
            let mut row = sample();
            row.summary = summary.into();
            let mut bytes = serde_json::to_vec(&row).unwrap();
            bytes.push(b'\n');
            assert!(decode_envelope(&bytes).is_err());
        }
        // 64 KiB gets as far as JSON validation; +1 is refused before parsing.
        assert!(
            !decode_envelope(&vec![b' '; MAX_ENVELOPE])
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert!(
            decode_envelope(&vec![b' '; MAX_ENVELOPE + 1])
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
    }
}
