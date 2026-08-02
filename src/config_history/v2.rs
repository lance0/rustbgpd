//! Dormant, bounded ADR-0121 v2 history-envelope wire codec.

#![allow(
    dead_code,
    reason = "ADR-0121 tranche 2 deliberately lands the codec before filesystem wiring"
)]

use std::io;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const VERSION: u32 = 2;
const MAX_ENVELOPE: usize = 32 * 1024 * 1024;
const MAX_TOML: usize = 10 * 1024 * 1024;
const MAX_MANIFEST: usize = 16 * 1024 * 1024;
const MAX_UNITS: usize = 4096;
const MAX_MODULES: usize = 64;
const MAX_IMPORTS: usize = 4096;
const MAX_DATASETS: usize = 65_536;
const MAX_TEXT: usize = 64 * 1024;
const SOURCE_DIGEST_DOMAIN: &[u8] = b"rustbgpd.config-source.v2\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    pub(super) version: u32,
    pub(super) sequence: u64,
    pub(super) timestamp_unix_seconds: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
    #[serde(with = "hex_digest")]
    pub(super) source_sha256: [u8; 32],
    pub(super) normalized_toml: String,
    pub(super) manifest: Manifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    #[serde(with = "hex_digest")]
    pub(super) toml_sha256: [u8; 32],
    pub(super) rpol_units: Vec<RpolUnit>,
    pub(super) datasets: Vec<Dataset>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpolUnit {
    pub(super) modules: Vec<RpolModule>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RpolModule {
    pub(super) path: LosslessPath,
    pub(super) length: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
    pub(super) imports: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Dataset {
    pub(super) name: String,
    pub(super) kind: DatasetKind,
    pub(super) path: LosslessPath,
    pub(super) length: u64,
    #[serde(with = "hex_digest")]
    pub(super) sha256: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(super) enum DatasetKind {
    #[serde(rename = "prefix-set")]
    Prefix,
    #[serde(rename = "asn-set")]
    Asn,
    #[serde(rename = "community-set")]
    Community,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LosslessPath(pub(super) Vec<u8>);

impl Serialize for LosslessPath {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Wire<'a> {
            encoding: &'static str,
            value: &'a str,
        }
        let value = encode_hex(&self.0);
        Wire {
            encoding: "unix-bytes-hex",
            value: &value,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LosslessPath {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            encoding: String,
            value: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.encoding != "unix-bytes-hex" {
            return Err(serde::de::Error::custom("unsupported path encoding"));
        }
        decode_hex(&wire.value)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

pub(super) fn encode_envelope(envelope: &Envelope) -> io::Result<Vec<u8>> {
    validate(envelope)?;
    let mut bytes = serde_json::to_vec(envelope).map_err(invalid)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_ENVELOPE {
        return Err(limit("envelope", MAX_ENVELOPE));
    }
    Ok(bytes)
}

pub(super) fn decode_envelope(bytes: &[u8]) -> io::Result<Envelope> {
    if bytes.len() > MAX_ENVELOPE {
        return Err(limit("envelope", MAX_ENVELOPE));
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(invalid)?;
    validate(&envelope)?;
    if encode_envelope(&envelope)? != bytes {
        return Err(invalid("non-canonical v2 envelope"));
    }
    Ok(envelope)
}

fn validate(envelope: &Envelope) -> io::Result<()> {
    if envelope.version != VERSION {
        return Err(invalid("unsupported config-history envelope version"));
    }
    if envelope.normalized_toml.len() > MAX_TOML {
        return Err(limit("normalized TOML", MAX_TOML));
    }
    let actual_toml: [u8; 32] = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
    if envelope.sha256 != actual_toml || envelope.manifest.toml_sha256 != actual_toml {
        return Err(invalid("normalized TOML digest mismatch"));
    }
    validate_manifest(&envelope.manifest)?;
    if envelope.source_sha256 != manifest_source_sha256(&envelope.manifest) {
        return Err(invalid("source manifest digest mismatch"));
    }
    Ok(())
}

fn validate_manifest(manifest: &Manifest) -> io::Result<()> {
    if manifest.rpol_units.len() > MAX_UNITS {
        return Err(limit("RPOL units", MAX_UNITS));
    }
    for unit in &manifest.rpol_units {
        if unit.modules.is_empty() || unit.modules.len() > MAX_MODULES {
            return Err(invalid("RPOL unit must contain 1..=64 modules"));
        }
        for module in &unit.modules {
            if module.path.0.len() > MAX_TEXT || module.imports.len() > MAX_IMPORTS {
                return Err(invalid("RPOL module exceeds a codec bound"));
            }
            if module
                .imports
                .iter()
                .any(|&index| index as usize >= unit.modules.len())
            {
                return Err(invalid("RPOL import index is outside its unit"));
            }
        }
    }
    if manifest.datasets.len() > MAX_DATASETS {
        return Err(limit("datasets", MAX_DATASETS));
    }
    let mut prior: Option<&[u8]> = None;
    for dataset in &manifest.datasets {
        if dataset.name.len() > MAX_TEXT || dataset.path.0.len() > MAX_TEXT {
            return Err(invalid("dataset name or path exceeds 64 KiB"));
        }
        if prior.is_some_and(|name| name >= dataset.name.as_bytes()) {
            return Err(invalid("datasets are not strictly byte-sorted and unique"));
        }
        prior = Some(dataset.name.as_bytes());
    }
    if serde_json::to_vec(manifest).map_err(invalid)?.len() > MAX_MANIFEST {
        return Err(limit("manifest", MAX_MANIFEST));
    }
    Ok(())
}

fn manifest_source_sha256(manifest: &Manifest) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(SOURCE_DIGEST_DOMAIN);
    frame(&mut digest, &manifest.toml_sha256);
    frame_u64(&mut digest, manifest.rpol_units.len() as u64);
    for unit in &manifest.rpol_units {
        frame_u64(&mut digest, unit.modules.len() as u64);
        for module in &unit.modules {
            frame(&mut digest, b"unix-os-bytes");
            frame(&mut digest, &module.path.0);
            frame_u64(&mut digest, module.length);
            frame(&mut digest, &module.sha256);
            frame_u64(&mut digest, module.imports.len() as u64);
            for import in &module.imports {
                frame(&mut digest, &import.to_be_bytes());
            }
        }
    }
    frame_u64(&mut digest, manifest.datasets.len() as u64);
    for dataset in &manifest.datasets {
        frame(&mut digest, dataset.name.as_bytes());
        frame(&mut digest, dataset_kind_name(dataset.kind).as_bytes());
        frame(&mut digest, b"unix-os-bytes");
        frame(&mut digest, &dataset.path.0);
        frame_u64(&mut digest, dataset.length);
        frame(&mut digest, &dataset.sha256);
    }
    digest.finalize().into()
}

fn frame(digest: &mut Sha256, bytes: &[u8]) {
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn frame_u64(digest: &mut Sha256, value: u64) {
    frame(digest, &value.to_be_bytes());
}

fn dataset_kind_name(kind: DatasetKind) -> &'static str {
    match kind {
        DatasetKind::Prefix => "prefix-set",
        DatasetKind::Asn => "asn-set",
        DatasetKind::Community => "community-set",
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, byte| {
            let _ = write!(out, "{byte:02x}");
            out
        })
}

fn decode_hex(value: &str) -> Result<Vec<u8>, &'static str> {
    if !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("hex must be lowercase and even-length");
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| {
                if byte <= b'9' {
                    byte - b'0'
                } else {
                    byte - b'a' + 10
                }
            };
            Ok((digit(pair[0]) << 4) | digit(pair[1]))
        })
        .collect()
}

mod hex_digest {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        digest: &[u8; 32],
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&super::encode_hex(digest))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<[u8; 32], D::Error> {
        let value = String::deserialize(deserializer)?;
        let bytes = super::decode_hex(&value).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("digest must be exactly 32 bytes"))
    }
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

fn limit(name: &str, bytes: usize) -> io::Error {
    invalid(format!("{name} exceeds its {bytes}-byte limit"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Envelope {
        let normalized_toml = "asn = 64512\n".to_string();
        let toml_sha256 = Sha256::digest(normalized_toml.as_bytes()).into();
        let manifest = Manifest {
            toml_sha256,
            rpol_units: vec![RpolUnit {
                modules: vec![RpolModule {
                    path: LosslessPath(b"/policy/main.rpol".to_vec()),
                    length: 3,
                    sha256: [0x22; 32],
                    imports: vec![0],
                }],
            }],
            datasets: vec![Dataset {
                name: "customers".into(),
                kind: DatasetKind::Asn,
                path: LosslessPath(b"/data/asns".to_vec()),
                length: 4,
                sha256: [0x33; 32],
            }],
        };
        Envelope {
            version: 2,
            sequence: 7,
            timestamp_unix_seconds: 9,
            sha256: toml_sha256,
            source_sha256: manifest_source_sha256(&manifest),
            normalized_toml,
            manifest,
        }
    }

    fn reseal(envelope: &mut Envelope) {
        envelope.sha256 = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
        envelope.manifest.toml_sha256 = envelope.sha256;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
    }

    fn assert_error(result: io::Result<impl Sized>, text: &str) {
        let Err(error) = result else {
            panic!("expected InvalidData containing {text:?}");
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains(text), "{error}");
    }

    #[test]
    fn canonical_golden_order_and_lf_round_trip() {
        let envelope = sample();
        let bytes = encode_envelope(&envelope).unwrap();
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert_eq!(
            text,
            concat!(
                "{\"version\":2,\"sequence\":7,\"timestamp_unix_seconds\":9,\"sha256\":\"a8745c2ae560173c753ac9fa5f37f2167c05d5eb68c5154d561502c674d72d6c\",",
                "\"source_sha256\":\"94f27364376996e7af8fe5f2e8ec07986f3ea41a0f655e730bd19ed9bfa2201c\",\"normalized_toml\":\"asn = 64512\\n\",",
                "\"manifest\":{\"toml_sha256\":\"a8745c2ae560173c753ac9fa5f37f2167c05d5eb68c5154d561502c674d72d6c\",\"rpol_units\":[",
                "{\"modules\":[{\"path\":{\"encoding\":\"unix-bytes-hex\",\"value\":\"2f706f6c6963792f6d61696e2e72706f6c\"},\"length\":3,",
                "\"sha256\":\"2222222222222222222222222222222222222222222222222222222222222222\",\"imports\":[0]}]}],",
                "\"datasets\":[{\"name\":\"customers\",\"kind\":\"asn-set\",\"path\":{\"encoding\":\"unix-bytes-hex\",",
                "\"value\":\"2f646174612f61736e73\"},\"length\":4,\"sha256\":\"3333333333333333333333333333333333333333333333333333333333333333\"}]}}\n"
            )
        );
        assert_eq!(decode_envelope(&bytes).unwrap(), envelope);
    }

    #[test]
    fn rejects_noncanonical_and_bad_wire_spellings() {
        let bytes = encode_envelope(&sample()).unwrap();
        // LOAD-BEARING BREAK: each mutation changes one canonical wire rule;
        // accepting any item makes this destructive proof red.
        for (broken, expected) in [
            (
                [&b" "[..], &bytes[..]].concat(),
                "non-canonical v2 envelope",
            ),
            (
                bytes[..bytes.len() - 1].to_vec(),
                "non-canonical v2 envelope",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace(
                        "\"version\":2,\"sequence\":7",
                        "\"sequence\":7,\"version\":2",
                    )
                    .into_bytes(),
                "non-canonical v2 envelope",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("\"version\":2", "\"version\":3")
                    .into_bytes(),
                "unsupported config-history",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("unix-bytes-hex", "unix_bytes_hex")
                    .into_bytes(),
                "unsupported path encoding",
            ),
            (
                String::from_utf8(bytes.clone())
                    .unwrap()
                    .replace("asn-set", "ASN-set")
                    .into_bytes(),
                "unknown variant",
            ),
        ] {
            assert_error(decode_envelope(&broken), expected);
        }
        let duplicate =
            String::from_utf8(bytes.clone())
                .unwrap()
                .replacen('{', "{\"version\":2,", 1);
        assert_error(
            decode_envelope(duplicate.as_bytes()),
            "duplicate field `version`",
        );
        let unknown = String::from_utf8(bytes)
            .unwrap()
            .replacen('{', "{\"unknown\":0,", 1);
        assert_error(
            decode_envelope(unknown.as_bytes()),
            "unknown field `unknown`",
        );
    }

    #[test]
    fn rejects_digest_and_roster_invariants() {
        // LOAD-BEARING BREAK: recomputing or repairing caller-owned fields in
        // encode would make these destructive mutations unexpectedly green.
        let mut envelope = sample();
        envelope.sha256[0] ^= 1;
        assert_error(encode_envelope(&envelope), "TOML digest mismatch");
        envelope = sample();
        envelope.source_sha256[0] ^= 1;
        assert_error(
            encode_envelope(&envelope),
            "source manifest digest mismatch",
        );
        envelope = sample();
        envelope.manifest.rpol_units[0].modules.clear();
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "1..=64 modules");
        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].imports[0] = 1;
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "outside its unit");
        envelope = sample();
        envelope
            .manifest
            .datasets
            .push(envelope.manifest.datasets[0].clone());
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert_error(encode_envelope(&envelope), "strictly byte-sorted");
    }

    #[test]
    fn loader_digest_golden_and_invalid_utf8_path() {
        let mut manifest = sample().manifest;
        manifest.rpol_units[0].modules[0].path = LosslessPath(vec![b'/', 0xff]);
        let envelope = Envelope {
            source_sha256: manifest_source_sha256(&manifest),
            manifest,
            ..sample()
        };
        assert_eq!(
            decode_envelope(&encode_envelope(&envelope).unwrap()).unwrap(),
            envelope
        );
        assert_eq!(
            encode_hex(&manifest_source_sha256(&Manifest {
                toml_sha256: [0x11; 32],
                rpol_units: vec![RpolUnit {
                    modules: vec![RpolModule {
                        path: LosslessPath(b"/policy".to_vec()),
                        length: 3,
                        sha256: [0x22; 32],
                        imports: vec![0, 1],
                    }],
                }],
                datasets: vec![Dataset {
                    name: "customers".into(),
                    kind: DatasetKind::Asn,
                    path: LosslessPath(b"/dataset".to_vec()),
                    length: 4,
                    sha256: [0x33; 32],
                }],
            })),
            "ea0d43501b201fcec9724d17ada9603e72a635cc9c048523b6449f0e4c7e6009"
        );
        // LOAD-BEARING BREAK: removing the unix-os-bytes tag or any framing
        // operation changes the golden above and proves loader incompatibility.
    }

    #[test]
    fn exact_and_plus_one_practical_bounds() {
        let mut envelope = sample();
        envelope.normalized_toml = "x".repeat(MAX_TOML);
        envelope.sha256 = Sha256::digest(envelope.normalized_toml.as_bytes()).into();
        envelope.manifest.toml_sha256 = envelope.sha256;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.normalized_toml.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "normalized TOML");
        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].path.0 = vec![b'x'; MAX_TEXT];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules[0].path.0.push(b'x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL module");
        assert_error(
            decode_envelope(&vec![b' '; MAX_ENVELOPE + 1]),
            "envelope exceeds",
        );
    }

    #[test]
    fn exact_and_plus_one_roster_bounds() {
        let module = sample().manifest.rpol_units[0].modules[0].clone();
        let mut envelope = sample();
        envelope.manifest.rpol_units = vec![
            RpolUnit {
                modules: vec![module.clone()],
            };
            MAX_UNITS
        ];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units.push(RpolUnit {
            modules: vec![module.clone()],
        });
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL units");

        envelope = sample();
        envelope.manifest.rpol_units[0].modules = vec![module.clone(); MAX_MODULES];
        for item in &mut envelope.manifest.rpol_units[0].modules {
            item.imports = vec![0];
        }
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules.push(module.clone());
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "1..=64 modules");

        envelope = sample();
        envelope.manifest.rpol_units[0].modules[0].imports = vec![0; MAX_IMPORTS];
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.rpol_units[0].modules[0].imports.push(0);
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "RPOL module");

        envelope = sample();
        let dataset = envelope.manifest.datasets[0].clone();
        envelope.manifest.datasets = (0..MAX_DATASETS)
            .map(|index| Dataset {
                name: format!("{index:05}"),
                ..dataset.clone()
            })
            .collect();
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.datasets.push(Dataset {
            name: "zzzzz".into(),
            ..dataset
        });
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "datasets exceeds");
    }

    #[test]
    fn exact_manifest_and_text_bounds() {
        let template = sample().manifest.datasets[0].clone();
        let mut envelope = sample();
        envelope.manifest.datasets = (0..256)
            .map(|index| Dataset {
                name: if index < 255 {
                    format!("{index:03}{}", "x".repeat(MAX_TEXT - 3))
                } else {
                    "255".into()
                },
                path: LosslessPath(Vec::new()),
                ..template.clone()
            })
            .collect();
        let base = serde_json::to_vec(&envelope.manifest).unwrap().len();
        envelope.manifest.datasets[255]
            .name
            .push_str(&"x".repeat(MAX_MANIFEST - base));
        assert_eq!(
            serde_json::to_vec(&envelope.manifest).unwrap().len(),
            MAX_MANIFEST
        );
        reseal(&mut envelope);
        assert!(encode_envelope(&envelope).is_ok());
        envelope.manifest.datasets[255].name.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "manifest exceeds");

        for field in ["name", "path"] {
            let mut envelope = sample();
            if field == "name" {
                envelope.manifest.datasets[0].name = "x".repeat(MAX_TEXT);
            } else {
                envelope.manifest.datasets[0].path.0 = vec![b'x'; MAX_TEXT];
            }
            reseal(&mut envelope);
            assert!(encode_envelope(&envelope).is_ok());
            if field == "name" {
                envelope.manifest.datasets[0].name.push('x');
            } else {
                envelope.manifest.datasets[0].path.0.push(b'x');
            }
            reseal(&mut envelope);
            assert_error(encode_envelope(&envelope), "name or path");
        }
    }

    #[test]
    fn exact_envelope_wire_bound_and_pre_serde_rejection() {
        let mut envelope = sample();
        envelope.normalized_toml.clear();
        reseal(&mut envelope);
        let base = encode_envelope(&envelope).unwrap().len();
        let remaining = MAX_ENVELOPE - base;
        envelope.normalized_toml = "\0".repeat(remaining / 6) + &"x".repeat(remaining % 6);
        reseal(&mut envelope);
        let bytes = encode_envelope(&envelope).unwrap();
        assert_eq!(bytes.len(), MAX_ENVELOPE);
        assert_eq!(decode_envelope(&bytes).unwrap(), envelope);
        envelope.normalized_toml.push('x');
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "envelope exceeds");
        assert_error(decode_envelope(&vec![b' '; MAX_ENVELOPE]), "EOF");
        assert_error(
            decode_envelope(&vec![b' '; MAX_ENVELOPE + 1]),
            "envelope exceeds",
        );
    }

    #[test]
    fn rejects_nested_schema_and_lexical_variants() {
        let canonical = String::from_utf8(encode_envelope(&sample()).unwrap()).unwrap();
        let cases = [
            (
                canonical.replace("\"sequence\":7", "\"sequence\":7.0"),
                "invalid type",
            ),
            (canonical.replace("22", "2A"), "hex must be lowercase"),
            (
                canonical.replace("2222", "222"),
                "digest must be exactly 32 bytes",
            ),
            (canonical.replace("2222", "22zz"), "hex must be lowercase"),
            (
                canonical.replacen("2f70", "2F70", 1),
                "hex must be lowercase",
            ),
            (canonical.replacen("2f70", "2f7", 1), "even-length"),
            (
                canonical.replacen("2f70", "2fzz", 1),
                "hex must be lowercase",
            ),
            (
                canonical.replace("\"modules\":[", "\"extra\":0,\"modules\":["),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"path\":{", "\"extra\":0,\"path\":{"),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"datasets\":[", "\"extra\":0,\"datasets\":["),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"name\":", "\"extra\":0,\"name\":"),
                "unknown field `extra`",
            ),
            (
                canonical.replace("\"encoding\":", "\"extra\":0,\"encoding\":"),
                "unknown field `extra`",
            ),
            (
                canonical.replacen("\"modules\":[", "\"modules\":[],\"modules\":[", 1),
                "duplicate field `modules`",
            ),
            (
                canonical.replacen("\"path\":{", "\"length\":3,\"path\":{", 1),
                "duplicate field `length`",
            ),
            (
                canonical.replacen("\"datasets\":[", "\"datasets\":[],\"datasets\":[", 1),
                "duplicate field `datasets`",
            ),
            (
                canonical.replacen("\"name\":", "\"name\":\"x\",\"name\":", 1),
                "duplicate field `name`",
            ),
            (
                canonical.replacen("\"encoding\":", "\"encoding\":\"x\",\"encoding\":", 1),
                "duplicate field `encoding`",
            ),
        ];
        for (broken, expected) in cases {
            assert_error(decode_envelope(broken.as_bytes()), expected);
        }
        let mut envelope = sample();
        envelope.manifest.toml_sha256[0] ^= 1;
        envelope.source_sha256 = manifest_source_sha256(&envelope.manifest);
        assert_error(encode_envelope(&envelope), "TOML digest mismatch");
        envelope = sample();
        envelope.manifest.datasets.insert(
            0,
            Dataset {
                name: "z".into(),
                ..envelope.manifest.datasets[0].clone()
            },
        );
        reseal(&mut envelope);
        assert_error(encode_envelope(&envelope), "strictly byte-sorted");
    }
}
