//! API RD text preserves the complete eight-byte route identity.

use rustbgpd_wire::RouteDistinguisher;
use tonic::Status;

pub(crate) fn parse_rd(value: &str) -> Result<RouteDistinguisher, Status> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        if hex.len() != 16 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(Status::invalid_argument(
                "raw RD requires 0x followed by exactly 16 hexadecimal digits",
            ));
        }
        return u64::from_str_radix(hex, 16)
            .map(|raw| RouteDistinguisher(raw.to_be_bytes()))
            .map_err(|_| Status::invalid_argument("invalid raw RD"));
    }
    value
        .parse()
        .map_err(|error| Status::invalid_argument(format!("invalid RD: {error}")))
}

pub(crate) fn parse_family_rd(value: &str) -> Result<Option<RouteDistinguisher>, Status> {
    if value.is_empty() {
        Ok(None)
    } else {
        parse_rd(value).map(Some).map_err(|error| {
            Status::invalid_argument(format!("invalid rd_filter: {}", error.message()))
        })
    }
}

pub(crate) fn format_rd(rd: RouteDistinguisher) -> String {
    // Small Type 2 ASNs otherwise display exactly like a different Type 0 RD.
    if rd.rd_type() == 2 && rd.0[2..4] == [0, 0] {
        format!("0x{:016x}", u64::from_be_bytes(rd.0))
    } else {
        rd.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rd_text_round_trips_all_types_without_collisions() {
        for raw in [
            0x0000_fde8_0000_0064u64,
            0x0001_c000_0201_0064,
            0x0002_0000_fde8_0064,
            0x0002_fa56_ea00_0064,
            0xffff_ffff_ffff_ffff,
        ] {
            let rd = RouteDistinguisher(raw.to_be_bytes());
            let text = format_rd(rd);
            assert_eq!(parse_rd(&text).unwrap(), rd);
            for prefix in ["0x", "0X"] {
                assert_eq!(parse_rd(&format!("{prefix}{raw:016X}")).unwrap(), rd);
            }
        }
        assert_eq!(format_rd(parse_rd("65000:100").unwrap()), "65000:100");
        assert_eq!(format_rd(parse_rd("10.0.0.1:100").unwrap()), "10.0.0.1:100");
        assert_eq!(
            format_rd(parse_rd("4200000000:100").unwrap()),
            "4200000000:100"
        );
        assert_eq!(
            format_rd(parse_rd("0X00020000FDE80064").unwrap()),
            "0x00020000fde80064"
        );
        assert_ne!(
            parse_rd("65000:100").unwrap(),
            parse_rd("0X00020000FDE80064").unwrap()
        );
    }

    #[test]
    fn rd_raw_grammar_rejects_malformed_and_required_empty() {
        assert_eq!(parse_family_rd("").unwrap(), None);
        for value in [
            "",
            "0x",
            "0X0002",
            "0x+0020000fde80064",
            "0x00020000fde800zz",
            "0x00020000fde800640",
            "0x０００２００００ｆｄｅ８００６４",
            "65536:65536",
        ] {
            assert_eq!(
                parse_rd(value).unwrap_err().code(),
                tonic::Code::InvalidArgument,
                "{value}"
            );
        }
    }
}
