//! Structural framing checks for assigned attributes retained opaquely.

use crate::constants::attr_type;

pub(crate) fn validate(type_code: u8, value: &[u8]) -> Result<(), &'static str> {
    match type_code {
        attr_type::DOMAIN_PATH => domain_path(value),
        attr_type::SFP => sfp(value),
        attr_type::BFD_DISCRIMINATOR => bfd_discriminator(value),
        attr_type::NHC => nhc(value),
        attr_type::PREFIX_SID => prefix_sid(value),
        attr_type::BIER => bier(value),
        _ => Ok(()),
    }
}

fn domain_path(mut value: &[u8]) -> Result<(), &'static str> {
    if value.len() < 8 {
        return Err("D-PATH must contain a non-empty domain segment");
    }
    while !value.is_empty() {
        let count = usize::from(value[0]);
        if count == 0 {
            return Err("D-PATH domain segment count is zero");
        }
        let length = 1_usize
            .checked_add(7_usize.checked_mul(count).ok_or("D-PATH length overflow")?)
            .ok_or("D-PATH length overflow")?;
        if value.len() < length {
            return Err("D-PATH domain segment overruns attribute");
        }
        value = &value[length..];
    }
    Ok(())
}

fn sfp(mut value: &[u8]) -> Result<(), &'static str> {
    let mut hop = false;
    while !value.is_empty() {
        let (kind, body, rest) = tlv_u8_u16(value)?;
        if kind == 2 {
            hop = true;
            if body.len() < 4 {
                return Err("SFP Hop TLV lacks service index or sub-TLV");
            }
            let mut sub = &body[1..];
            while !sub.is_empty() {
                let (_, _, rest) = tlv_u8_u16(sub)?;
                sub = rest;
            }
        }
        value = rest;
    }
    if !hop {
        return Err("SFP attribute lacks a Hop TLV");
    }
    Ok(())
}

fn bfd_discriminator(value: &[u8]) -> Result<(), &'static str> {
    if value.len() < 11 {
        return Err("BFD Discriminator attribute is shorter than 11 octets");
    }
    let mut source = false;
    let mut tlvs = &value[5..];
    while !tlvs.is_empty() {
        if tlvs.len() < 2 {
            return Err("BFD Discriminator TLV header is truncated");
        }
        let kind = tlvs[0];
        let length = usize::from(tlvs[1]);
        if tlvs.len() < 2 + length {
            return Err("BFD Discriminator TLV overruns attribute");
        }
        if kind == 1 {
            if !matches!(length, 4 | 16) {
                return Err("BFD Source IP TLV length is not 4 or 16");
            }
            source = true;
        }
        tlvs = &tlvs[2 + length..];
    }
    if !source {
        return Err("BFD Discriminator lacks Source IP TLV");
    }
    Ok(())
}

fn nhc(value: &[u8]) -> Result<(), &'static str> {
    if value.len() < 4 {
        return Err("NHC next-hop header is truncated");
    }
    let next_hop_len = usize::from(value[3]);
    if value.len() < 4 + next_hop_len {
        return Err("NHC next hop overruns attribute");
    }
    let mut characteristics = &value[4 + next_hop_len..];
    if characteristics.is_empty() {
        return Err("NHC has no characteristics");
    }
    while !characteristics.is_empty() {
        if characteristics.len() < 4 {
            return Err("NHC characteristic header is truncated");
        }
        let length = usize::from(u16::from_be_bytes([characteristics[2], characteristics[3]]));
        if characteristics.len() < 4 + length {
            return Err("NHC characteristic overruns attribute");
        }
        characteristics = &characteristics[4 + length..];
    }
    Ok(())
}

fn prefix_sid(mut value: &[u8]) -> Result<(), &'static str> {
    if value.len() < 3 {
        return Err("Prefix-SID attribute is shorter than one TLV header");
    }
    while !value.is_empty() {
        let (kind, body, rest) = tlv_u8_u16(value)?;
        match kind {
            1 if body.len() != 7 => return Err("Prefix-SID Label-Index TLV length is not 7"),
            3 if body.len() < 8 || (body.len() - 2) % 6 != 0 => {
                return Err("Prefix-SID Originator SRGB TLV length is invalid");
            }
            _ => {}
        }
        value = rest;
    }
    Ok(())
}

fn bier(mut value: &[u8]) -> Result<(), &'static str> {
    if value.is_empty() {
        return Err("BIER attribute contains no TLVs");
    }
    while !value.is_empty() {
        let (kind, body, rest) = tlv_u16_u16(value)?;
        if kind == 1 && body.len() >= 4 {
            validate_bier_subtlvs(&body[4..])?;
        }
        value = rest;
    }
    Ok(())
}

fn validate_bier_subtlvs(mut value: &[u8]) -> Result<(), &'static str> {
    let mut pending = Vec::new();
    loop {
        while !value.is_empty() {
            let (kind, body, rest) = tlv_u16_u16(value)?;
            match kind {
                2 | 3 if body.len() >= 4 && !body[4..].is_empty() => {
                    pending.push(&body[4..]);
                }
                _ => {}
            }
            value = rest;
        }
        let Some(next) = pending.pop() else { break };
        value = next;
    }
    Ok(())
}

fn tlv_u8_u16(value: &[u8]) -> Result<(u8, &[u8], &[u8]), &'static str> {
    if value.len() < 3 {
        return Err("TLV header is truncated");
    }
    let length = usize::from(u16::from_be_bytes([value[1], value[2]]));
    if value.len() < 3 + length {
        return Err("TLV overruns attribute");
    }
    Ok((value[0], &value[3..3 + length], &value[3 + length..]))
}

fn tlv_u16_u16(value: &[u8]) -> Result<(u16, &[u8], &[u8]), &'static str> {
    if value.len() < 4 {
        return Err("TLV header is truncated");
    }
    let kind = u16::from_be_bytes([value[0], value[1]]);
    let length = usize::from(u16::from_be_bytes([value[2], value[3]]));
    if value.len() < 4 + length {
        return Err("TLV overruns attribute");
    }
    Ok((kind, &value[4..4 + length], &value[4 + length..]))
}
