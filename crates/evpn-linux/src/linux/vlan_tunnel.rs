//! Target-scoped read of one bridge port's VLAN tunnel mappings.
//!
//! The FDB apply path re-reads an SVD VXLAN's bridge VLAN tunnel mapping
//! before each write. The `AF_BRIDGE` link dump returns every port in the
//! namespace, so a per-row read through it costs a full dump per row. The
//! bridge VLAN database (`RTM_GETVLAN`, Linux 5.13+) dumps only the port
//! named in the request's `br_vlan_msg.ifindex`, and its per-VLAN options
//! carry the tunnel ID (`BRIDGE_VLANDB_ENTRY_TUNNEL_INFO`, Linux 5.14+).
//! `netlink-packet-route` has no `RTM_GETVLAN` support, so this module
//! encodes the request and parses the reply directly.

use netlink_sys::{AsyncSocket, AsyncSocketExt, SocketAddr, TokioSocket, protocols::NETLINK_ROUTE};

use crate::error::DataplaneError;

const RTM_NEWVLAN: u16 = 112;
const RTM_GETVLAN: u16 = 114;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const AF_BRIDGE: u8 = 7;
const NLMSG_HDRLEN: usize = 16;
const BR_VLAN_MSG_LEN: usize = 8;
const NLA_TYPE_MASK: u16 = 0x3fff;

const BRIDGE_VLANDB_ENTRY: u16 = 1;
const BRIDGE_VLANDB_ENTRY_INFO: u16 = 1;
const BRIDGE_VLANDB_ENTRY_RANGE: u16 = 2;
const BRIDGE_VLANDB_ENTRY_TUNNEL_INFO: u16 = 4;
const BRIDGE_VLANDB_TINFO_ID: u16 = 1;

/// One compressed VLAN database entry for a port: VLANs
/// `vid_start..=vid_end`, and when tunnelled, the tunnel ID of
/// `vid_start`. The kernel compresses a range only when the tunnel IDs
/// are consecutive, so VLAN `v` in the range maps to
/// `tunnel_start + (v - vid_start)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct VlanEntry {
    pub vid_start: u16,
    pub vid_end: u16,
    pub tunnel_start: Option<u32>,
}

impl VlanEntry {
    /// Tunnel ID carried by `vid`, when this entry covers it.
    fn tunnel_for(self, vid: u16) -> Option<u32> {
        if vid < self.vid_start || vid > self.vid_end {
            return None;
        }
        self.tunnel_start
            .map(|start| start.wrapping_add(u32::from(vid - self.vid_start)))
    }
}

/// Whether the dumped entries map `bridge_vlan` to `tunnel_id`.
pub(crate) fn entries_map_vlan_to_tunnel(
    entries: &[VlanEntry],
    bridge_vlan: u16,
    tunnel_id: u32,
) -> bool {
    entries
        .iter()
        .any(|entry| entry.tunnel_for(bridge_vlan) == Some(tunnel_id))
}

/// Dump the VLAN database of the single bridge port `ifindex`.
pub(crate) async fn dump_port_vlans(ifindex: u32) -> Result<Vec<VlanEntry>, DataplaneError> {
    let io = |e: std::io::Error| DataplaneError::Other(format!("bridge VLAN db read: {e}"));
    let mut socket = TokioSocket::new(NETLINK_ROUTE).map_err(io)?;
    socket.socket_mut().bind_auto().map_err(io)?;
    socket
        .socket_mut()
        .connect(&SocketAddr::new(0, 0))
        .map_err(io)?;
    let seq = 1;
    socket
        .send(&encode_dump_request(seq, ifindex))
        .await
        .map_err(io)?;

    let mut entries = Vec::new();
    loop {
        let (buf, _) = socket.recv_from_full().await.map_err(io)?;
        if parse_dump_datagram(&buf, seq, ifindex, &mut entries)? {
            return Ok(entries);
        }
    }
}

fn encode_dump_request(seq: u32, ifindex: u32) -> Vec<u8> {
    let len = NLMSG_HDRLEN + BR_VLAN_MSG_LEN;
    let mut buf = Vec::with_capacity(len);
    buf.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_ne_bytes());
    buf.extend_from_slice(&RTM_GETVLAN.to_ne_bytes());
    buf.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    buf.extend_from_slice(&seq.to_ne_bytes());
    buf.extend_from_slice(&0u32.to_ne_bytes());
    // struct br_vlan_msg { u8 family; u8 reserved1; u16 reserved2; u32 ifindex; }
    buf.extend_from_slice(&[AF_BRIDGE, 0, 0, 0]);
    buf.extend_from_slice(&ifindex.to_ne_bytes());
    buf
}

fn read_u16(buf: &[u8], at: usize) -> Option<u16> {
    buf.get(at..at + 2)
        .map(|b| u16::from_ne_bytes([b[0], b[1]]))
}

fn read_u32(buf: &[u8], at: usize) -> Option<u32> {
    buf.get(at..at + 4)
        .map(|b| u32::from_ne_bytes([b[0], b[1], b[2], b[3]]))
}

fn truncated() -> DataplaneError {
    DataplaneError::Other("bridge VLAN db read: truncated netlink message".into())
}

/// Iterate the `(type, payload)` attributes in `buf`.
fn attrs(buf: &[u8]) -> impl Iterator<Item = Result<(u16, &[u8]), DataplaneError>> {
    let mut at = 0;
    std::iter::from_fn(move || {
        if at + 4 > buf.len() {
            return None;
        }
        let (Some(len), Some(kind)) = (read_u16(buf, at), read_u16(buf, at + 2)) else {
            return Some(Err(truncated()));
        };
        let len = usize::from(len);
        if len < 4 || at + len > buf.len() {
            return Some(Err(truncated()));
        }
        let payload = &buf[at + 4..at + len];
        at += (len + 3) & !3;
        Some(Ok((kind & NLA_TYPE_MASK, payload)))
    })
}

fn parse_entry(payload: &[u8]) -> Result<Option<VlanEntry>, DataplaneError> {
    let mut vid = None;
    let mut range = None;
    let mut tunnel = None;
    for attr in attrs(payload) {
        let (kind, data) = attr?;
        match kind {
            // struct bridge_vlan_info { u16 flags; u16 vid; }
            BRIDGE_VLANDB_ENTRY_INFO => vid = read_u16(data, 2),
            BRIDGE_VLANDB_ENTRY_RANGE => range = read_u16(data, 0),
            BRIDGE_VLANDB_ENTRY_TUNNEL_INFO => {
                for inner in attrs(data) {
                    let (inner_kind, inner_data) = inner?;
                    if inner_kind == BRIDGE_VLANDB_TINFO_ID {
                        tunnel = read_u32(inner_data, 0);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(vid.map(|vid_start| VlanEntry {
        vid_start,
        vid_end: range.unwrap_or(vid_start).max(vid_start),
        tunnel_start: tunnel,
    }))
}

/// Parse one dump datagram. Returns `true` once the dump is complete.
fn parse_dump_datagram(
    buf: &[u8],
    seq: u32,
    ifindex: u32,
    out: &mut Vec<VlanEntry>,
) -> Result<bool, DataplaneError> {
    let mut at = 0;
    while at + NLMSG_HDRLEN <= buf.len() {
        let (Some(len), Some(kind), Some(flags), Some(msg_seq)) = (
            read_u32(buf, at),
            read_u16(buf, at + 4),
            read_u16(buf, at + 6),
            read_u32(buf, at + 8),
        ) else {
            return Err(truncated());
        };
        let len = usize::try_from(len).map_err(|_| truncated())?;
        if len < NLMSG_HDRLEN || at + len > buf.len() {
            return Err(truncated());
        }
        let body = &buf[at + NLMSG_HDRLEN..at + len];
        at += (len + 3) & !3;
        if msg_seq != seq {
            continue;
        }
        // The VLAN database changed mid-dump: entries already read may be
        // stale, so the whole dump is untrustworthy. Fail transiently.
        if flags & NLM_F_DUMP_INTR != 0 {
            return Err(DataplaneError::Other(
                "bridge VLAN db read: dump interrupted by a concurrent change".into(),
            ));
        }
        match kind {
            // NLMSG_ERROR carries an `int error`; so does NLMSG_DONE when a
            // dump fails part-way after sending some entries.
            NLMSG_DONE | NLMSG_ERROR => {
                let errno = read_u32(body, 0).map_or(0, u32::cast_signed);
                if errno != 0 {
                    return Err(DataplaneError::Other(format!(
                        "bridge VLAN db read: kernel errno {}",
                        -errno
                    )));
                }
                if kind == NLMSG_DONE {
                    return Ok(true);
                }
            }
            RTM_NEWVLAN => {
                if body.len() < BR_VLAN_MSG_LEN || read_u32(body, 4) != Some(ifindex) {
                    continue;
                }
                for attr in attrs(&body[BR_VLAN_MSG_LEN..]) {
                    let (attr_kind, data) = attr?;
                    if attr_kind == BRIDGE_VLANDB_ENTRY
                        && let Some(entry) = parse_entry(data)?
                    {
                        out.push(entry);
                    }
                }
            }
            _ => {}
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
        let len = 4 + payload.len();
        let mut out = Vec::new();
        out.extend_from_slice(&u16::try_from(len).unwrap().to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(payload);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn entry(vid: u16, range: Option<u16>, tunnel: Option<u32>) -> Vec<u8> {
        let mut info = Vec::new();
        info.extend_from_slice(&0u16.to_ne_bytes());
        info.extend_from_slice(&vid.to_ne_bytes());
        let mut payload = nla(BRIDGE_VLANDB_ENTRY_INFO, &info);
        if let Some(range) = range {
            payload.extend(nla(BRIDGE_VLANDB_ENTRY_RANGE, &range.to_ne_bytes()));
        }
        if let Some(tunnel) = tunnel {
            payload.extend(nla(
                BRIDGE_VLANDB_ENTRY_TUNNEL_INFO | 0x8000,
                &nla(BRIDGE_VLANDB_TINFO_ID, &tunnel.to_ne_bytes()),
            ));
        }
        nla(BRIDGE_VLANDB_ENTRY | 0x8000, &payload)
    }

    fn message(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let len = NLMSG_HDRLEN + body.len();
        let mut out = Vec::new();
        out.extend_from_slice(&u32::try_from(len).unwrap().to_ne_bytes());
        out.extend_from_slice(&kind.to_ne_bytes());
        out.extend_from_slice(&0x2u16.to_ne_bytes());
        out.extend_from_slice(&seq.to_ne_bytes());
        out.extend_from_slice(&0u32.to_ne_bytes());
        out.extend_from_slice(body);
        out
    }

    fn vlan_message(seq: u32, ifindex: u32, entries: &[Vec<u8>]) -> Vec<u8> {
        let mut body = vec![AF_BRIDGE, 0, 0, 0];
        body.extend_from_slice(&ifindex.to_ne_bytes());
        for e in entries {
            body.extend_from_slice(e);
        }
        message(RTM_NEWVLAN, seq, &body)
    }

    #[test]
    fn request_names_the_port_and_asks_for_a_dump() {
        let req = encode_dump_request(9, 42);
        assert_eq!(req.len(), NLMSG_HDRLEN + BR_VLAN_MSG_LEN);
        assert_eq!(read_u16(&req, 4), Some(RTM_GETVLAN));
        assert_eq!(read_u16(&req, 6), Some(NLM_F_REQUEST | NLM_F_DUMP));
        assert_eq!(req[NLMSG_HDRLEN], AF_BRIDGE);
        assert_eq!(read_u32(&req, NLMSG_HDRLEN + 4), Some(42));
    }

    #[test]
    fn parses_tunnel_ranges_and_ignores_other_ports() {
        let mut buf = vlan_message(
            3,
            42,
            &[entry(10, None, Some(100)), entry(20, Some(22), Some(200))],
        );
        buf.extend(vlan_message(3, 7, &[entry(30, None, Some(300))]));
        let mut out = Vec::new();
        assert!(!parse_dump_datagram(&buf, 3, 42, &mut out).unwrap());
        assert!(parse_dump_datagram(&message(NLMSG_DONE, 3, &[0; 4]), 3, 42, &mut out).unwrap());
        assert_eq!(
            out,
            vec![
                VlanEntry {
                    vid_start: 10,
                    vid_end: 10,
                    tunnel_start: Some(100)
                },
                VlanEntry {
                    vid_start: 20,
                    vid_end: 22,
                    tunnel_start: Some(200)
                },
            ]
        );
        assert!(entries_map_vlan_to_tunnel(&out, 10, 100));
        assert!(entries_map_vlan_to_tunnel(&out, 21, 201));
        assert!(!entries_map_vlan_to_tunnel(&out, 21, 200));
        assert!(
            !entries_map_vlan_to_tunnel(&out, 30, 300),
            "other port's entry"
        );
    }

    #[test]
    fn untunnelled_vlan_maps_nothing() {
        let entries = [VlanEntry {
            vid_start: 10,
            vid_end: 10,
            tunnel_start: None,
        }];
        assert!(!entries_map_vlan_to_tunnel(&entries, 10, 100));
    }

    // A failed or interrupted dump must not authorize an FDB write, even
    // after an earlier message supplied a matching tunnel entry.
    #[test]
    fn done_with_error_fails_the_dump() {
        let mut buf = vlan_message(3, 42, &[entry(10, None, Some(100))]);
        buf.extend(message(NLMSG_DONE, 3, &(-16i32).to_ne_bytes()));
        let err = parse_dump_datagram(&buf, 3, 42, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("errno 16"), "{err}");
        assert_eq!(err.class(), crate::error::FailureClass::Transient);
    }

    #[test]
    fn interrupted_dump_fails() {
        let mut intr = vlan_message(3, 42, &[entry(10, None, Some(100))]);
        let flags = read_u16(&intr, 6).unwrap() | NLM_F_DUMP_INTR;
        intr[6..8].copy_from_slice(&flags.to_ne_bytes());
        intr.extend(message(NLMSG_DONE, 3, &[0; 4]));
        let err = parse_dump_datagram(&intr, 3, 42, &mut Vec::new()).unwrap_err();
        assert!(err.to_string().contains("interrupted"), "{err}");
        assert_eq!(err.class(), crate::error::FailureClass::Transient);
    }

    #[test]
    fn kernel_error_frame_is_reported() {
        let mut body = (-22i32).to_ne_bytes().to_vec();
        body.extend_from_slice(&[0; 16]);
        let err = parse_dump_datagram(&message(NLMSG_ERROR, 3, &body), 3, 42, &mut Vec::new())
            .unwrap_err();
        assert!(err.to_string().contains("errno 22"), "{err}");
    }
}
