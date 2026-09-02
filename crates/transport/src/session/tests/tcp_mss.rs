//! `TCP_MAXSEG` reaches the active-open socket before connect. The passive
//! listener half is proven in `listener::tests`.

use super::*;

#[cfg(target_os = "linux")]
#[test]
fn active_open_installs_tcp_mss_clamp_before_connect() {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::cell::Cell;

    let peer_config = PeerConfig::new(65001, 65002, Ipv4Addr::new(10, 0, 0, 1));
    let mut config = TransportConfig::new(peer_config, "192.0.2.2:179".parse().unwrap());
    config.tcp_mss = Some(1000);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
    let observed = Cell::new(None);
    let result = super::io::prepare_active_socket_for_test(
        socket,
        &config,
        "192.0.2.2",
        |_, _, _, _, _| Ok(()),
        |socket, _| {
            observed.set(Some(socket.tcp_mss().unwrap()));
            Err(std::io::Error::other("stop before connect"))
        },
    );
    assert!(result.is_err());
    assert_eq!(
        observed.get(),
        Some(1000),
        "clamp must be set before connect"
    );
}
