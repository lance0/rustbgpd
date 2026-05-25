//! Privileged netns spike for ADR-0069 BGP unnumbered primitives.
//!
//! This is intentionally a proof test, not production BGP behavior. It pins the
//! Linux/socket facts ADR-0069 depends on before rustbgpd grows a scoped peer
//! identity:
//!
//! 1. Active TCP can connect to `fe80::peer%ifindex`.
//! 2. A passive wildcard listener can accept that connection; the observed
//!    accepted-peer scope is printed so the production slice can choose between
//!    wildcard matching and per-interface listener binding.
//! 3. IPv6 Hop-Limit/GTSM-style socket options work on TCP: a listener with
//!    `IPV6_MINHOPCOUNT=254` accepts a peer that sends with hop-limit 255.
//! 4. Linux accepts an IPv4 route via an IPv6 link-local gateway when `dev` is
//!    supplied.
//!
//! Run through the Docker harness:
//!
//! ```bash
//! bash crates/evpn-linux/tests/docker/run-netns-tests.sh bgp_unnumbered
//! ```

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::os::fd::FromRawFd;
use std::process::Command;
use std::thread;
use std::time::Duration;

const IFACE: &str = "eth0";
const CLIENT_LL: &str = "fe80::1";
const SERVER_LL: &str = "fe80::2";
const PORT_PLAIN: u16 = 11_790;
const PORT_GTSM: u16 = 11_791;

fn netns_gate() -> bool {
    std::env::var("EVPN_LINUX_NETNS").as_deref() == Ok("1")
}

fn is_inner() -> bool {
    std::env::var("RUSTBGPD_NETNS_INNER").is_ok()
}

fn run(cmd: &str, args: &[&str]) -> std::process::Output {
    let out = Command::new(cmd).args(args).output().expect("spawn");
    if !out.status.success() {
        panic!(
            "{cmd} {args:?} failed: status={} stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
    }
    out
}

fn try_run(cmd: &str, args: &[&str]) {
    let _ = Command::new(cmd).args(args).output();
}

struct NetnsFixture {
    name: String,
}

impl NetnsFixture {
    fn create(test_name: &str, role: &str) -> Self {
        let name = format!(
            "rustbgpd-bgp-unnumbered-{test_name}-{role}-{}",
            std::process::id()
        );
        try_run("ip", &["netns", "delete", &name]);
        run("ip", &["netns", "add", &name]);
        run("ip", &["-n", &name, "link", "set", "lo", "up"]);
        Self { name }
    }
}

impl Drop for NetnsFixture {
    fn drop(&mut self) {
        try_run("ip", &["netns", "delete", &self.name]);
    }
}

fn run_role(ns: &NetnsFixture, test_name: &str, role: &str) -> std::process::Child {
    let exe = std::env::current_exe().expect("self-exe");
    Command::new("ip")
        .args(["netns", "exec", &ns.name])
        .arg(&exe)
        .args(["--exact", "--nocapture", test_name])
        .env("RUSTBGPD_NETNS_INNER", "1")
        .env("RUSTBGPD_NETNS_ROLE", role)
        .env("EVPN_LINUX_NETNS", "1")
        .spawn()
        .expect("spawn inner role")
}

fn setup_veth_pair(client_ns: &str, server_ns: &str) {
    try_run("ip", &["link", "del", "veth-client"]);
    run(
        "ip",
        &[
            "link",
            "add",
            "veth-client",
            "type",
            "veth",
            "peer",
            "name",
            "veth-server",
        ],
    );
    run(
        "ip",
        &[
            "link",
            "set",
            "veth-client",
            "netns",
            client_ns,
            "name",
            IFACE,
        ],
    );
    run(
        "ip",
        &[
            "link",
            "set",
            "veth-server",
            "netns",
            server_ns,
            "name",
            IFACE,
        ],
    );
    configure_endpoint(client_ns, CLIENT_LL);
    configure_endpoint(server_ns, SERVER_LL);
}

fn configure_endpoint(ns: &str, ll: &str) {
    run("ip", &["-n", ns, "link", "set", IFACE, "up"]);
    run(
        "ip",
        &[
            "-n",
            ns,
            "-6",
            "addr",
            "add",
            &format!("{ll}/64"),
            "dev",
            IFACE,
            "nodad",
        ],
    );
}

fn ifindex(name: &str) -> u32 {
    let path = format!("/sys/class/net/{name}/ifindex");
    std::fs::read_to_string(path)
        .expect("read ifindex")
        .trim()
        .parse()
        .expect("parse ifindex")
}

fn parse_v6(addr: &str) -> Ipv6Addr {
    addr.parse().expect("parse IPv6 address")
}

fn set_ipv6_unicast_hops(fd: libc::c_int, hops: libc::c_int) {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_UNICAST_HOPS,
            (&raw const hops).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt(IPV6_UNICAST_HOPS): {}",
        std::io::Error::last_os_error()
    );
}

fn set_ipv6_min_hopcount(fd: libc::c_int, hops: libc::c_int) {
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_MINHOPCOUNT,
            (&raw const hops).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "setsockopt(IPV6_MINHOPCOUNT): {}",
        std::io::Error::last_os_error()
    );
}

fn scoped_tcp_connect(client_ifindex: u32, port: u16, hop_limit: Option<i32>) -> TcpStream {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        fd >= 0,
        "socket(AF_INET6): {}",
        std::io::Error::last_os_error()
    );
    if let Some(hops) = hop_limit {
        set_ipv6_unicast_hops(fd, hops);
    }
    let mut addr = sockaddr_v6(parse_v6(SERVER_LL), port, client_ifindex);
    let rc = unsafe {
        libc::connect(
            fd,
            (&raw mut addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    assert_eq!(
        rc,
        0,
        "connect(fe80::2%{client_ifindex}): {}",
        std::io::Error::last_os_error()
    );
    let stream = unsafe { TcpStream::from_raw_fd(fd) };
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .expect("set write timeout");
    stream
}

fn bind_wildcard_listener_with_min_hopcount(port: u16, min_hops: Option<i32>) -> TcpListener {
    let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    assert!(
        fd >= 0,
        "socket(AF_INET6): {}",
        std::io::Error::last_os_error()
    );
    if let Some(hops) = min_hops {
        set_ipv6_min_hopcount(fd, hops);
    }
    let mut addr = sockaddr_v6(Ipv6Addr::UNSPECIFIED, port, 0);
    let rc = unsafe {
        libc::bind(
            fd,
            (&raw mut addr).cast::<libc::sockaddr>(),
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        )
    };
    assert_eq!(rc, 0, "bind([::]:0): {}", std::io::Error::last_os_error());
    let rc = unsafe { libc::listen(fd, 16) };
    assert_eq!(rc, 0, "listen: {}", std::io::Error::last_os_error());
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    listener.set_nonblocking(false).expect("blocking listener");
    listener
}

fn sockaddr_v6(addr: Ipv6Addr, port: u16, scope_id: u32) -> libc::sockaddr_in6 {
    libc::sockaddr_in6 {
        sin6_family: libc::AF_INET6 as libc::sa_family_t,
        sin6_port: port.to_be(),
        sin6_flowinfo: 0,
        sin6_addr: libc::in6_addr {
            s6_addr: addr.octets(),
        },
        sin6_scope_id: scope_id,
    }
}

fn assert_ipv4_route_via_link_local_dev() {
    run(
        "ip",
        &[
            "route",
            "add",
            "198.51.100.0/24",
            "via",
            "inet6",
            SERVER_LL,
            "dev",
            IFACE,
        ],
    );
    let out = run("ip", &["route", "show", "exact", "198.51.100.0/24"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("198.51.100.0/24")
            && stdout.contains("via inet6 fe80::2")
            && stdout.contains(&format!("dev {IFACE}")),
        "expected IPv4 route via IPv6 link-local dev {IFACE}, got: {stdout}"
    );
}

fn run_server_role() {
    let plain_listener = bind_wildcard_listener_with_min_hopcount(PORT_PLAIN, None);
    assert_eq!(
        plain_listener.local_addr().expect("plain addr").port(),
        PORT_PLAIN
    );
    let gtsm_listener = bind_wildcard_listener_with_min_hopcount(PORT_GTSM, Some(254));
    assert_eq!(
        gtsm_listener.local_addr().expect("gtsm addr").port(),
        PORT_GTSM
    );

    let peer = accept_one_byte(plain_listener);
    match peer {
        SocketAddr::V6(v6) => {
            eprintln!(
                "ADR-0069 passive accept observed peer={} scope_id={}",
                v6.ip(),
                v6.scope_id()
            );
            assert_eq!(*v6.ip(), parse_v6(CLIENT_LL));
            // Load-bearing for ADR-0069: a wildcard listener can match a scoped
            // link-local peer only if the accepted address carries the arrival
            // interface as a non-zero scope id. If this ever regresses to 0, the
            // production slice would need per-interface listener binding instead
            // of (peer_ll, scope_id) matching — so gate the assumption, don't
            // just observe it.
            assert_ne!(
                v6.scope_id(),
                0,
                "accepted link-local peer must carry a non-zero arrival scope id"
            );
        }
        SocketAddr::V4(v4) => panic!("expected IPv6 accepted peer, got {v4}"),
    }

    let peer = accept_one_byte(gtsm_listener);
    assert!(peer.is_ipv6(), "GTSM/Hop-Limit listener accepted IPv6 peer");
}

fn accept_one_byte(listener: TcpListener) -> SocketAddr {
    let (mut accepted, peer) = listener.accept().expect("accept scoped connection");
    let mut byte = [0_u8; 1];
    accepted.read_exact(&mut byte).expect("read byte");
    accepted.write_all(b"y").expect("write byte");
    peer
}

fn run_client_role() {
    thread::sleep(Duration::from_millis(250));
    let client_ifindex = ifindex(IFACE);
    let mut client = scoped_tcp_connect(client_ifindex, PORT_PLAIN, None);
    client.write_all(b"x").expect("write client byte");
    let mut byte = [0_u8; 1];
    client.read_exact(&mut byte).expect("read reply byte");

    let mut client = scoped_tcp_connect(client_ifindex, PORT_GTSM, Some(255));
    client.write_all(b"x").expect("write gtsm client byte");
    client.read_exact(&mut byte).expect("read gtsm reply byte");

    assert_ipv4_route_via_link_local_dev();
}

#[test]
fn bgp_unnumbered_kernel_socket_primitives() {
    if !netns_gate() {
        eprintln!("skipping: set EVPN_LINUX_NETNS=1 to run ADR-0069 netns spike");
        return;
    }

    if is_inner() {
        match std::env::var("RUSTBGPD_NETNS_ROLE").as_deref() {
            Ok("server") => run_server_role(),
            Ok("client") => run_client_role(),
            other => panic!("unexpected RUSTBGPD_NETNS_ROLE={other:?}"),
        }
        return;
    }

    let client_ns = NetnsFixture::create("primitives", "client");
    let server_ns = NetnsFixture::create("primitives", "server");
    setup_veth_pair(&client_ns.name, &server_ns.name);

    let mut server = run_role(
        &server_ns,
        "bgp_unnumbered_kernel_socket_primitives",
        "server",
    );
    let mut client = run_role(
        &client_ns,
        "bgp_unnumbered_kernel_socket_primitives",
        "client",
    );
    let client_status = client.wait().expect("client wait");
    let server_status = server.wait().expect("server wait");
    assert!(
        client_status.success(),
        "client role failed: {client_status}"
    );
    assert!(
        server_status.success(),
        "server role failed: {server_status}"
    );
}
