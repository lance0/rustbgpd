use std::time::Duration;

use rustbgpd_transport::BgpListener;
use tokio::net::TcpStream;
use tokio::sync::mpsc;

#[tokio::test]
async fn socket2_backed_listener_accepts_tcp_connections() {
    let (accept_tx, mut accept_rx) = mpsc::channel(4);
    let listener = BgpListener::bind("127.0.0.1:0".parse().unwrap(), accept_tx)
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();

    let listener_task = tokio::spawn(listener.run());
    let client = TcpStream::connect(addr).await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_secs(2), accept_rx.recv())
        .await
        .expect("listener did not accept connection")
        .expect("accept channel closed");

    assert_eq!(
        accepted.peer_addr.ip(),
        std::net::IpAddr::from([127, 0, 0, 1])
    );
    assert_eq!(accepted.stream.local_addr().unwrap(), addr);
    assert!(accepted.tcp_ao_info.is_none());

    drop(client);
    listener_task.abort();
}
