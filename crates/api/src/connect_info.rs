//! gRPC listener connection metadata extensions.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tonic::transport::server::Connected;

use crate::authz_principal::{PrincipalExtractionError, principal_from_peer_certs};

/// Per-connection cache for the principal derived from a validated mTLS peer
/// certificate.
#[derive(Clone, Debug, Default)]
pub(crate) struct MtlsPrincipalCache {
    inner: Arc<OnceLock<Result<Arc<str>, PrincipalExtractionError>>>,
}

impl MtlsPrincipalCache {
    pub(crate) fn resolve<C>(&self, certs: &[C]) -> Result<Arc<str>, PrincipalExtractionError>
    where
        C: AsRef<[u8]>,
    {
        self.resolve_with(|| principal_from_peer_certs(certs).map(Arc::<str>::from))
    }

    fn resolve_with<F>(&self, resolver: F) -> Result<Arc<str>, PrincipalExtractionError>
    where
        F: FnOnce() -> Result<Arc<str>, PrincipalExtractionError>,
    {
        self.inner.get_or_init(resolver).clone()
    }
}

/// TCP connect info used by rustbgpd's gRPC listener.
#[derive(Clone, Debug)]
pub(crate) struct RustbgpdTcpConnectInfo {
    mtls_principal: MtlsPrincipalCache,
}

impl RustbgpdTcpConnectInfo {
    fn new() -> Self {
        Self {
            mtls_principal: MtlsPrincipalCache::default(),
        }
    }

    pub(crate) fn mtls_principal<C>(
        &self,
        certs: &[C],
    ) -> Result<Arc<str>, PrincipalExtractionError>
    where
        C: AsRef<[u8]>,
    {
        self.mtls_principal.resolve(certs)
    }
}

/// TCP stream wrapper that carries rustbgpd-specific connect info through
/// tonic's `Connected` extension path.
#[derive(Debug)]
pub(crate) struct RustbgpdTcpStream {
    inner: TcpStream,
    info: RustbgpdTcpConnectInfo,
}

impl RustbgpdTcpStream {
    pub(crate) fn new(inner: TcpStream) -> Self {
        let info = RustbgpdTcpConnectInfo::new();
        Self { inner, info }
    }
}

impl Connected for RustbgpdTcpStream {
    type ConnectInfo = RustbgpdTcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.info.clone()
    }
}

impl AsyncRead for RustbgpdTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for RustbgpdTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[test]
    fn mtls_principal_cache_reuses_successful_resolution() {
        let calls = AtomicUsize::new(0);
        let cache = MtlsPrincipalCache::default();
        let first = cache
            .resolve_with(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::<str>::from("rustbgpd://operator/alice"))
            })
            .unwrap();
        let second = cache
            .resolve_with(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::<str>::from("rustbgpd://operator/bob"))
            })
            .unwrap();

        assert_eq!(first.as_ref(), "rustbgpd://operator/alice");
        assert_eq!(second.as_ref(), "rustbgpd://operator/alice");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn mtls_principal_cache_reuses_failed_resolution() {
        let calls = AtomicUsize::new(0);
        let cache = MtlsPrincipalCache::default();
        let first = cache
            .resolve_with(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Err(PrincipalExtractionError::MissingPrincipal)
            })
            .unwrap_err();
        let second = cache
            .resolve_with(|| {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(Arc::<str>::from("rustbgpd://operator/alice"))
            })
            .unwrap_err();

        assert_eq!(first, PrincipalExtractionError::MissingPrincipal);
        assert_eq!(second, PrincipalExtractionError::MissingPrincipal);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
