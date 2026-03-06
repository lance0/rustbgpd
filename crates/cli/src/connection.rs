use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::metadata::AsciiMetadataValue;
use tonic::service::Interceptor;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Status};
use tower::service_fn;

use crate::error::CliError;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const AUTHORIZATION_HEADER: &str = "authorization";
const BEARER_PREFIX: &str = "Bearer ";

#[derive(Clone)]
pub(crate) struct Connection {
    channel: Channel,
    token: Option<AsciiMetadataValue>,
}

impl Connection {
    pub(crate) const fn new(channel: Channel, token: Option<AsciiMetadataValue>) -> Self {
        Self { channel, token }
    }

    pub(crate) fn channel(&self) -> Channel {
        self.channel.clone()
    }

    pub(crate) fn interceptor(&self) -> AuthInterceptor {
        AuthInterceptor {
            token: self.token.clone(),
        }
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AuthInterceptor {
    token: Option<AsciiMetadataValue>,
}

impl Interceptor for AuthInterceptor {
    fn call(&mut self, mut request: Request<()>) -> Result<Request<()>, Status> {
        if let Some(token) = self.token.clone() {
            request.metadata_mut().insert(AUTHORIZATION_HEADER, token);
        }
        Ok(request)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EndpointTarget {
    Tcp(String),
    Uds(PathBuf),
}

pub(crate) async fn connect(addr: &str, token_file: Option<&str>) -> Result<Connection, CliError> {
    let token = load_bearer_token(token_file)?;
    let channel = match parse_endpoint_target(addr)? {
        EndpointTarget::Tcp(uri) => connect_tcp(&uri).await?,
        EndpointTarget::Uds(path) => connect_uds(&path).await?,
    };
    Ok(Connection::new(channel, token))
}

fn parse_endpoint_target(addr: &str) -> Result<EndpointTarget, CliError> {
    if let Some(path) = addr.strip_prefix("unix://") {
        return parse_uds_target(path);
    }

    if addr.starts_with("http://") || addr.starts_with("https://") {
        return Ok(EndpointTarget::Tcp(addr.to_string()));
    }

    Ok(EndpointTarget::Tcp(format!("http://{addr}")))
}

fn parse_uds_target(path: &str) -> Result<EndpointTarget, CliError> {
    if path.is_empty() {
        return Err(CliError::Argument(
            "invalid address: unix:// path must not be empty".into(),
        ));
    }

    let path = PathBuf::from(path);
    if !path.is_absolute() {
        return Err(CliError::Argument(format!(
            "invalid address: unix socket path must be absolute: {}",
            path.display()
        )));
    }

    Ok(EndpointTarget::Uds(path))
}

fn load_bearer_token(token_file: Option<&str>) -> Result<Option<AsciiMetadataValue>, CliError> {
    let Some(token_file) = token_file else {
        return Ok(None);
    };

    let raw = fs::read_to_string(token_file)?;
    let token = raw.trim_end();
    if token.is_empty() {
        return Err(CliError::Argument(format!(
            "token file is empty: {token_file}"
        )));
    }

    let header = format!("{BEARER_PREFIX}{token}");
    let value = AsciiMetadataValue::try_from(header).map_err(|e| {
        CliError::Argument(format!(
            "invalid token file {token_file}: authorization value must be ASCII ({e})"
        ))
    })?;
    Ok(Some(value))
}

async fn connect_tcp(uri: &str) -> Result<Channel, CliError> {
    let endpoint = Endpoint::from_shared(uri.to_string())
        .map_err(|e| CliError::Argument(format!("invalid address: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    endpoint.connect().await.map_err(Into::into)
}

async fn connect_uds(path: &Path) -> Result<Channel, CliError> {
    let endpoint = Endpoint::try_from("http://[::]:50051")
        .map_err(|e| CliError::Argument(format!("invalid UDS endpoint: {e}")))?
        .connect_timeout(CONNECT_TIMEOUT);
    let path = path.to_path_buf();
    let connect = endpoint.connect_with_connector(service_fn(move |_: Uri| {
        let path = path.clone();
        async move {
            let stream = UnixStream::connect(path).await?;
            Ok::<_, std::io::Error>(TokioIo::new(stream))
        }
    }));
    let channel = tokio::time::timeout(CONNECT_TIMEOUT, connect)
        .await
        .map_err(|_| CliError::ConnectTimeout)??;
    Ok(channel)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tonic::metadata::MetadataValue;

    use super::*;

    #[test]
    fn parse_endpoint_target_accepts_plain_tcp_address() {
        assert_eq!(
            parse_endpoint_target("127.0.0.1:50051").unwrap(),
            EndpointTarget::Tcp("http://127.0.0.1:50051".into())
        );
    }

    #[test]
    fn parse_endpoint_target_preserves_http_uri() {
        assert_eq!(
            parse_endpoint_target("http://127.0.0.1:50051").unwrap(),
            EndpointTarget::Tcp("http://127.0.0.1:50051".into())
        );
    }

    #[test]
    fn parse_endpoint_target_accepts_unix_uri() {
        assert_eq!(
            parse_endpoint_target("unix:///tmp/rustbgpd.sock").unwrap(),
            EndpointTarget::Uds(PathBuf::from("/tmp/rustbgpd.sock"))
        );
    }

    #[test]
    fn parse_endpoint_target_rejects_relative_unix_uri() {
        let err = parse_endpoint_target("unix://tmp/rustbgpd.sock").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid address: unix socket path must be absolute: tmp/rustbgpd.sock"
        );
    }

    #[test]
    fn parse_endpoint_target_rejects_empty_unix_uri() {
        let err = parse_endpoint_target("unix://").unwrap_err();
        assert_eq!(
            err.to_string(),
            "invalid address: unix:// path must not be empty"
        );
    }

    #[test]
    fn auth_interceptor_injects_bearer_token() {
        let mut interceptor = AuthInterceptor {
            token: Some(MetadataValue::try_from("Bearer secret").unwrap()),
        };
        let request = interceptor.call(Request::new(())).unwrap();

        assert_eq!(
            request.metadata().get(AUTHORIZATION_HEADER).unwrap(),
            "Bearer secret"
        );
    }

    #[test]
    fn auth_interceptor_leaves_request_untouched_without_token() {
        let mut interceptor = AuthInterceptor::default();
        let request = interceptor.call(Request::new(())).unwrap();

        assert!(request.metadata().get(AUTHORIZATION_HEADER).is_none());
    }

    #[test]
    fn load_bearer_token_trims_trailing_whitespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.txt");
        fs::write(&path, "secret-token\n").unwrap();

        let token = load_bearer_token(Some(path.to_str().unwrap())).unwrap();

        assert_eq!(token.unwrap(), "Bearer secret-token");
    }

    #[test]
    fn load_bearer_token_rejects_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token.txt");
        fs::write(&path, "\n").unwrap();

        let err = load_bearer_token(Some(path.to_str().unwrap())).unwrap_err();

        assert_eq!(
            err.to_string(),
            format!("token file is empty: {}", path.display())
        );
    }
}
