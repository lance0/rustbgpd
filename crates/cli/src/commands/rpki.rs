//! `rbgp rpki validate` — bounded route-origin validation diagnostics.

use std::fmt::Write as _;
use std::net::IpAddr;

use serde::Serialize;

use crate::connection::{Connection, read_rpc};
use crate::error::CliError;
use crate::output;
use crate::proto::rpki_service_client::RpkiServiceClient;
use crate::proto::{
    CoveringVrp, ListRpkiCachesRequest, ListRpkiCachesResponse, RouteOriginValidation,
    ValidateRouteOriginRequest, ValidateRouteOriginResponse,
};

#[derive(Debug, Serialize)]
struct JsonCache<'a> {
    address: &'a str,
    connected: bool,
    accepted: Option<JsonAcceptedCache>,
}

#[derive(Debug, Serialize)]
struct JsonAcceptedCache {
    protocol_version: Option<u32>,
    session_id: Option<u32>,
    serial: Option<u32>,
    vrp_v4_count: u64,
    vrp_v6_count: u64,
    aspa_count: u64,
    age_seconds: u64,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct JsonCoveringVrp {
    prefix: String,
    max_length: u32,
    origin_asn: u32,
    authorizes: bool,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct JsonValidation {
    prefix: String,
    origin_asn: u32,
    validation: String,
    complete: bool,
    omitted: u64,
    covering_vrps: Vec<JsonCoveringVrp>,
}

fn validation_label(value: i32) -> &'static str {
    match RouteOriginValidation::try_from(value).unwrap_or(RouteOriginValidation::Unspecified) {
        RouteOriginValidation::Valid => "valid",
        RouteOriginValidation::Invalid => "invalid",
        RouteOriginValidation::NotFound => "not_found",
        RouteOriginValidation::Unspecified => "unspecified",
    }
}

fn row_prefix(row: &CoveringVrp) -> String {
    format!("{}/{}", row.prefix, row.prefix_length)
}

fn to_json(response: &ValidateRouteOriginResponse) -> JsonValidation {
    JsonValidation {
        prefix: response.prefix.clone(),
        origin_asn: response.origin_asn,
        validation: validation_label(response.validation).to_string(),
        complete: response.complete,
        omitted: response.omitted,
        covering_vrps: response
            .covering_vrps
            .iter()
            .map(|row| JsonCoveringVrp {
                prefix: row_prefix(row),
                max_length: row.max_length,
                origin_asn: row.origin_asn,
                authorizes: row.authorizes,
            })
            .collect(),
    }
}

fn render_human(response: &ValidateRouteOriginResponse) -> String {
    let mut rendered = String::new();
    writeln!(rendered, "Prefix: {}", response.prefix).expect("writing to String cannot fail");
    writeln!(rendered, "Origin ASN: {}", response.origin_asn)
        .expect("writing to String cannot fail");
    writeln!(
        rendered,
        "Validation: {}",
        validation_label(response.validation)
    )
    .expect("writing to String cannot fail");
    if response.covering_vrps.is_empty() {
        writeln!(rendered, "Covering VRPs: none").expect("writing to String cannot fail");
    } else {
        writeln!(rendered, "Covering VRPs:").expect("writing to String cannot fail");
        writeln!(
            rendered,
            "{:<43} {:>10} {:>12} {:>10}",
            "Prefix", "MaxLength", "Origin ASN", "Authorizes"
        )
        .expect("writing to String cannot fail");
        for row in &response.covering_vrps {
            writeln!(
                rendered,
                "{:<43} {:>10} {:>12} {:>10}",
                row_prefix(row),
                row.max_length,
                row.origin_asn,
                if row.authorizes { "yes" } else { "no" }
            )
            .expect("writing to String cannot fail");
        }
    }
    if response.complete {
        writeln!(rendered, "Listing: complete").expect("writing to String cannot fail");
    } else {
        writeln!(
            rendered,
            "Listing: incomplete ({} omitted)",
            response.omitted
        )
        .expect("writing to String cannot fail");
    }
    rendered
}

fn split_prefix(prefix: &str) -> Result<(String, u32), CliError> {
    let (address, length) = prefix.split_once('/').ok_or_else(|| {
        CliError::Argument("PREFIX must be CIDR text such as 192.0.2.0/24".to_string())
    })?;
    if length.contains('/') {
        return Err(CliError::Argument(
            "PREFIX must contain exactly one slash".to_string(),
        ));
    }
    let address = address
        .parse::<IpAddr>()
        .map_err(|_| CliError::Argument("PREFIX address must be valid IPv4 or IPv6".to_string()))?;
    let length = length
        .parse::<u32>()
        .map_err(|_| CliError::Argument("PREFIX length must be an integer".to_string()))?;
    let valid = match address {
        IpAddr::V4(_) => length <= 32,
        IpAddr::V6(_) => length <= 128,
    };
    if !valid {
        return Err(CliError::Argument(format!(
            "PREFIX length {length} is out of range for {address}"
        )));
    }
    Ok((address.to_string(), length))
}

async fn fetch(
    connection: Connection,
    prefix: &str,
    origin_asn: u32,
) -> Result<ValidateRouteOriginResponse, CliError> {
    let (prefix, prefix_length) = split_prefix(prefix)?;
    let mut client =
        RpkiServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    Ok(read_rpc(
        "ValidateRouteOrigin",
        client.validate_route_origin(ValidateRouteOriginRequest {
            prefix,
            prefix_length: Some(prefix_length),
            origin_asn,
        }),
    )
    .await?
    .into_inner())
}

/// Validate one route prefix and origin against the daemon's current VRPs.
pub async fn validate(
    connection: Connection,
    prefix: &str,
    origin_asn: u32,
    json: bool,
) -> Result<(), CliError> {
    let response = fetch(connection, prefix, origin_asn).await?;
    if json {
        output::print_json_pretty(&to_json(&response))?;
    } else {
        output::print_text(&render_human(&response))?;
    }
    Ok(())
}

fn render_caches_human(response: &ListRpkiCachesResponse) -> String {
    let mut rendered = String::new();
    if response.caches.is_empty() {
        rendered.push_str("RPKI caches: none\n");
    } else {
        writeln!(
            rendered,
            "{:<45} {:<12} {:>10} {:>10} {:>10} {:>10}",
            "Address", "State", "VRP v4", "VRP v6", "ASPAs", "Age(s)"
        )
        .unwrap();
        for cache in &response.caches {
            if let Some(accepted) = &cache.accepted {
                writeln!(
                    rendered,
                    "{:<45} {:<12} {:>10} {:>10} {:>10} {:>10}",
                    cache.address,
                    if cache.connected {
                        "connected"
                    } else {
                        "retained"
                    },
                    accepted.vrp_v4_count,
                    accepted.vrp_v6_count,
                    accepted.aspa_count,
                    accepted.age_seconds
                )
                .unwrap();
            } else {
                writeln!(
                    rendered,
                    "{:<45} {:<12} {:>10} {:>10} {:>10} {:>10}",
                    cache.address,
                    if cache.connected {
                        "syncing"
                    } else {
                        "disconnected"
                    },
                    "-",
                    "-",
                    "-",
                    "-"
                )
                .unwrap();
            }
        }
    }
    if response.complete {
        rendered.push_str("Listing: complete\n");
    } else {
        writeln!(
            rendered,
            "Listing: incomplete ({} omitted)",
            response.omitted
        )
        .unwrap();
    }
    rendered
}

fn caches_json(response: &ListRpkiCachesResponse) -> serde_json::Value {
    let rows: Vec<_> = response
        .caches
        .iter()
        .map(|cache| JsonCache {
            address: &cache.address,
            connected: cache.connected,
            accepted: cache.accepted.as_ref().map(|state| JsonAcceptedCache {
                protocol_version: state.protocol_version,
                session_id: state.session_id,
                serial: state.serial,
                vrp_v4_count: state.vrp_v4_count,
                vrp_v6_count: state.vrp_v6_count,
                aspa_count: state.aspa_count,
                age_seconds: state.age_seconds,
            }),
        })
        .collect();
    serde_json::json!({ "caches": rows, "complete": response.complete, "omitted": response.omitted })
}

pub async fn caches(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        RpkiServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let response = read_rpc("ListCaches", client.list_caches(ListRpkiCachesRequest {}))
        .await?
        .into_inner();
    if json {
        output::print_json_pretty(&caches_json(&response))?;
    } else {
        output::print_text(&render_caches_human(&response))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tokio::net::TcpListener;
    use tokio::sync::Mutex;
    use tokio_stream::wrappers::TcpListenerStream;
    use tonic::transport::Server;
    use tonic::{Request, Response, Status};

    use crate::connection::connect;
    use rustbgpd_api::proto as server_proto;
    use rustbgpd_api::proto::rpki_service_server::{RpkiService, RpkiServiceServer};

    use super::*;

    fn response() -> ValidateRouteOriginResponse {
        ValidateRouteOriginResponse {
            prefix: "192.0.2.0/24".to_string(),
            origin_asn: 64_496,
            validation: RouteOriginValidation::Valid as i32,
            complete: false,
            omitted: 2,
            covering_vrps: vec![
                CoveringVrp {
                    prefix: "192.0.2.0".to_string(),
                    prefix_length: 24,
                    max_length: 24,
                    origin_asn: 64_496,
                    authorizes: true,
                },
                CoveringVrp {
                    prefix: "192.0.0.0".to_string(),
                    prefix_length: 16,
                    max_length: 24,
                    origin_asn: 0,
                    authorizes: false,
                },
            ],
        }
    }

    #[test]
    fn parser_requires_one_valid_cidr() {
        assert_eq!(
            split_prefix("192.0.2.129/24").unwrap(),
            ("192.0.2.129".to_string(), 24)
        );
        assert_eq!(
            split_prefix("2001:db8::1/0").unwrap(),
            ("2001:db8::1".to_string(), 0)
        );
        for invalid in [
            "192.0.2.0",
            "192.0.2.0/24/1",
            "192.0.2.0/nope",
            "192.0.2.0/33",
            "2001:db8::/129",
        ] {
            assert!(split_prefix(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn json_shape_is_exact_and_ordered() {
        assert_eq!(
            serde_json::to_string(&to_json(&response())).unwrap(),
            concat!(
                r#"{"prefix":"192.0.2.0/24","origin_asn":64496,"validation":"valid","complete":false,"omitted":2,"covering_vrps":["#,
                r#"{"prefix":"192.0.2.0/24","max_length":24,"origin_asn":64496,"authorizes":true},"#,
                r#"{"prefix":"192.0.0.0/16","max_length":24,"origin_asn":0,"authorizes":false}]}"#
            )
        );
    }

    #[test]
    fn human_output_is_exact_and_deterministic() {
        assert_eq!(
            render_human(&response()),
            concat!(
                "Prefix: 192.0.2.0/24\n",
                "Origin ASN: 64496\n",
                "Validation: valid\n",
                "Covering VRPs:\n",
                "Prefix                                       MaxLength   Origin ASN Authorizes\n",
                "192.0.2.0/24                                        24        64496        yes\n",
                "192.0.0.0/16                                        24            0         no\n",
                "Listing: incomplete (2 omitted)\n",
            )
        );
        let empty = ValidateRouteOriginResponse {
            prefix: "198.51.100.0/24".to_string(),
            origin_asn: 64_497,
            validation: RouteOriginValidation::NotFound as i32,
            complete: true,
            ..Default::default()
        };
        assert!(render_human(&empty).contains("Covering VRPs: none\nListing: complete\n"));
    }

    #[test]
    fn cache_inventory_human_and_json_are_presence_aware() {
        let response = ListRpkiCachesResponse {
            caches: vec![crate::proto::RpkiCacheState {
                address: "192.0.2.1:3323".to_string(),
                connected: false,
                accepted: Some(crate::proto::AcceptedRpkiCacheState {
                    protocol_version: Some(2),
                    session_id: Some(7),
                    serial: Some(11),
                    vrp_v4_count: 10,
                    vrp_v6_count: 20,
                    aspa_count: 3,
                    age_seconds: 4,
                }),
            }],
            complete: false,
            omitted: 1,
        };
        let human = render_caches_human(&response);
        assert!(human.contains("192.0.2.1:3323"));
        assert!(human.contains("retained"));
        assert!(human.ends_with("Listing: incomplete (1 omitted)\n"));
        assert_eq!(
            caches_json(&response),
            serde_json::json!({
                "caches": [{
                    "address": "192.0.2.1:3323", "connected": false,
                    "accepted": { "protocol_version": 2, "session_id": 7, "serial": 11,
                        "vrp_v4_count": 10, "vrp_v6_count": 20, "aspa_count": 3, "age_seconds": 4 }
                }],
                "complete": false, "omitted": 1
            })
        );
        assert_eq!(
            render_caches_human(&ListRpkiCachesResponse::default()),
            "RPKI caches: none\nListing: incomplete (0 omitted)\n"
        );

        let unavailable = ListRpkiCachesResponse {
            caches: vec![crate::proto::RpkiCacheState {
                address: "[2001:db8::1]:3323".to_string(),
                connected: false,
                accepted: None,
            }],
            complete: true,
            omitted: 0,
        };
        assert_eq!(
            render_caches_human(&unavailable),
            concat!(
                "Address                                       State            VRP v4     VRP v6      ASPAs     Age(s)\n",
                "[2001:db8::1]:3323                            disconnected          -          -          -          -\n",
                "Listing: complete\n",
            )
        );
    }

    #[derive(Clone)]
    struct MockRpki {
        request: Arc<Mutex<Option<server_proto::ValidateRouteOriginRequest>>>,
    }

    #[tonic::async_trait]
    impl RpkiService for MockRpki {
        async fn list_caches(
            &self,
            _request: Request<server_proto::ListRpkiCachesRequest>,
        ) -> Result<Response<server_proto::ListRpkiCachesResponse>, Status> {
            Ok(Response::new(
                server_proto::ListRpkiCachesResponse::default(),
            ))
        }

        async fn validate_route_origin(
            &self,
            request: Request<server_proto::ValidateRouteOriginRequest>,
        ) -> Result<Response<server_proto::ValidateRouteOriginResponse>, Status> {
            *self.request.lock().await = Some(request.into_inner());
            Ok(Response::new(server_proto::ValidateRouteOriginResponse {
                prefix: "192.0.2.0/24".to_string(),
                origin_asn: 64_496,
                validation: server_proto::RouteOriginValidation::Valid as i32,
                complete: false,
                omitted: 2,
                covering_vrps: vec![
                    server_proto::CoveringVrp {
                        prefix: "192.0.2.0".to_string(),
                        prefix_length: 24,
                        max_length: 24,
                        origin_asn: 64_496,
                        authorizes: true,
                    },
                    server_proto::CoveringVrp {
                        prefix: "192.0.0.0".to_string(),
                        prefix_length: 16,
                        max_length: 24,
                        origin_asn: 0,
                        authorizes: false,
                    },
                ],
            }))
        }
    }

    #[tokio::test]
    async fn live_mock_rpc_sends_presence_aware_request() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let captured = Arc::new(Mutex::new(None));
        let server = tokio::spawn(
            Server::builder()
                .add_service(RpkiServiceServer::new(MockRpki {
                    request: Arc::clone(&captured),
                }))
                .serve_with_incoming(TcpListenerStream::new(listener)),
        );
        let connection = connect(&format!("http://{address}"), None).await.unwrap();

        let actual = fetch(connection, "192.0.2.129/24", 64_496).await.unwrap();
        assert_eq!(actual, response());
        assert_eq!(
            *captured.lock().await,
            Some(server_proto::ValidateRouteOriginRequest {
                prefix: "192.0.2.129".to_string(),
                prefix_length: Some(24),
                origin_asn: 64_496,
            })
        );
        server.abort();
    }
}
