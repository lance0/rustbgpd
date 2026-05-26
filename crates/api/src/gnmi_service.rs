//! Read-only `OpenConfig` gNMI surface.

use std::pin::Pin;

use tokio_stream::Stream;
use tonic::{Request, Response, Status};

use crate::gnmi;

const GNMI_VERSION: &str = "0.10.0";

/// Read-only gNMI target for the supported `OpenConfig` operational-state subset.
#[derive(Clone, Debug, Default)]
pub struct GnmiService;

type SubscribeStream =
    Pin<Box<dyn Stream<Item = Result<gnmi::SubscribeResponse, Status>> + Send + 'static>>;

fn supported_models() -> Vec<gnmi::ModelData> {
    vec![
        gnmi::ModelData {
            name: "openconfig-network-instance".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "4.7.0".to_string(),
        },
        gnmi::ModelData {
            name: "openconfig-bgp".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "9.9.1".to_string(),
        },
        gnmi::ModelData {
            name: "openconfig-policy-types".to_string(),
            organization: "OpenConfig working group".to_string(),
            version: "3.3.0".to_string(),
        },
    ]
}

fn supported_encodings() -> Vec<i32> {
    vec![gnmi::Encoding::Json as i32, gnmi::Encoding::JsonIetf as i32]
}

#[tonic::async_trait]
impl gnmi::g_nmi_server::GNmi for GnmiService {
    async fn capabilities(
        &self,
        _request: Request<gnmi::CapabilityRequest>,
    ) -> Result<Response<gnmi::CapabilityResponse>, Status> {
        Ok(Response::new(gnmi::CapabilityResponse {
            supported_models: supported_models(),
            supported_encodings: supported_encodings(),
            g_nmi_version: GNMI_VERSION.to_string(),
            extension: Vec::new(),
        }))
    }

    async fn get(
        &self,
        _request: Request<gnmi::GetRequest>,
    ) -> Result<Response<gnmi::GetResponse>, Status> {
        Err(Status::unimplemented(
            "gNMI Get is not implemented in this slice",
        ))
    }

    async fn set(
        &self,
        _request: Request<gnmi::SetRequest>,
    ) -> Result<Response<gnmi::SetResponse>, Status> {
        Err(Status::unimplemented("gNMI Set is not supported"))
    }

    type SubscribeStream = SubscribeStream;

    async fn subscribe(
        &self,
        _request: Request<tonic::Streaming<gnmi::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        Err(Status::unimplemented(
            "gNMI Subscribe is not implemented in this slice",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnmi::g_nmi_server::GNmi as _;

    #[tokio::test]
    async fn capabilities_advertises_version_models_and_encodings() {
        let response = GnmiService
            .capabilities(Request::new(gnmi::CapabilityRequest {
                extension: Vec::new(),
            }))
            .await
            .unwrap()
            .into_inner();

        assert_eq!(response.g_nmi_version, GNMI_VERSION);
        assert_eq!(
            response.supported_encodings,
            vec![gnmi::Encoding::Json as i32, gnmi::Encoding::JsonIetf as i32]
        );
        let model_names = response
            .supported_models
            .iter()
            .map(|model| model.name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            model_names,
            vec![
                "openconfig-network-instance",
                "openconfig-bgp",
                "openconfig-policy-types"
            ]
        );
        let model_versions = response
            .supported_models
            .iter()
            .map(|model| {
                (
                    model.name.as_str(),
                    model.organization.as_str(),
                    model.version.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            model_versions,
            vec![
                (
                    "openconfig-network-instance",
                    "OpenConfig working group",
                    "4.7.0"
                ),
                ("openconfig-bgp", "OpenConfig working group", "9.9.1"),
                (
                    "openconfig-policy-types",
                    "OpenConfig working group",
                    "3.3.0"
                )
            ]
        );
    }

    #[tokio::test]
    async fn get_is_not_implemented_in_pr1() {
        let get_err = GnmiService
            .get(Request::new(gnmi::GetRequest {
                prefix: None,
                path: Vec::new(),
                r#type: gnmi::get_request::DataType::State as i32,
                encoding: gnmi::Encoding::JsonIetf as i32,
                use_models: Vec::new(),
                extension: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(get_err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn set_is_stably_closed() {
        let err = GnmiService
            .set(Request::new(gnmi::SetRequest {
                prefix: None,
                delete: Vec::new(),
                replace: Vec::new(),
                update: Vec::new(),
                extension: Vec::new(),
                union_replace: Vec::new(),
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
        assert!(err.message().contains("not supported"));
    }
}
