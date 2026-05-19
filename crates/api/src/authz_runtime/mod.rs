//! Runtime ADR-0064 audit layer for gRPC method-tier decisions.
//!
//! This layer records the method tier that feeds ADR-0064 authorization,
//! enforces the per-listener method-tier cap plus optional
//! per-principal role ceilings, then forwards permitted requests to
//! the existing tonic services. Bearer-token authentication and
//! listener `AccessMode` checks remain in `server.rs` and the service
//! handlers.

mod context;
mod decision;
mod layer;

#[cfg(test)]
mod tests;

pub(crate) use context::BearerAuthSecret;
pub use context::{GrpcAuthAuditContext, GrpcAuthnKind};
pub use decision::{GrpcAuthAuditDecision, audit_decision_for_path};
pub use layer::{GrpcAuthzLayer, GrpcAuthzService};
