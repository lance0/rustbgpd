//! `rbgp fib-table ...` — runtime `[[fib_tables]]` CRUD.
//!
//! Wraps RibService's `SetFibTable` / `DeleteFibTable` / `ListFibTables`.
//! `set` is a create-or-replace upsert keyed on table name (the request carries
//! the full table definition, not a patch); `delete` removes by name. Both
//! hot-apply through the FIB reconciler and persist to the TOML config, and
//! require the reconciler to be running (at least one table present at startup).

use serde::Serialize;

use crate::connection::Connection;
use crate::error::CliError;
use crate::output;
use crate::proto::rib_service_client::RibServiceClient;
use crate::proto::{
    DeleteFibTableRequest, FibTableConfig, ListFibTablesRequest, ListFibTablesResponse,
    SetFibTableRequest,
};

#[derive(Debug, Serialize)]
struct JsonFibTable {
    name: String,
    table_id: u32,
    metric: u32,
    families: Vec<String>,
    allowed_peer_groups: Vec<String>,
    allowed_neighbors: Vec<String>,
    max_routes: Option<u32>,
    maximum_paths: Option<u32>,
    maximum_paths_ebgp: Option<u32>,
    maximum_paths_ibgp: Option<u32>,
}

#[derive(Debug, Serialize)]
struct JsonFibTableList {
    runtime_available: bool,
    tables: Vec<JsonFibTable>,
}

impl From<&FibTableConfig> for JsonFibTable {
    fn from(t: &FibTableConfig) -> Self {
        Self {
            name: t.name.clone(),
            table_id: t.table_id,
            metric: t.metric,
            families: t.families.clone(),
            allowed_peer_groups: t.allowed_peer_groups.clone(),
            allowed_neighbors: t.allowed_neighbors.clone(),
            max_routes: t.max_routes,
            maximum_paths: t.maximum_paths,
            maximum_paths_ebgp: t.maximum_paths_ebgp,
            maximum_paths_ibgp: t.maximum_paths_ibgp,
        }
    }
}

fn render(resp: &ListFibTablesResponse, json: bool) -> Result<(), CliError> {
    if json {
        let out = JsonFibTableList {
            runtime_available: resp.runtime_available,
            tables: resp.tables.iter().map(JsonFibTable::from).collect(),
        };
        output::print_json_pretty(&out)?;
        return Ok(());
    }
    if !resp.runtime_available {
        println!(
            "FIB reconciler not running (no [[fib_tables]] at startup, or non-Linux / netlink \
             unavailable); a restart is required to start it."
        );
    }
    if resp.tables.is_empty() {
        println!("No FIB tables configured");
        return Ok(());
    }
    println!(
        "{:<16} {:<9} {:<7} {:<24} MAX_ROUTES",
        "NAME", "TABLE_ID", "METRIC", "FAMILIES"
    );
    for t in &resp.tables {
        let families = if t.families.is_empty() {
            "(default)".to_string()
        } else {
            t.families.join(",")
        };
        let max_routes = t
            .max_routes
            .map_or_else(|| "-".to_string(), |m| m.to_string());
        println!(
            "{:<16} {:<9} {:<7} {:<24} {}",
            t.name, t.table_id, t.metric, families, max_routes
        );
    }
    Ok(())
}

pub async fn list(connection: Connection, json: bool) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .list_fib_tables(ListFibTablesRequest {})
        .await?
        .into_inner();
    render(&resp, json)
}

#[allow(
    clippy::too_many_arguments,
    reason = "CLI arguments map directly to one FIB-table request"
)]
pub async fn set(
    connection: Connection,
    name: &str,
    table_id: u32,
    metric: u32,
    families: Vec<String>,
    allowed_peer_groups: Vec<String>,
    allowed_neighbors: Vec<String>,
    max_routes: Option<u32>,
    maximum_paths: Option<u32>,
    maximum_paths_ebgp: Option<u32>,
    maximum_paths_ibgp: Option<u32>,
    json: bool,
) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .set_fib_table(SetFibTableRequest {
            table: Some(FibTableConfig {
                name: name.to_string(),
                table_id,
                metric,
                families,
                allowed_peer_groups,
                allowed_neighbors,
                max_routes,
                maximum_paths,
                maximum_paths_ebgp,
                maximum_paths_ibgp,
            }),
        })
        .await?
        .into_inner();
    if json {
        render(&resp, true)?;
    } else {
        println!(
            "FIB table {name} applied ({} table(s) now active)",
            resp.tables.len()
        );
    }
    Ok(())
}

pub async fn delete(connection: Connection, name: &str, json: bool) -> Result<(), CliError> {
    let mut client =
        RibServiceClient::with_interceptor(connection.channel(), connection.interceptor());
    let resp = client
        .delete_fib_table(DeleteFibTableRequest {
            name: name.to_string(),
        })
        .await?
        .into_inner();
    if json {
        render(&resp, true)?;
    } else {
        println!(
            "FIB table {name} deleted ({} table(s) now active)",
            resp.tables.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connection::connect;
    use crate::test_support::spawn_mock_server;

    #[tokio::test]
    async fn list_renders_tables() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        list(connection, true).await.unwrap();
    }

    #[tokio::test]
    async fn set_sends_full_table() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        set(
            connection,
            "edge",
            1000,
            200,
            vec!["ipv4_unicast".to_string()],
            vec![],
            vec![],
            Some(50_000),
            None,
            None,
            None,
            true,
        )
        .await
        .unwrap();
        let captured = server
            .state
            .last_set_fib_table
            .lock()
            .await
            .clone()
            .unwrap();
        let table = captured.table.unwrap();
        assert_eq!(table.name, "edge");
        assert_eq!(table.table_id, 1000);
        assert_eq!(table.metric, 200);
        assert_eq!(table.families, vec!["ipv4_unicast"]);
        assert_eq!(table.allowed_peer_groups, Vec::<String>::new());
        assert_eq!(table.allowed_neighbors, Vec::<String>::new());
        assert_eq!(table.max_routes, Some(50_000));
        assert_eq!(table.maximum_paths, None);
        assert_eq!(table.maximum_paths_ebgp, None);
        assert_eq!(table.maximum_paths_ibgp, None);
    }

    #[tokio::test]
    async fn delete_sends_name() {
        let server = spawn_mock_server(None).await;
        let connection = connect(&server.addr, None).await.unwrap();
        delete(connection, "edge", true).await.unwrap();
        let captured = server
            .state
            .last_delete_fib_table
            .lock()
            .await
            .clone()
            .unwrap();
        assert_eq!(captured.name, "edge");
    }
}
