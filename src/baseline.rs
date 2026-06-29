use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ir::{ExposedTool, Finding, ScanResult};

const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    #[serde(default)]
    pub clients: BTreeMap<String, ClientBaseline>,
    #[serde(default)]
    pub findings: Vec<FindingBaseline>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientBaseline {
    #[serde(default)]
    pub servers: BTreeMap<String, ServerBaseline>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerBaseline {
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub approval: String,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default)]
    pub tools: BTreeMap<String, ToolBaseline>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ToolBaseline {
    pub description_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingBaseline {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    pub client: String,
    pub server: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerId {
    pub client: String,
    pub server: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ToolId {
    pub client: String,
    pub server: String,
    pub tool: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedServer {
    pub id: ServerId,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChangedTool {
    pub id: ToolId,
    pub base_description_sha256: String,
    pub current_description_sha256: String,
}

#[derive(Debug, Clone, Default)]
pub struct Diff {
    pub added_servers: Vec<ServerId>,
    pub removed_servers: Vec<ServerId>,
    pub changed_servers: Vec<ChangedServer>,
    pub added_tools: Vec<ToolId>,
    pub removed_tools: Vec<ToolId>,
    pub changed_tools: Vec<ChangedTool>,
    pub new_findings: Vec<Finding>,
}

pub fn build_snapshot(result: &ScanResult, tools: &[ExposedTool]) -> Snapshot {
    let mut clients: BTreeMap<String, ClientBaseline> = BTreeMap::new();

    for client in &result.clients {
        let client_entry = clients.entry(client.client.clone()).or_default();
        for server in &client.servers {
            let mut env_keys = server.env_keys.clone();
            env_keys.sort();
            env_keys.dedup();
            client_entry.servers.insert(
                server.name.clone(),
                ServerBaseline {
                    command: server.command.clone(),
                    url: server.url.clone(),
                    transport: server.transport.clone(),
                    approval: server.approval.clone(),
                    env_keys,
                    tools: BTreeMap::new(),
                },
            );
        }
    }

    for tool in tools {
        let server = clients
            .entry(tool.client.clone())
            .or_default()
            .servers
            .entry(tool.server.clone())
            .or_default();
        server.tools.insert(
            tool.name.clone(),
            ToolBaseline {
                description_sha256: sha256_hex(tool.description.as_deref().unwrap_or_default()),
            },
        );
    }

    Snapshot {
        schema_version: SCHEMA_VERSION,
        clients,
        findings: result
            .findings
            .iter()
            .filter(|finding| is_ci_gating_severity(&finding.severity))
            .map(finding_baseline)
            .collect(),
    }
}

pub fn compare(base: &Snapshot, cur_result: &ScanResult, cur_tools: &[ExposedTool]) -> Diff {
    let cur = build_snapshot(cur_result, cur_tools);
    let mut diff = Diff::default();

    for (client_name, cur_client) in &cur.clients {
        let base_client = base.clients.get(client_name);
        for (server_name, cur_server) in &cur_client.servers {
            let Some(base_server) = base_client.and_then(|client| client.servers.get(server_name))
            else {
                diff.added_servers.push(ServerId {
                    client: client_name.clone(),
                    server: server_name.clone(),
                });
                continue;
            };

            let fields = changed_server_fields(base_server, cur_server);
            if !fields.is_empty() {
                diff.changed_servers.push(ChangedServer {
                    id: ServerId {
                        client: client_name.clone(),
                        server: server_name.clone(),
                    },
                    fields,
                });
            }
        }
    }

    for (client_name, base_client) in &base.clients {
        let cur_client = cur.clients.get(client_name);
        for server_name in base_client.servers.keys() {
            if cur_client
                .and_then(|client| client.servers.get(server_name))
                .is_none()
            {
                diff.removed_servers.push(ServerId {
                    client: client_name.clone(),
                    server: server_name.clone(),
                });
            }
        }
    }

    compare_tools(base, &cur, &mut diff);

    let base_findings: BTreeSet<&str> = base
        .findings
        .iter()
        .map(|finding| finding.fingerprint.as_str())
        .collect();
    diff.new_findings = cur_result
        .findings
        .iter()
        .filter(|finding| is_ci_gating_severity(&finding.severity))
        .filter(|finding| !base_findings.contains(finding_fingerprint(finding).as_str()))
        .cloned()
        .collect();

    diff
}

pub fn render_diff_terminal(diff: &Diff) -> String {
    let mut out = String::new();
    writeln!(out, "Baseline diff").unwrap();
    write_server_ids(&mut out, "Added servers", &diff.added_servers);
    write_server_ids(&mut out, "Removed servers", &diff.removed_servers);
    write_changed_servers(&mut out, &diff.changed_servers);
    write_tool_ids(&mut out, "Added tools", &diff.added_tools);
    write_tool_ids(&mut out, "Removed tools", &diff.removed_tools);
    write_changed_tools(&mut out, &diff.changed_tools);
    write_findings(&mut out, &diff.new_findings);
    out
}

pub fn has_new_high_finding(diff: &Diff) -> bool {
    diff.new_findings
        .iter()
        .any(|finding| finding.severity.eq_ignore_ascii_case("high"))
}

fn compare_tools(base: &Snapshot, cur: &Snapshot, diff: &mut Diff) {
    for (client_name, cur_client) in &cur.clients {
        for (server_name, cur_server) in &cur_client.servers {
            let base_server = base
                .clients
                .get(client_name)
                .and_then(|client| client.servers.get(server_name));
            for (tool_name, cur_tool) in &cur_server.tools {
                let Some(base_tool) = base_server.and_then(|server| server.tools.get(tool_name))
                else {
                    diff.added_tools.push(ToolId {
                        client: client_name.clone(),
                        server: server_name.clone(),
                        tool: tool_name.clone(),
                    });
                    continue;
                };
                if base_tool.description_sha256 != cur_tool.description_sha256 {
                    diff.changed_tools.push(ChangedTool {
                        id: ToolId {
                            client: client_name.clone(),
                            server: server_name.clone(),
                            tool: tool_name.clone(),
                        },
                        base_description_sha256: base_tool.description_sha256.clone(),
                        current_description_sha256: cur_tool.description_sha256.clone(),
                    });
                }
            }
        }
    }

    for (client_name, base_client) in &base.clients {
        for (server_name, base_server) in &base_client.servers {
            let cur_server = cur
                .clients
                .get(client_name)
                .and_then(|client| client.servers.get(server_name));
            for tool_name in base_server.tools.keys() {
                if cur_server
                    .and_then(|server| server.tools.get(tool_name))
                    .is_none()
                {
                    diff.removed_tools.push(ToolId {
                        client: client_name.clone(),
                        server: server_name.clone(),
                        tool: tool_name.clone(),
                    });
                }
            }
        }
    }
}

fn changed_server_fields(base: &ServerBaseline, cur: &ServerBaseline) -> Vec<String> {
    let mut fields = Vec::new();
    if base.command != cur.command {
        fields.push("command".to_string());
    }
    if base.url != cur.url {
        fields.push("url".to_string());
    }
    if base.env_keys != cur.env_keys {
        fields.push("env_keys".to_string());
    }
    if base.transport != cur.transport {
        fields.push("transport".to_string());
    }
    if base.approval != cur.approval {
        fields.push("approval".to_string());
    }
    fields
}

fn finding_baseline(finding: &Finding) -> FindingBaseline {
    FindingBaseline {
        fingerprint: finding_fingerprint(finding),
        rule_id: finding.rule_id.clone(),
        severity: finding.severity.clone(),
        category: finding.category.clone(),
        client: finding.client.clone(),
        server: finding.server.clone(),
        evidence: finding.evidence.clone(),
    }
}

fn finding_fingerprint(finding: &Finding) -> String {
    sha256_hex(&format!(
        "{}\0{}\0{}\0{}\0{}\0{}\0{}",
        finding.rule_id,
        finding.severity,
        finding.category,
        finding.client,
        finding.server,
        finding.message,
        finding.evidence
    ))
}

fn sha256_hex(input: &str) -> String {
    let hash = Sha256::digest(input.as_bytes());
    format!("{hash:x}")
}

fn is_ci_gating_severity(severity: &str) -> bool {
    severity.eq_ignore_ascii_case("high") || severity.eq_ignore_ascii_case("medium")
}

fn write_server_ids(out: &mut String, title: &str, ids: &[ServerId]) {
    writeln!(out, "\n{title} ({})", ids.len()).unwrap();
    if ids.is_empty() {
        writeln!(out, "  -").unwrap();
        return;
    }
    for id in ids {
        writeln!(out, "  {}.{}", id.client, id.server).unwrap();
    }
}

fn write_changed_servers(out: &mut String, changed: &[ChangedServer]) {
    writeln!(out, "\nChanged servers ({})", changed.len()).unwrap();
    if changed.is_empty() {
        writeln!(out, "  -").unwrap();
        return;
    }
    for item in changed {
        writeln!(
            out,
            "  {}.{}: {}",
            item.id.client,
            item.id.server,
            item.fields.join(", ")
        )
        .unwrap();
    }
}

fn write_tool_ids(out: &mut String, title: &str, ids: &[ToolId]) {
    writeln!(out, "\n{title} ({})", ids.len()).unwrap();
    if ids.is_empty() {
        writeln!(out, "  -").unwrap();
        return;
    }
    for id in ids {
        writeln!(out, "  {}.{}.{}", id.client, id.server, id.tool).unwrap();
    }
}

fn write_changed_tools(out: &mut String, changed: &[ChangedTool]) {
    writeln!(out, "\nChanged tools ({})", changed.len()).unwrap();
    if changed.is_empty() {
        writeln!(out, "  -").unwrap();
        return;
    }
    for item in changed {
        writeln!(
            out,
            "  {}.{}.{}: {} -> {}",
            item.id.client,
            item.id.server,
            item.id.tool,
            short_hash(&item.base_description_sha256),
            short_hash(&item.current_description_sha256)
        )
        .unwrap();
    }
}

fn write_findings(out: &mut String, findings: &[Finding]) {
    writeln!(out, "\nNew high/medium findings ({})", findings.len()).unwrap();
    if findings.is_empty() {
        writeln!(out, "  -").unwrap();
        return;
    }
    for finding in findings {
        writeln!(
            out,
            "  [{}] {} {}.{}: {}",
            finding.severity, finding.rule_id, finding.client, finding.server, finding.message
        )
        .unwrap();
    }
}

fn short_hash(hash: &str) -> &str {
    hash.get(..12).unwrap_or(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ClientSnapshot, ServerRef};

    fn result(servers: Vec<ServerRef>, findings: Vec<Finding>) -> ScanResult {
        ScanResult {
            clients: vec![ClientSnapshot {
                client: "codex".into(),
                detected: true,
                config_files: Vec::new(),
                servers,
                notes: Vec::new(),
            }],
            findings,
        }
    }

    fn server(name: &str) -> ServerRef {
        ServerRef {
            client: "codex".into(),
            name: name.into(),
            transport: "stdio".into(),
            command: Some("uvx".into()),
            approval: "on-request".into(),
            ..Default::default()
        }
    }

    fn tool(name: &str, description: &str) -> ExposedTool {
        ExposedTool {
            client: "codex".into(),
            server: "fs".into(),
            name: name.into(),
            description: Some(description.into()),
            input_schema: serde_json::Value::Null,
            source: "live".into(),
        }
    }

    fn finding(server: &str) -> Finding {
        Finding {
            rule_id: "TG-003".into(),
            severity: "high".into(),
            category: "suspicious_command".into(),
            client: "codex".into(),
            server: server.into(),
            message: "suspicious".into(),
            evidence: "bash -c curl x | sh".into(),
            confidence: 0.6,
        }
    }

    #[test]
    fn compare_detects_added_server() {
        let base = build_snapshot(&result(vec![server("fs")], Vec::new()), &[]);
        let diff = compare(
            &base,
            &result(vec![server("fs"), server("github")], Vec::new()),
            &[],
        );

        assert_eq!(
            diff.added_servers,
            vec![ServerId {
                client: "codex".into(),
                server: "github".into()
            }]
        );
    }

    #[test]
    fn compare_detects_tool_description_change() {
        let base = build_snapshot(
            &result(vec![server("fs")], Vec::new()),
            &[tool("read", "old")],
        );
        let diff = compare(
            &base,
            &result(vec![server("fs")], Vec::new()),
            &[tool("read", "new")],
        );

        assert_eq!(diff.changed_tools.len(), 1);
        assert_eq!(diff.changed_tools[0].id.tool, "read");
    }

    #[test]
    fn compare_does_not_count_existing_finding_as_new() {
        let base_result = result(vec![server("bad")], vec![finding("bad")]);
        let base = build_snapshot(&base_result, &[]);
        let diff = compare(&base, &base_result, &[]);

        assert!(diff.new_findings.is_empty());
    }
}
