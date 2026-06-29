//! SARIF 2.1.0 report rendering.

use serde_json::{Value, json};

use crate::ir::{ExposedTool, Finding, FlowEdge, ScanResult};

use super::INFORMATION_URI;

const RULES: &[(&str, &str, &str)] = &[
    (
        "TG-001",
        "auto-approve",
        "Tools are auto-approved; the agent may call them without confirmation.",
    ),
    ("TG-002", "disabled-server", "Server is disabled in config."),
    (
        "TG-003",
        "suspicious-command",
        "Launch command/args match a suspicious pattern.",
    ),
    (
        "TG-004",
        "secret-env",
        "Server receives a secret-like environment variable.",
    ),
    (
        "TG-005",
        "remote-transport",
        "Remote MCP transport; descriptions are network-controlled.",
    ),
    (
        "TG-101",
        "hidden-stealth-directive",
        "Tool description hides a stealth directive from the user.",
    ),
    (
        "TG-102",
        "cross-tool-exfil-call",
        "Tool description instructs the model to call another (sink) tool.",
    ),
    (
        "TG-103",
        "sensitive-path-ref",
        "Tool description references a sensitive path or secret.",
    ),
];

pub fn render_scan_sarif(result: &ScanResult) -> String {
    serde_json::to_string_pretty(&build(&result.findings)).expect("SARIF is JSON-serializable")
}

pub fn render_live_sarif(
    _tools: &[ExposedTool],
    findings: &[Finding],
    _edges: &[FlowEdge],
) -> String {
    serde_json::to_string_pretty(&build(findings)).expect("SARIF is JSON-serializable")
}

fn build(findings: &[Finding]) -> Value {
    let mut rule_ids: Vec<&str> = Vec::new();
    for f in findings {
        if !rule_ids.contains(&f.rule_id.as_str()) {
            rule_ids.push(&f.rule_id);
        }
    }

    let rules = rule_ids
        .iter()
        .map(|rid| {
            let (name, short) = rule_meta(rid);
            json!({
                "id": rid,
                "name": name,
                "shortDescription": {"text": short},
                "properties": {"tags": ["security", "mcp", "agent"]}
            })
        })
        .collect::<Vec<_>>();

    let results = findings
        .iter()
        .map(|f| {
            json!({
                "ruleId": f.rule_id,
                "level": level(&f.severity),
                "message": {"text": f.message},
                "locations": [{
                    "logicalLocation": {"fullyQualifiedName": format!("{}/{}", f.client, f.server)}
                }],
                "fingerprints": {"primary": fingerprint(f)}
            })
        })
        .collect::<Vec<_>>();

    json!({
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/cs01/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "ToolGlass",
                    "informationUri": INFORMATION_URI,
                    "rules": rules
                }
            },
            "results": results
        }]
    })
}

fn rule_meta(rule_id: &str) -> (&str, &str) {
    RULES
        .iter()
        .find(|(id, _, _)| *id == rule_id)
        .map(|(_, name, short)| (*name, *short))
        .unwrap_or((rule_id, rule_id))
}

fn level(severity: &str) -> &'static str {
    match severity {
        "high" => "error",
        "medium" => "warning",
        "low" | "info" => "note",
        _ => "note",
    }
}

fn fingerprint(finding: &Finding) -> String {
    let text = format!(
        "{}\0{}\0{}\0{}\0{}",
        finding.rule_id, finding.client, finding.server, finding.message, finding.evidence
    );
    format!("{:016x}", fnv1a64(text.as_bytes()))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for b in bytes {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Finding, ScanResult};

    #[test]
    fn sarif_dedupes_rules_and_maps_levels() {
        let result = ScanResult {
            clients: vec![],
            findings: vec![
                finding("TG-001", "medium"),
                finding("TG-001", "medium"),
                finding("TG-003", "high"),
                finding("TG-005", "low"),
            ],
        };

        let parsed: Value = serde_json::from_str(&render_scan_sarif(&result)).unwrap();
        let run = &parsed["runs"][0];
        assert_eq!(run["tool"]["driver"]["informationUri"], INFORMATION_URI);
        assert_eq!(run["tool"]["driver"]["rules"].as_array().unwrap().len(), 3);
        assert_eq!(run["results"][0]["level"], "warning");
        assert_eq!(run["results"][3]["level"], "note");
    }

    fn finding(rule_id: &str, severity: &str) -> Finding {
        Finding {
            rule_id: rule_id.into(),
            severity: severity.into(),
            category: "test".into(),
            client: "codex".into(),
            server: "srv".into(),
            message: format!("{rule_id} message"),
            evidence: "evidence".into(),
            confidence: 0.5,
        }
    }
}
