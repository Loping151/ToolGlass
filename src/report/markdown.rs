//! Markdown report rendering.

use crate::ir::{ExposedTool, Finding, FlowEdge, ScanResult};

use super::{next_step_tip, scan_summary_line, scanned_clients_line, server_count, severity_rank};

pub fn render_scan_md(result: &ScanResult) -> String {
    let mut out = Vec::new();
    out.push("# ToolGlass — Agent Visible Surface\n".to_string());
    out.push(
        "> Generated locally. Nothing was sent anywhere. No MCP server was executed.\n".to_string(),
    );

    let detected = result.clients.iter().filter(|c| c.detected).count();
    out.push("## Summary\n".to_string());
    out.push(format!(
        "- Clients: {} ({} detected)",
        result.clients.len(),
        detected
    ));
    out.push(format!("- MCP servers: {}", server_count(result)));
    out.push(format!("- Findings: {}\n", result.findings.len()));

    out.push("## Agent Visible Surface\n".to_string());
    out.push(
        "| client | server | scope | transport | command / url | approval | env keys |".to_string(),
    );
    out.push("|---|---|---|---|---|---|---|".to_string());
    for c in &result.clients {
        for s in &c.servers {
            let cmd = s.command.as_deref().or(s.url.as_deref()).unwrap_or("-");
            let env = if s.env_keys.is_empty() {
                "-".to_string()
            } else {
                s.env_keys.join(", ")
            };
            out.push(format!(
                "| {} | {} | {} | {} | `{}` | {} | {} |",
                cell(&c.client),
                cell(&s.name),
                cell(&s.scope),
                cell(&s.transport),
                code(cmd),
                cell(&s.approval),
                cell(&env)
            ));
        }
    }
    out.push(format!("\n{}", scan_summary_line(result)));
    out.push(scanned_clients_line(result));

    out.push("\n## Findings\n".to_string());
    if result.findings.is_empty() {
        out.push("No findings on the config surface.".to_string());
    } else {
        out.push("| rule | sev | category | client.server | message |".to_string());
        out.push("|---|---|---|---|---|".to_string());
        let mut findings = result.findings.clone();
        findings.sort_by_key(|f| severity_rank(&f.severity));
        for f in findings {
            out.push(format!(
                "| {} | **{}** | {} | {}.{} | {} |",
                cell(&f.rule_id),
                cell(&f.severity),
                cell(&f.category),
                cell(&f.client),
                cell(&f.server),
                cell(&f.message)
            ));
        }
    }
    out.push(format!("\n{}", next_step_tip(result)));
    out.join("\n") + "\n"
}

pub fn render_live_md(tools: &[ExposedTool], findings: &[Finding], edges: &[FlowEdge]) -> String {
    let mut out = Vec::new();
    out.push("# ToolGlass — LIVE: what your agent actually sees\n".to_string());
    out.push("> Tool descriptions below are exactly what the model receives. ToolGlass never called any tool.\n".to_string());

    out.push("## Exposed tool descriptions\n".to_string());
    for t in tools {
        out.push(format!("### {} . {}\n", t.server, t.name));
        let desc = t.description.as_deref().unwrap_or("(no description)");
        out.push(format!("> {}", desc.replace('\n', "\n> ")));
        out.push(String::new());
    }

    out.push("## Poisoning findings\n".to_string());
    if findings.is_empty() {
        out.push("No poisoning indicators.".to_string());
    } else {
        out.push("| rule | sev | category | server | message | evidence |".to_string());
        out.push("|---|---|---|---|---|---|".to_string());
        let mut sorted = findings.to_vec();
        sorted.sort_by_key(|f| severity_rank(&f.severity));
        for f in sorted {
            out.push(format!(
                "| {} | **{}** | {} | {} | {} | {} |",
                cell(&f.rule_id),
                cell(&f.severity),
                cell(&f.category),
                cell(&f.server),
                cell(&f.message),
                cell(&f.evidence)
            ));
        }
    }

    out.push("\n## Exfiltration paths\n".to_string());
    if edges.is_empty() {
        out.push("None.".to_string());
    } else {
        for e in edges {
            out.push(format!(
                "- `{}` -> `{}` — _{}_",
                code(&e.src),
                code(&e.dst),
                e.reason
            ));
        }
    }
    out.join("\n") + "\n"
}

fn cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', "<br>")
}

fn code(value: &str) -> String {
    value.replace('`', "\\`")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ClientSnapshot, Finding, ScanResult, ServerRef};

    #[test]
    fn scan_markdown_includes_summary_and_findings_table() {
        let result = ScanResult {
            clients: vec![ClientSnapshot {
                client: "codex".into(),
                detected: true,
                servers: vec![ServerRef {
                    client: "codex".into(),
                    name: "sink".into(),
                    command: Some("uvx sink".into()),
                    approval: "auto".into(),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            findings: vec![Finding {
                rule_id: "TG-001".into(),
                severity: "medium".into(),
                category: "over_broad_perm".into(),
                client: "codex".into(),
                server: "sink".into(),
                message: "Tools are auto-approved.".into(),
                evidence: String::new(),
                confidence: 0.8,
            }],
        };

        let md = render_scan_md(&result);
        assert!(md.contains("- MCP servers: 1"));
        assert!(md.contains("| TG-001 | **medium** |"));
    }
}
