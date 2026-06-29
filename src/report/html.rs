//! Self-contained single-file HTML report.

use crate::ir::{ExposedTool, Finding, FlowEdge, ScanResult};

use super::{server_count, severity_rank};

const STYLE: &str = r#"
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,sans-serif;max-width:1000px;margin:24px auto;padding:0 16px;color:#222}
h1{color:#7a1fa2;margin-bottom:4px}
h2{border-bottom:2px solid #eee;padding-bottom:4px;margin-top:30px}
h3{margin-bottom:4px}
table{border-collapse:collapse;width:100%;margin:8px 0}
th,td{border:1px solid #ddd;padding:6px 9px;text-align:left;vertical-align:top;font-size:14px}
th{background:#f6f0f8}
tr.high{background:#ffecec}
tr.medium{background:#fff7e6}
tr.low{background:#eef9ff}
pre{background:#0f0f12;color:#eee;padding:12px;border-radius:8px;overflow:auto;white-space:pre-wrap;word-break:break-word}
pre.flagged{border-left:4px solid #e53935;background:#2a1010;color:#fff1f1}
.muted{color:#888;font-size:13px}
.sev-high{color:#c62828;font-weight:700}
.sev-medium{color:#b8860b;font-weight:700}
.sev-low{color:#1565c0}
.sev-info{color:#888}
"#;

pub fn render_scan_html(result: &ScanResult) -> String {
    let mut rows = String::new();
    for c in &result.clients {
        for s in &c.servers {
            let cmd = esc(s.command.as_deref().or(s.url.as_deref()).unwrap_or("-"));
            let env = if s.env_keys.is_empty() {
                "-".to_string()
            } else {
                s.env_keys.join(", ")
            };
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                esc(&c.client),
                esc(&s.name),
                esc(&s.scope),
                esc(&s.transport),
                cmd,
                esc(&s.approval),
                esc(&env)
            ));
        }
    }
    let surface = if rows.is_empty() {
        "<p class='muted'>No MCP servers found.</p>".to_string()
    } else {
        format!(
            "<table><tr><th>client</th><th>server</th><th>scope</th><th>transport</th><th>command/url</th><th>approval</th><th>env keys</th></tr>{rows}</table>"
        )
    };

    let mut fr = String::new();
    let mut findings = result.findings.clone();
    findings.sort_by_key(|f| severity_rank(&f.severity));
    for f in &findings {
        fr.push_str(&format!(
            "<tr class='{}'><td>{}</td><td class='sev-{}'>{}</td><td>{}</td><td>{}.{}</td><td>{}</td></tr>",
            row_class(&f.severity),
            esc(&f.rule_id),
            esc_attr(&f.severity),
            esc(&f.severity),
            esc(&f.category),
            esc(&f.client),
            esc(&f.server),
            esc(&f.message)
        ));
    }
    let findings_html = if fr.is_empty() {
        "<h2>Findings</h2><p>No findings on the config surface.</p>".to_string()
    } else {
        format!(
            "<h2>Findings</h2><table><tr><th>rule</th><th>sev</th><th>category</th><th>client.server</th><th>message</th></tr>{fr}</table>"
        )
    };

    let detected = result.clients.iter().filter(|c| c.detected).count();
    let summary = format!(
        "<h2>Summary</h2><ul><li>Clients: {} ({} detected)</li><li>MCP servers: {}</li><li>Findings: {}</li></ul>",
        result.clients.len(),
        detected,
        server_count(result),
        result.findings.len()
    );
    page(
        "Agent Visible Surface — generated locally; nothing sent anywhere; no MCP server was executed.",
        &format!("<h2>Agent Visible Surface</h2>{surface}{summary}{findings_html}"),
    )
}

pub fn render_live_html(tools: &[ExposedTool], findings: &[Finding], edges: &[FlowEdge]) -> String {
    let mut desc = String::new();
    for t in tools {
        let flagged = findings.iter().any(|f| f.server == t.server);
        let class = if flagged { "flagged" } else { "" };
        desc.push_str(&format!(
            "<h3>{} . {}</h3><pre class='{}'>{}</pre>",
            esc(&t.server),
            esc(&t.name),
            class,
            esc(t.description.as_deref().unwrap_or("(no description)"))
        ));
    }
    if desc.is_empty() {
        desc.push_str("<p class='muted'>No tools.</p>");
    }

    let mut fr = String::new();
    let mut sorted = findings.to_vec();
    sorted.sort_by_key(|f| severity_rank(&f.severity));
    for f in &sorted {
        fr.push_str(&format!(
            "<tr class='{}'><td>{}</td><td class='sev-{}'>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            row_class(&f.severity),
            esc(&f.rule_id),
            esc_attr(&f.severity),
            esc(&f.severity),
            esc(&f.category),
            esc(&f.server),
            esc(&f.message)
        ));
    }
    let findings_html = if fr.is_empty() {
        "<h2>Poisoning findings</h2><p>No poisoning indicators.</p>".to_string()
    } else {
        format!(
            "<h2>Poisoning findings</h2><table><tr><th>rule</th><th>sev</th><th>category</th><th>server</th><th>message</th></tr>{fr}</table>"
        )
    };

    let flow_html = if edges.is_empty() {
        "<h2>Exfiltration paths</h2><p>None.</p>".to_string()
    } else {
        let flow = edges
            .iter()
            .map(|e| format!("{}  ->  {}     ({})", e.src, e.dst, e.reason))
            .collect::<Vec<_>>()
            .join("\n");
        format!("<h2>Exfiltration paths</h2><pre>{}</pre>", esc(&flow))
    };

    page(
        "LIVE — what your agent actually sees right now. Descriptions below are exactly what the model receives; ToolGlass never called any tool.",
        &format!("<h2>Exposed tool descriptions</h2>{desc}{findings_html}{flow_html}"),
    )
}

fn page(intro: &str, body: &str) -> String {
    format!(
        "<!doctype html><html><head><meta charset='utf-8'><title>ToolGlass report</title><style>{STYLE}</style></head><body><h1>ToolGlass</h1><p class='muted'>{}</p>{body}</body></html>\n",
        esc(intro)
    )
}

fn row_class(severity: &str) -> &str {
    match severity {
        "high" => "high",
        "medium" => "medium",
        "low" => "low",
        _ => "",
    }
}

fn esc(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn esc_attr(value: &str) -> String {
    value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect()
}
