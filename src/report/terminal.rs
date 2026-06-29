//! Terminal reports.

use std::collections::HashSet;
use std::fmt::Write as _;

use comfy_table::presets::UTF8_FULL;
use comfy_table::{ContentArrangement, Table};

use crate::ir::{ExposedTool, Finding, FlowEdge, ScanResult};

use super::{
    next_step_tip, parse_warnings, scan_summary_line, scanned_clients_line, server_count,
    severity_rank,
};

pub fn render_scan_terminal(result: &ScanResult) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "\x1b[1;35mToolGlass\x1b[0m — what your agent actually sees\n"
    )
    .unwrap();

    if server_count(result) == 0 {
        writeln!(out, "No MCP servers found.").unwrap();
    } else {
        let mut surface = Table::new();
        surface
            .load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec![
                "client",
                "server",
                "scope",
                "transport",
                "command / url",
                "approval",
                "env keys",
            ]);
        for c in &result.clients {
            for s in &c.servers {
                let cmd = s
                    .command
                    .clone()
                    .or_else(|| s.url.clone())
                    .unwrap_or_else(|| "-".into());
                surface.add_row(vec![
                    s.client.clone(),
                    s.name.clone(),
                    s.scope.clone(),
                    s.transport.clone(),
                    cmd,
                    s.approval.clone(),
                    if s.env_keys.is_empty() {
                        "-".into()
                    } else {
                        s.env_keys.join(", ")
                    },
                ]);
            }
        }
        writeln!(out, "{surface}").unwrap();
    }

    let mut findings = result.findings.clone();
    findings.sort_by_key(|f| severity_rank(&f.severity));

    if findings.is_empty() {
        writeln!(out, "\x1b[32m✓ No findings on the config surface.\x1b[0m").unwrap();
        writeln!(out, "{}", scan_summary_line(result)).unwrap();
        writeln!(out, "{}", scanned_clients_line(result)).unwrap();
        writeln!(out, "{}", next_step_tip(result)).unwrap();
        write_parse_warnings(&mut out, result);
        return out;
    }

    let mut ftab = Table::new();
    ftab.load_preset(UTF8_FULL)
        .set_content_arrangement(ContentArrangement::Dynamic)
        .set_header(vec!["rule", "sev", "category", "client.server", "message"]);
    for f in &findings {
        ftab.add_row(vec![
            f.rule_id.clone(),
            f.severity.clone(),
            f.category.clone(),
            format!("{}.{}", f.client, f.server),
            f.message.clone(),
        ]);
    }
    writeln!(out, "\nFindings ({})\n{ftab}", findings.len()).unwrap();
    writeln!(out, "{}", scan_summary_line(result)).unwrap();
    writeln!(out, "{}", scanned_clients_line(result)).unwrap();
    writeln!(out, "{}", next_step_tip(result)).unwrap();
    write_parse_warnings(&mut out, result);
    out
}

fn write_parse_warnings(out: &mut String, result: &ScanResult) {
    let warnings = parse_warnings(result);
    if warnings.is_empty() {
        return;
    }
    writeln!(out, "\nparse warnings:").unwrap();
    for warning in warnings {
        writeln!(out, "  - {warning}").unwrap();
    }
}

pub fn render_live_terminal(
    tools: &[ExposedTool],
    findings: &[Finding],
    edges: &[FlowEdge],
) -> String {
    let mut out = String::new();
    writeln!(
        out,
        "\x1b[1;35mToolGlass — LIVE\x1b[0m — what your agent actually sees right now\n"
    )
    .unwrap();

    let flagged: HashSet<&str> = findings.iter().map(|f| f.server.as_str()).collect();
    for t in tools {
        let body = t
            .description
            .clone()
            .unwrap_or_else(|| "(no description)".into());
        if flagged.contains(t.server.as_str()) {
            writeln!(
                out,
                "\x1b[31m[{} . {}]\x1b[0m\n\x1b[31m{body}\x1b[0m\n",
                t.server, t.name
            )
            .unwrap();
        } else {
            writeln!(out, "[{} . {}]\n{body}\n", t.server, t.name).unwrap();
        }
    }

    let mut f = findings.to_vec();
    f.sort_by_key(|x| severity_rank(&x.severity));

    if f.is_empty() {
        writeln!(out, "\x1b[32m✓ No poisoning indicators.\x1b[0m").unwrap();
    } else {
        let mut tab = Table::new();
        tab.load_preset(UTF8_FULL)
            .set_content_arrangement(ContentArrangement::Dynamic)
            .set_header(vec!["rule", "sev", "category", "server", "message"]);
        for x in &f {
            tab.add_row(vec![
                x.rule_id.clone(),
                x.severity.clone(),
                x.category.clone(),
                x.server.clone(),
                x.message.clone(),
            ]);
        }
        writeln!(out, "Poisoning findings ({})\n{tab}", f.len()).unwrap();
    }

    if !edges.is_empty() {
        writeln!(out, "Exfiltration paths:").unwrap();
        for e in edges {
            writeln!(out, "  {} -> {}  ({})", e.src, e.dst, e.reason).unwrap();
        }
    }
    out
}
