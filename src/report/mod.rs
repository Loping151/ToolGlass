//! Report renderers for terminal, Markdown, HTML, and SARIF.

pub mod html;
pub mod markdown;
pub mod sarif;
pub mod terminal;

use crate::ir::ScanResult;

pub use html::{render_live_html, render_scan_html};
pub use markdown::{render_live_md, render_scan_md};
pub use sarif::{render_live_sarif, render_scan_sarif};
pub use terminal::{render_live_terminal, render_scan_terminal};

pub(crate) const INFORMATION_URI: &str = "https://github.com/Loping151/ToolGlass";

pub(crate) fn server_count(result: &ScanResult) -> usize {
    result.clients.iter().map(|c| c.servers.len()).sum()
}

pub(crate) fn detected_client_count(result: &ScanResult) -> usize {
    result.clients.iter().filter(|c| c.detected).count()
}

pub(crate) fn live_supported_server_count(result: &ScanResult) -> usize {
    result
        .clients
        .iter()
        .flat_map(|c| &c.servers)
        .filter(|s| s.transport == "stdio" || (s.transport == "http" && s.url.is_some()))
        .count()
}

pub(crate) fn parse_warnings(result: &ScanResult) -> Vec<String> {
    result
        .clients
        .iter()
        .flat_map(|client| client.notes.iter().cloned())
        .collect()
}

pub(crate) fn severity_counts(result: &ScanResult) -> (usize, usize, usize) {
    let mut high = 0;
    let mut medium = 0;
    let mut low = 0;
    for f in &result.findings {
        match f.severity.as_str() {
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }
    (high, medium, low)
}

pub(crate) fn scan_summary_line(result: &ScanResult) -> String {
    let (high, medium, low) = severity_counts(result);
    format!(
        "{} servers across {} clients · {} findings: {} high / {} medium / {} low",
        server_count(result),
        detected_client_count(result),
        result.findings.len(),
        high,
        medium,
        low
    )
}

pub(crate) fn scanned_clients_line(result: &ScanResult) -> String {
    format!(
        "scanned {} clients · {} had MCP configs",
        result.clients.len(),
        detected_client_count(result)
    )
}

pub(crate) fn next_step_tip(result: &ScanResult) -> &'static str {
    if live_supported_server_count(result) > 0 {
        "Tip: run tool-glass scan --live to read actual tool descriptions."
    } else {
        "Tip: run tool-glass demo to see a tool-poisoning example."
    }
}

pub(crate) fn severity_rank(severity: &str) -> u8 {
    match severity {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        "info" => 3,
        _ => 9,
    }
}
