//! Scan orchestration: run all adapters, evaluate rules, return a ScanResult.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::adapters;
use crate::analysis;
use crate::ir::{ExposedTool, Finding, FlowEdge, ScanResult};
use crate::mcp;
use crate::rules::{evaluate, suspicious_command_match};

fn default_home() -> PathBuf {
    PathBuf::from(std::env::var("HOME").unwrap_or_default())
}

fn default_cwd() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub fn run_scan(
    home: Option<&Path>,
    cwd: Option<&Path>,
    clients: Option<&[String]>,
) -> anyhow::Result<ScanResult> {
    let home = home.map(PathBuf::from).unwrap_or_else(default_home);
    let cwd = cwd.map(PathBuf::from).unwrap_or_else(default_cwd);

    let chosen: Vec<_> = adapters::all()
        .into_iter()
        .filter(|(name, _)| match clients {
            Some(c) => c.iter().any(|x| x == name),
            None => true,
        })
        .collect();

    let mut snapshots = Vec::new();
    for (_, discover) in &chosen {
        snapshots.push(discover(&home, &cwd));
    }

    let mut all_servers = Vec::new();
    for snap in &snapshots {
        for s in &snap.servers {
            all_servers.push(s.clone());
        }
    }
    let findings = evaluate(&all_servers);

    Ok(ScanResult {
        clients: snapshots,
        findings,
    })
}

#[derive(Debug, Clone)]
pub struct LiveLaunch {
    pub client: String,
    pub server: String,
    pub command: String,
    pub args: Vec<String>,
    pub env_keys: Vec<String>,
    pub suspicious_match: Option<String>,
}

pub fn live_launches(result: &ScanResult) -> Vec<LiveLaunch> {
    let mut launches = Vec::new();
    for snap in &result.clients {
        for s in &snap.servers {
            if s.transport != "stdio" {
                continue;
            }
            let Some(command) = &s.command else { continue };
            launches.push(LiveLaunch {
                client: s.client.clone(),
                server: s.name.clone(),
                command: command.clone(),
                args: s.args.clone(),
                env_keys: s.env_keys.clone(),
                suspicious_match: suspicious_command_match(Some(command), &s.args),
            });
        }
    }
    launches
}

pub fn run_live(
    result: &ScanResult,
) -> (Vec<ExposedTool>, Vec<Finding>, Vec<FlowEdge>, Vec<String>) {
    let mut tools: Vec<ExposedTool> = Vec::new();
    let mut notes: Vec<String> = Vec::new();

    for snap in &result.clients {
        for s in &snap.servers {
            match s.transport.as_str() {
                "stdio" => {
                    let Some(cmd) = &s.command else { continue };
                    let env_list = if s.env_keys.is_empty() {
                        "-".to_string()
                    } else {
                        s.env_keys.join(",")
                    };
                    notes.push(format!(
                        "introspect {}.{}: {} {} [env: {}]",
                        s.client,
                        s.name,
                        cmd,
                        s.args.join(" "),
                        env_list
                    ));
                    match mcp::introspect_stdio(cmd, &s.args, &s.env_values, Duration::from_secs(8))
                    {
                        Ok(descs) => push_live_tools(&mut tools, s, descs),
                        Err(_) => notes.push(format!(
                            "  failed {}.{}: could not start MCP server {}.{} (command failed or it is not an MCP server)",
                            s.client, s.name, s.client, s.name
                        )),
                    }
                }
                "http" => {
                    let Some(url) = &s.url else { continue };
                    notes.push(format!("introspect {}.{}: {url}", s.client, s.name));
                    match mcp::introspect_http(url, Duration::from_secs(8)) {
                        Ok(descs) => push_live_tools(&mut tools, s, descs),
                        Err(_) => notes.push(format!(
                            "  failed {}.{}: could not introspect MCP server {}.{} over HTTP (request failed or it is not a Streamable HTTP MCP server)",
                            s.client, s.name, s.client, s.name
                        )),
                    }
                }
                "sse" => notes.push(format!(
                    "introspect {}.{}: SSE transport not yet supported for live introspection",
                    s.client, s.name
                )),
                _ => {}
            }
        }
    }

    let findings = analysis::evaluate_tools(&tools);
    let edges = analysis::build_edges(&tools);
    (tools, findings, edges, notes)
}

fn push_live_tools(
    tools: &mut Vec<ExposedTool>,
    s: &crate::ir::ServerRef,
    descs: Vec<mcp::ToolDesc>,
) {
    for d in descs {
        tools.push(ExposedTool {
            client: s.client.clone(),
            server: s.name.clone(),
            name: d.name,
            description: d.description,
            input_schema: d.input_schema,
            source: "live".into(),
        });
    }
}
