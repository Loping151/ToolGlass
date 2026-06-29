//! Minimal MCP clients: initialize, tools/list. Never calls tools.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use serde_json::{Value, json};

const PROTOCOL_VERSION: &str = "2025-06-18";

pub struct ToolDesc {
    pub name: String,
    pub description: Option<String>,
    pub input_schema: Value,
}

fn restricted_env(extra: &BTreeMap<String, String>) -> Vec<(String, String)> {
    let mut env = Vec::new();
    for k in ["PATH", "HOME", "USER"] {
        if let Ok(v) = std::env::var(k) {
            env.push((k.to_string(), v));
        }
    }
    for (k, v) in extra {
        env.push((k.clone(), v.clone()));
    }
    env
}

pub fn introspect_stdio(
    command: &str,
    args: &[String],
    extra_env: &BTreeMap<String, String>,
    timeout: Duration,
) -> anyhow::Result<Vec<ToolDesc>> {
    let mut child = Command::new(command)
        .args(args)
        .env_clear()
        .envs(restricted_env(extra_env))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdin = child.stdin.take().expect("stdin");
    let stdout = child.stdout.take().expect("stdout");

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(handshake(stdin, stdout));
    });

    let result = match rx.recv_timeout(timeout) {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("MCP server did not respond within timeout")),
    };

    let _ = child.kill();
    let _ = child.wait();
    result
}

pub fn introspect_http(url: &str, timeout: Duration) -> anyhow::Result<Vec<ToolDesc>> {
    let agent = ureq::AgentBuilder::new()
        .timeout(timeout)
        .redirects(0)
        .build();
    let init = json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "tool-glass", "version": "0.1.0"},
        }
    });
    let init_resp = agent
        .post(url)
        .set("content-type", "application/json")
        .set("accept", "application/json")
        .send_string(&init.to_string())?;
    let session_id = init_resp.header("mcp-session-id").map(str::to_owned);
    let _init_body: Value = init_resp.into_json()?;

    let list = json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}});
    let mut req = agent
        .post(url)
        .set("content-type", "application/json")
        .set("accept", "application/json");
    if let Some(session_id) = &session_id {
        req = req.set("mcp-session-id", session_id);
    }
    let resp: Value = req.send_string(&list.to_string())?.into_json()?;
    Ok(parse_tools_list_response(&resp))
}

fn handshake(
    mut stdin: std::process::ChildStdin,
    stdout: std::process::ChildStdout,
) -> anyhow::Result<Vec<ToolDesc>> {
    let mut reader = BufReader::new(stdout);

    write_line(
        &mut stdin,
        &json!({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "tool-glass", "version": "0.1.0"},
            }
        }),
    )?;
    read_json(&mut reader)?; // initialize response

    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
    )?;
    write_line(
        &mut stdin,
        &json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    )?;
    let resp = read_json(&mut reader)?;

    Ok(parse_tools_list_response(&resp))
}

fn parse_tools_list_response(resp: &Value) -> Vec<ToolDesc> {
    let mut tools = Vec::new();
    if let Some(arr) = resp
        .get("result")
        .and_then(|r| r.get("tools"))
        .and_then(|t| t.as_array())
    {
        for t in arr {
            tools.push(ToolDesc {
                name: t
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                description: t
                    .get("description")
                    .and_then(|v| v.as_str())
                    .map(str::to_owned),
                input_schema: t.get("inputSchema").cloned().unwrap_or(Value::Null),
            });
        }
    }
    tools
}

fn write_line(w: &mut impl Write, v: &Value) -> anyhow::Result<()> {
    writeln!(w, "{v}")?;
    w.flush()?;
    Ok(())
}

fn read_json(reader: &mut impl BufRead) -> anyhow::Result<Value> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            anyhow::bail!("MCP server closed stdout");
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        return Ok(serde_json::from_str(line)?);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_http_tools_list_response() {
        let resp = json!({
            "jsonrpc": "2.0",
            "result": {
                "tools": [
                    {"name": "x", "description": "y"}
                ]
            }
        });

        let tools = parse_tools_list_response(&resp);

        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "x");
        assert_eq!(tools[0].description.as_deref(), Some("y"));
    }
}
