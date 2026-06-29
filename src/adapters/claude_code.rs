//! Claude Code adapter (JSON): <project>/.mcp.json, ~/.mcp.json, ~/.claude.json.
//! Shape: { "mcpServers": { "<name>": { "command", "args", "env", "url"? } } }

use std::path::Path;

use crate::adapters::env_from_json;
use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(home: &Path, cwd: &Path) -> ClientSnapshot {
    let paths = [
        cwd.join(".mcp.json"),
        home.join(".mcp.json"),
        home.join(".claude.json"),
    ];

    let mut files = Vec::new();
    let mut servers = Vec::new();
    let mut notes = Vec::new();

    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let data: serde_json::Value = match serde_json::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                notes.push(format!("failed to parse {}: {e}", path.display()));
                continue;
            }
        };
        files.push(path.display().to_string());
        let scope = if path.file_name().and_then(|n| n.to_str()) == Some(".mcp.json")
            && path.parent() == Some(cwd)
        {
            "project"
        } else {
            "user"
        };

        let Some(servers_map) = data.get("mcpServers").and_then(|v| v.as_object()) else {
            continue;
        };
        for (name, cfg) in servers_map {
            let Some(cfg) = cfg.as_object() else { continue };
            let command = cfg
                .get("command")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let url = cfg.get("url").and_then(|v| v.as_str()).map(str::to_owned);
            let (env_keys, env_values) = env_from_json(cfg.get("env"));
            let transport = if command.is_some() {
                "stdio"
            } else if url.is_some() {
                "http"
            } else {
                "unknown"
            };
            let disabled = cfg
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let args = cfg
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            servers.push(ServerRef {
                client: "claude_code".into(),
                name: name.clone(),
                scope: scope.into(),
                transport: transport.into(),
                command,
                args,
                url,
                env_keys,
                env_values,
                approval: if disabled { "disabled" } else { "on-request" }.into(),
                disabled,
                raw_source: path.display().to_string(),
            });
        }
    }

    ClientSnapshot {
        client: "claude_code".into(),
        detected: !files.is_empty(),
        config_files: files,
        servers,
        notes,
    }
}
