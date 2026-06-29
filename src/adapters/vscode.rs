//! VS Code (Copilot Chat) adapter (JSON): <project>/.vscode/mcp.json.
//! Shape: { "servers": { "<name>": { "type":"stdio"|"http", "command","args","env","url"? } } }
//! Also tolerates the "mcpServers" key.

use std::path::Path;

use crate::adapters::env_from_json;
use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(_home: &Path, cwd: &Path) -> ClientSnapshot {
    let path = cwd.join(".vscode").join("mcp.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ClientSnapshot {
            client: "vscode".into(),
            ..Default::default()
        };
    };
    let notes = Vec::new();
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return ClientSnapshot {
                client: "vscode".into(),
                detected: true,
                config_files: vec![path.display().to_string()],
                notes: vec![format!("failed to parse {}: {e}", path.display())],
                ..Default::default()
            };
        }
    };

    let mut servers = Vec::new();
    let servers_map = data
        .get("servers")
        .and_then(|v| v.as_object())
        .or_else(|| data.get("mcpServers").and_then(|v| v.as_object()));

    if let Some(map) = servers_map {
        for (name, cfg) in map {
            let Some(cfg) = cfg.as_object() else { continue };
            let stype = cfg
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("stdio")
                .to_lowercase();
            let command = cfg
                .get("command")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let url = cfg.get("url").and_then(|v| v.as_str()).map(str::to_owned);
            let (env_keys, env_values) = env_from_json(cfg.get("env"));
            let transport = if stype == "http" || url.is_some() {
                "http"
            } else {
                "stdio"
            };
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
                client: "vscode".into(),
                name: name.clone(),
                scope: "project".into(),
                transport: transport.into(),
                command,
                args,
                url,
                env_keys,
                env_values,
                approval: "on-request".into(),
                ..Default::default()
            });
        }
    }

    ClientSnapshot {
        client: "vscode".into(),
        detected: true,
        config_files: vec![path.display().to_string()],
        servers,
        notes,
    }
}
