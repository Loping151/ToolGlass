//! Cline adapter (JSON): ~/.cline/mcp.json.
//! Shape: { "mcpServers": { "<name>": { "command"|"url","args","env","transportType",
//!        "disabled":bool, "autoApprove":[..] } } }

use std::path::Path;

use crate::adapters::env_from_json;
use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(home: &Path, _cwd: &Path) -> ClientSnapshot {
    let path = home.join(".cline").join("mcp.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ClientSnapshot {
            client: "cline".into(),
            ..Default::default()
        };
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return ClientSnapshot {
                client: "cline".into(),
                detected: true,
                config_files: vec![path.display().to_string()],
                notes: vec![format!("failed to parse {}: {e}", path.display())],
                ..Default::default()
            };
        }
    };

    let mut servers = Vec::new();
    if let Some(map) = data.get("mcpServers").and_then(|v| v.as_object()) {
        for (name, cfg) in map {
            let Some(cfg) = cfg.as_object() else { continue };
            let command = cfg
                .get("command")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let url = cfg.get("url").and_then(|v| v.as_str()).map(str::to_owned);
            let ttype = cfg
                .get("transportType")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_lowercase();
            let transport = if ttype == "http" || url.is_some() {
                "http"
            } else {
                "stdio"
            };
            let disabled = cfg
                .get("disabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let auto = cfg
                .get("autoApprove")
                .and_then(|v| v.as_array())
                .is_some_and(|a| !a.is_empty());
            let approval = if disabled {
                "disabled"
            } else if auto {
                "auto"
            } else {
                "on-request"
            };
            let (env_keys, env_values) = env_from_json(cfg.get("env"));
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
                client: "cline".into(),
                name: name.clone(),
                scope: "user".into(),
                transport: transport.into(),
                command,
                args,
                url,
                env_keys,
                env_values,
                approval: approval.into(),
                disabled,
                raw_source: path.display().to_string(),
            });
        }
    }

    ClientSnapshot {
        client: "cline".into(),
        detected: true,
        config_files: vec![path.display().to_string()],
        servers,
        ..Default::default()
    }
}
