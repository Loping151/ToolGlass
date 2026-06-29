//! Cursor adapter (JSON): ~/.cursor/mcp.json.
//! Shape: { "mcpServers": { "<name>": { "command", "args", "env" } } }

use std::path::Path;

use crate::adapters::env_from_json;
use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(home: &Path, _cwd: &Path) -> ClientSnapshot {
    let path = home.join(".cursor").join("mcp.json");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ClientSnapshot {
            client: "cursor".into(),
            ..Default::default()
        };
    };
    let data: serde_json::Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return ClientSnapshot {
                client: "cursor".into(),
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
            let (env_keys, env_values) = env_from_json(cfg.get("env"));
            servers.push(ServerRef {
                client: "cursor".into(),
                name: name.clone(),
                scope: "user".into(),
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
        client: "cursor".into(),
        detected: true,
        config_files: vec![path.display().to_string()],
        servers,
        ..Default::default()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn parses_cursor_mcp_servers() {
        let root =
            std::env::temp_dir().join(format!("tool_glass_cursor_test_{}", std::process::id()));
        let cursor_dir = root.join(".cursor");
        fs::create_dir_all(&cursor_dir).unwrap();
        fs::write(
            cursor_dir.join("mcp.json"),
            r#"{
              "mcpServers": {
                "docs": {
                  "command": "npx",
                  "args": ["-y", "@demo/docs-mcp"],
                  "env": { "DOCS_TOKEN": "redacted" }
                },
                "remote": {
                  "url": "https://cursor.example/mcp",
                  "disabled": true
                }
              }
            }"#,
        )
        .unwrap();

        let snapshot = discover(&root, Path::new("."));

        assert!(snapshot.detected);
        assert_eq!(snapshot.client, "cursor");
        assert_eq!(snapshot.servers.len(), 2);
        let docs = snapshot
            .servers
            .iter()
            .find(|server| server.name == "docs")
            .unwrap();
        assert_eq!(docs.transport, "stdio");
        assert_eq!(docs.command.as_deref(), Some("npx"));
        assert_eq!(docs.args, ["-y", "@demo/docs-mcp"]);
        assert_eq!(docs.env_keys, ["DOCS_TOKEN"]);
        assert_eq!(docs.scope, "user");

        let remote = snapshot
            .servers
            .iter()
            .find(|server| server.name == "remote")
            .unwrap();
        assert_eq!(remote.transport, "http");
        assert_eq!(remote.url.as_deref(), Some("https://cursor.example/mcp"));
        assert_eq!(remote.approval, "disabled");
        assert!(remote.disabled);

        fs::remove_dir_all(root).unwrap();
    }
}
