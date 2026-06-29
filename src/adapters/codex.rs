//! OpenAI Codex CLI adapter (TOML): ~/.codex/config.toml, <project>/.codex/config.toml.
//! Shape: [mcp_servers.<name>] command=.. args=[..] env={ KEY=".." }

use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(home: &Path, cwd: &Path) -> ClientSnapshot {
    let paths = [
        home.join(".codex").join("config.toml"),
        cwd.join(".codex").join("config.toml"),
    ];

    let mut files = Vec::new();
    let mut servers = Vec::new();
    let mut notes = Vec::new();

    for path in paths {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let data: toml::Value = match toml::from_str(&text) {
            Ok(v) => v,
            Err(e) => {
                notes.push(format!("failed to parse {}: {e}", path.display()));
                continue;
            }
        };
        files.push(path.display().to_string());
        let scope = if path.parent() == Some(cwd.join(".codex").as_path()) {
            "project"
        } else {
            "user"
        };

        let Some(mcp) = data.get("mcp_servers").and_then(|v| v.as_table()) else {
            continue;
        };
        for (name, cfg) in mcp {
            let Some(cfg) = cfg.as_table() else { continue };
            let command = cfg
                .get("command")
                .and_then(|v| v.as_str())
                .map(str::to_owned);
            let args = cfg
                .get("args")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(str::to_owned))
                        .collect()
                })
                .unwrap_or_default();
            let (env_keys, env_values) = env_from_toml(cfg.get("env"));
            servers.push(ServerRef {
                client: "codex".into(),
                name: name.clone(),
                scope: scope.into(),
                transport: if command.is_some() {
                    "stdio"
                } else {
                    "unknown"
                }
                .into(),
                command,
                args,
                url: None,
                env_keys,
                env_values,
                approval: "on-request".into(),
                disabled: false,
                raw_source: path.display().to_string(),
            });
        }
    }

    ClientSnapshot {
        client: "codex".into(),
        detected: !files.is_empty(),
        config_files: files,
        servers,
        notes,
    }
}

fn env_from_toml(env_val: Option<&toml::Value>) -> (Vec<String>, BTreeMap<String, String>) {
    let mut keys = Vec::new();
    let mut values = BTreeMap::new();
    if let Some(tbl) = env_val.and_then(|v| v.as_table()) {
        for (k, v) in tbl {
            keys.push(k.clone());
            if let Some(s) = v.as_str() {
                values.insert(k.clone(), s.to_string());
            }
        }
    }
    keys.sort();
    (keys, values)
}
