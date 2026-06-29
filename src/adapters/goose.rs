//! goose adapter (YAML): ~/.config/goose/config.yaml.
//! Schema varies by version — best-effort: { mcpServers: {..} } or { extensions: [..] }.
//! Experimental; uncertainty is recorded as a note.

use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::{ClientSnapshot, ServerRef};

pub fn discover(home: &Path, _cwd: &Path) -> ClientSnapshot {
    let path = home.join(".config").join("goose").join("config.yaml");
    let Ok(text) = std::fs::read_to_string(&path) else {
        return ClientSnapshot {
            client: "goose".into(),
            ..Default::default()
        };
    };
    let data: serde_yaml::Value = match serde_yaml::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return ClientSnapshot {
                client: "goose".into(),
                detected: true,
                config_files: vec![path.display().to_string()],
                notes: vec![format!("failed to parse {}: {e}", path.display())],
                ..Default::default()
            };
        }
    };

    let mut servers = Vec::new();
    if let Some(mapping) = data.as_mapping() {
        for key in ["mcpServers", "mcp_servers"] {
            if let Some(m) = mapping.get(serde_yaml::Value::String(key.into()))
                && let Some(map) = m.as_mapping()
            {
                for (name, cfg) in map {
                    if let (Some(name), Some(cfg)) = (name.as_str(), cfg.as_mapping()) {
                        servers.push(server_from(name, cfg, &path));
                    }
                }
            }
        }
        if let Some(ext) = mapping.get(serde_yaml::Value::String("extensions".into()))
            && let Some(seq) = ext.as_sequence()
        {
            for e in seq {
                if let Some(m) = e.as_mapping() {
                    let name = m
                        .get(serde_yaml::Value::String("name".into()))
                        .and_then(|v| v.as_str())
                        .or_else(|| {
                            m.get(serde_yaml::Value::String("id".into()))
                                .and_then(|v| v.as_str())
                        })
                        .unwrap_or("unnamed");
                    servers.push(server_from(name, m, &path));
                }
            }
        }
    }

    ClientSnapshot {
        client: "goose".into(),
        detected: true,
        config_files: vec![path.display().to_string()],
        servers,
        notes: vec![
            "goose config schema varies by version; parsed best-effort (experimental)".into(),
        ],
    }
}

fn server_from(name: &str, cfg: &serde_yaml::Mapping, path: &Path) -> ServerRef {
    let command = cfg
        .get(serde_yaml::Value::String("command".into()))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let url = cfg
        .get(serde_yaml::Value::String("url".into()))
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let transport = if command.is_some() {
        "stdio"
    } else if url.is_some() {
        "http"
    } else {
        "unknown"
    };
    let enabled = cfg
        .get(serde_yaml::Value::String("enabled".into()))
        .and_then(|v| v.as_bool());
    let disabled = matches!(enabled, Some(false));

    let (env_keys, env_values) = env_from_yaml(cfg.get(serde_yaml::Value::String("env".into())));
    let args = cfg
        .get(serde_yaml::Value::String("args".into()))
        .and_then(|v| v.as_sequence())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    ServerRef {
        client: "goose".into(),
        name: name.into(),
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
    }
}

fn env_from_yaml(env_val: Option<&serde_yaml::Value>) -> (Vec<String>, BTreeMap<String, String>) {
    let mut keys = Vec::new();
    let mut values = BTreeMap::new();
    if let Some(map) = env_val.and_then(|v| v.as_mapping()) {
        for (k, v) in map {
            if let Some(k) = k.as_str() {
                keys.push(k.to_string());
                if let Some(s) = v.as_str() {
                    values.insert(k.to_string(), s.to_string());
                }
            }
        }
    }
    keys.sort();
    (keys, values)
}
