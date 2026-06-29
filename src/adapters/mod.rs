//! Client adapters: parse each client's MCP config into the IR.

pub mod claude_code;
pub mod cline;
pub mod codex;
pub mod cursor;
pub mod goose;
pub mod vscode;

use std::collections::BTreeMap;
use std::path::Path;

use crate::ir::ClientSnapshot;

type DiscoverFn = fn(&Path, &Path) -> ClientSnapshot;

/// All supported clients, in scan order.
pub fn all() -> Vec<(&'static str, DiscoverFn)> {
    vec![
        ("claude_code", claude_code::discover),
        ("cursor", cursor::discover),
        ("codex", codex::discover),
        ("vscode", vscode::discover),
        ("cline", cline::discover),
        ("goose", goose::discover),
    ]
}

/// Pull (sorted env key names, env values) from a JSON object value, if any.
pub(crate) fn env_from_json(
    env_val: Option<&serde_json::Value>,
) -> (Vec<String>, BTreeMap<String, String>) {
    let mut keys = Vec::new();
    let mut values = BTreeMap::new();
    if let Some(obj) = env_val.and_then(|v| v.as_object()) {
        for (k, v) in obj {
            keys.push(k.clone());
            if let Some(s) = v.as_str() {
                values.insert(k.clone(), s.to_string());
            }
        }
    }
    keys.sort();
    (keys, values)
}
