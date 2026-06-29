//! Agent Visible Surface IR.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServerRef {
    pub client: String,
    pub name: String,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub transport: String,
    #[serde(default)]
    pub command: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub env_keys: Vec<String>,
    #[serde(default, skip_serializing)]
    pub env_values: BTreeMap<String, String>,
    #[serde(default)]
    pub approval: String,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub raw_source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub category: String,
    #[serde(default)]
    pub client: String,
    #[serde(default)]
    pub server: String,
    pub message: String,
    #[serde(default)]
    pub evidence: String,
    #[serde(default)]
    pub confidence: f64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientSnapshot {
    pub client: String,
    #[serde(default)]
    pub detected: bool,
    #[serde(default)]
    pub config_files: Vec<String>,
    #[serde(default)]
    pub servers: Vec<ServerRef>,
    #[serde(default)]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub clients: Vec<ClientSnapshot>,
    #[serde(default)]
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExposedTool {
    pub client: String,
    pub server: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub input_schema: serde_json::Value,
    #[serde(default = "default_live")]
    pub source: String,
}

fn default_live() -> String {
    "live".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowEdge {
    pub src: String,
    pub dst: String,
    #[serde(default)]
    pub reason: String,
}
