use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// An immutable evidence record verifying a factual claim about a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence<T> {
    /// Deterministic SHA-256 hash of tool + target_digest + data
    pub id: String,
    /// SHA-256 of the analyzed target file
    pub target_digest: String,
    /// Absolute or relative path to the target file
    pub target_path: String,
    /// Identification of the tool or engine producing this evidence
    pub tool: String,
    /// ISO 8601 UTC timestamp
    pub timestamp: String,
    /// Typed evidence payload
    pub data: T,
    /// Registered uncertainties or missing symbols
    pub unknowns: Vec<String>,
}

impl<T: Serialize> Evidence<T> {
    pub fn new(target_path: impl Into<String>, target_digest: impl Into<String>, tool: impl Into<String>, data: T, unknowns: Vec<String>) -> Self {
        let path = target_path.into();
        let digest = target_digest.into();
        let tool_name = tool.into();
        let timestamp = Utc::now().to_rfc3339();

        // Calculate deterministic ID based on tool, digest, and payload
        let payload_json = serde_json::to_string(&data).unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(tool_name.as_bytes());
        hasher.update(digest.as_bytes());
        hasher.update(payload_json.as_bytes());
        let id = hex::encode(hasher.finalize());

        Self {
            id,
            target_digest: digest,
            target_path: path,
            tool: tool_name,
            timestamp,
            data,
            unknowns,
        }
    }
}

/// A registered gap in an investigation that an agent or analyst must acknowledge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResidualUnknown {
    pub id: String,
    pub title: String,
    pub description: String,
    pub resolved: bool,
    pub resolution_evidence_id: Option<String>,
}

/// In-memory ledger tracking verified evidence and residual uncertainties.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct EvidenceLedger {
    pub records: HashMap<String, serde_json::Value>,
    pub unknowns: Vec<ResidualUnknown>,
}

impl EvidenceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record<T: Serialize>(&mut self, evidence: &Evidence<T>) -> String {
        let value = serde_json::to_value(evidence).unwrap_or(serde_json::Value::Null);
        self.records.insert(evidence.id.clone(), value);
        evidence.id.clone()
    }

    pub fn add_unknown(&mut self, title: impl Into<String>, description: impl Into<String>) -> String {
        let title_s = title.into();
        let mut hasher = Sha256::new();
        hasher.update(title_s.as_bytes());
        let id = hex::encode(&hasher.finalize()[..8]);

        let unknown = ResidualUnknown {
            id: id.clone(),
            title: title_s,
            description: description.into(),
            resolved: false,
            resolution_evidence_id: None,
        };
        self.unknowns.push(unknown);
        id
    }

    pub fn resolve_unknown(&mut self, unknown_id: &str, evidence_id: &str) -> bool {
        if let Some(u) = self.unknowns.iter_mut().find(|u| u.id == unknown_id) {
            u.resolved = true;
            u.resolution_evidence_id = Some(evidence_id.to_string());
            true
        } else {
            false
        }
    }

    pub fn open_unknowns_count(&self) -> usize {
        self.unknowns.iter().filter(|u| !u.resolved).count()
    }
}

/// Helper function to compute the SHA-256 hash of a file's bytes.
pub fn compute_sha256(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
