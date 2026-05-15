pub mod db;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A historical finding from an audit report or previous analysis.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalFinding {
    pub project: String,
    pub contract: String,
    pub function: String,
    pub check: String,
    pub description: String,
    pub severity: String,
    pub source_url: Option<String>,
}

/// Knowledge base for storing and querying historical audit findings.
pub struct KnowledgeBase {
    pub findings: Vec<HistoricalFinding>,
    by_check: HashMap<String, Vec<usize>>,
    by_contract: HashMap<String, Vec<usize>>,
    by_severity: HashMap<String, Vec<usize>>,
}

impl KnowledgeBase {
    pub fn new() -> Self {
        Self {
            findings: Vec::new(),
            by_check: HashMap::new(),
            by_contract: HashMap::new(),
            by_severity: HashMap::new(),
        }
    }

    pub fn add(&mut self, finding: HistoricalFinding) {
        let idx = self.findings.len();
        self.by_check
            .entry(finding.check.clone())
            .or_default()
            .push(idx);
        self.by_contract
            .entry(finding.contract.clone())
            .or_default()
            .push(idx);
        self.by_severity
            .entry(finding.severity.clone())
            .or_default()
            .push(idx);
        self.findings.push(finding);
    }

    pub fn lookup(&self, contract: &str, function: &str) -> Vec<&HistoricalFinding> {
        self.findings
            .iter()
            .filter(|f| {
                f.contract.to_lowercase() == contract.to_lowercase()
                    || f.function.to_lowercase() == function.to_lowercase()
            })
            .collect()
    }

    pub fn lookup_by_check(&self, check: &str) -> Vec<&HistoricalFinding> {
        self.by_check
            .get(check)
            .map(|indices| indices.iter().map(|&i| &self.findings[i]).collect())
            .unwrap_or_default()
    }

    pub fn lookup_by_contract(&self, contract: &str) -> Vec<&HistoricalFinding> {
        self.by_contract
            .get(contract)
            .map(|indices| indices.iter().map(|&i| &self.findings[i]).collect())
            .unwrap_or_default()
    }

    /// Find findings with similar descriptions using simple Jaccard similarity on words.
    pub fn find_similar(&self, description: &str, threshold: f64) -> Vec<&HistoricalFinding> {
        let desc_words: std::collections::HashSet<String> = description
            .to_lowercase()
            .split_whitespace()
            .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if desc_words.is_empty() {
            return Vec::new();
        }
        self.findings
            .iter()
            .filter(|f| {
                let f_words: std::collections::HashSet<String> = f
                    .description
                    .to_lowercase()
                    .split_whitespace()
                    .map(|s| s.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
                if f_words.is_empty() {
                    return false;
                }
                let intersection: std::collections::HashSet<_> =
                    desc_words.intersection(&f_words).cloned().collect();
                let union: std::collections::HashSet<_> =
                    desc_words.union(&f_words).cloned().collect();
                let jaccard = intersection.len() as f64 / union.len() as f64;
                jaccard >= threshold
            })
            .collect()
    }

    /// Boost confidence if a similar finding exists in knowledge base.
    pub fn boost_confidence(
        &self,
        check: &str,
        contract: &str,
        description: &str,
        base_confidence: f64,
    ) -> f64 {
        let similar = self.find_similar(description, 0.5);
        let matching: Vec<_> = similar
            .iter()
            .filter(|f| f.check == check && (f.contract == contract || f.project == contract))
            .collect();
        let boost = (matching.len() as f64 * 0.05).min(0.15);
        (base_confidence + boost).min(1.0)
    }

    /// Import findings from a JSON artifact file (Slither-style or our own).
    pub fn import_from_json(&mut self, json_str: &str) -> Result<usize, serde_json::Error> {
        let mut count = 0;
        // Try our own format first
        if let Ok(our_format) = serde_json::from_str::<Vec<HistoricalFinding>>(json_str) {
            for f in our_format {
                self.add(f);
                count += 1;
            }
            return Ok(count);
        }
        // Try Slither-style artifact format
        if let Ok(slither) = serde_json::from_str::<serde_json::Value>(json_str) {
            if let Some(detectors) = slither
                .get("results")
                .and_then(|r| r.get("detectors"))
                .and_then(|d| d.as_array())
            {
                for detector in detectors {
                    let check = detector
                        .get("check")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown")
                        .to_string();
                    let impact = detector
                        .get("impact")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Informational")
                        .to_string();
                    let description = detector
                        .get("description")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let contract = detector
                        .get("elements")
                        .and_then(|e| e.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|el| el.get("type_specific_fields"))
                        .and_then(|tsf| tsf.get("parent"))
                        .and_then(|p| p.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("Unknown")
                        .to_string();
                    let function = detector
                        .get("elements")
                        .and_then(|e| e.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|el| el.get("name"))
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_string();
                    self.add(HistoricalFinding {
                        project: "imported".to_string(),
                        contract,
                        function,
                        check,
                        description,
                        severity: impact,
                        source_url: None,
                    });
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}
