use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level of a vulnerability finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Impact {
    Informational,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Impact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Impact::Informational => write!(f, "Informational"),
            Impact::Low => write!(f, "Low"),
            Impact::Medium => write!(f, "Medium"),
            Impact::High => write!(f, "High"),
            Impact::Critical => write!(f, "Critical"),
        }
    }
}

/// A specific element in the code where a finding applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Element {
    pub kind: ElementKind,
    pub name: String,
    pub contract: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ElementKind {
    Function,
    Variable,
    Modifier,
    Event,
    Contract,
    Statement,
    Expression,
}

/// A vulnerability finding produced by an agent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Unique identifier for the check/pattern that produced this finding.
    pub check: String,
    /// Human-readable description of the vulnerability.
    pub description: String,
    /// Severity level.
    pub impact: Impact,
    /// Code elements associated with this finding.
    pub elements: Vec<Element>,
    /// Confidence score (0.0 to 1.0). Higher means more certain.
    pub confidence: f64,
    /// The agent that produced this finding.
    pub agent: String,
    /// Optional CWE / SWC identifier.
    pub swc_id: Option<String>,
    /// Optional remediation suggestion.
    pub remediation: Option<String>,
}

impl Finding {
    pub fn builder(check: impl Into<String>, agent: impl Into<String>) -> FindingBuilder {
        FindingBuilder::new(check, agent)
    }

    /// A unique key for deduplication: (check, contract, function_name).
    pub fn dedup_key(&self) -> String {
        let contract = self
            .elements
            .first()
            .map(|e| e.contract.clone())
            .unwrap_or_default();
        let name = self
            .elements
            .first()
            .map(|e| e.name.clone())
            .unwrap_or_default();
        format!(
            "{}::{}::{}::{}::{}::{}::{}::{}::",
            self.check,
            contract,
            name,
            self.description,
            self.impact,
            self.confidence,
            self.agent,
            self.swc_id.clone().unwrap_or_default()
        )
    }

    /// Check if this finding is a duplicate of another based on semantic similarity.
    pub fn is_duplicate_of(&self, other: &Finding) -> bool {
        if self.check != other.check {
            return false;
        }
        if self.impact != other.impact {
            return false;
        }
        // Same contract + same primary element name
        let self_contract = self.elements.first().map(|e| e.contract.as_str());
        let other_contract = other.elements.first().map(|e| e.contract.as_str());
        let self_name = self.elements.first().map(|e| e.name.as_str());
        let other_name = other.elements.first().map(|e| e.name.as_str());
        self_contract == other_contract && self_name == other_name
    }
}

pub struct FindingBuilder {
    check: String,
    agent: String,
    description: String,
    impact: Impact,
    elements: Vec<Element>,
    confidence: f64,
    swc_id: Option<String>,
    remediation: Option<String>,
}

impl FindingBuilder {
    pub fn new(check: impl Into<String>, agent: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            agent: agent.into(),
            description: String::new(),
            impact: Impact::Informational,
            elements: Vec::new(),
            confidence: 0.5,
            swc_id: None,
            remediation: None,
        }
    }

    pub fn description(mut self, desc: impl Into<String>) -> Self {
        self.description = desc.into();
        self
    }

    pub fn impact(mut self, impact: Impact) -> Self {
        self.impact = impact;
        self
    }

    pub fn element(
        mut self,
        kind: ElementKind,
        name: impl Into<String>,
        contract: impl Into<String>,
    ) -> Self {
        self.elements.push(Element {
            kind,
            name: name.into(),
            contract: contract.into(),
            line: None,
            column: None,
        });
        self
    }

    pub fn with_line(mut self, line: usize) -> Self {
        if let Some(last) = self.elements.last_mut() {
            last.line = Some(line);
        }
        self
    }

    pub fn confidence(mut self, c: f64) -> Self {
        self.confidence = c.clamp(0.0, 1.0);
        self
    }

    pub fn swc_id(mut self, id: impl Into<String>) -> Self {
        self.swc_id = Some(id.into());
        self
    }

    pub fn remediation(mut self, r: impl Into<String>) -> Self {
        self.remediation = Some(r.into());
        self
    }

    pub fn build(self) -> Finding {
        Finding {
            check: self.check,
            description: self.description,
            impact: self.impact,
            elements: self.elements,
            confidence: self.confidence,
            agent: self.agent,
            swc_id: self.swc_id,
            remediation: self.remediation,
        }
    }
}

/// Report format compatible with Slither artifacts for backward compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub source: String,
    pub duration_ms: u64,
    pub agents_run: Vec<String>,
    /// Diagnostic: per-pair outcomes from the pipeline run.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pair_outcomes: Vec<PairOutcome>,
    /// Diagnostic: fuzz execution history (compilation failures, etc.).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fuzz_history: Vec<FuzzResultSummary>,
    /// Diagnostic: KG vocabulary-matching statistics from the Knowledge Mapper.
    /// Helps measure efficiency of the LLM matching step (paper Section 3.3.2).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vocab_match_stats: Option<VocabMatchStats>,
    /// Whether this report was checkpointed mid-run (e.g. due to LLM quota exhaustion).
    /// When true, the audit was aborted before processing every pair.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub checkpointed: bool,
    /// If checkpointed, a short reason string (e.g. "llm_quota_exhausted").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_reason: Option<String>,
}

/// Statistics about the KG vocabulary-matching sub-step in the Knowledge Mapper.
///
/// This is the paper's Section 3.3.2 step: LLM matches extracted DeFi semantics
/// to canonical KG vocabulary names. Tracking these stats lets us measure
/// whether the matcher is producing useful matches (vs. the historical 0/35).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VocabMatchStats {
    /// Number of business types fed to the KG vocabulary fetch (post cap).
    pub business_types_used: usize,
    /// Total raw KG vocabulary entries returned across all business types.
    pub kg_vocab_total: usize,
    /// KG vocabulary entries after canonical-name filtering.
    pub kg_vocab_filtered: usize,
    /// Number of extracted semantics fed to the matcher.
    pub extracted_semantics: usize,
    /// Number of vocabulary candidates after heuristic prefilter (sum across semantics).
    pub candidates_after_prefilter: usize,
    /// Number of LLM matching calls that were issued (0 if cache hit).
    pub llm_calls: usize,
    /// Number of extracted semantics successfully matched to a KG name.
    pub matched: usize,
    /// True if the result came from the disk cache (no LLM call).
    pub cache_hit: bool,
}

/// Summary of a single pair's journey through the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairOutcome {
    pub pair_id: String,
    pub semantic: String,
    pub vulnerability: String,
    /// Final status: "confirmed", "expected_behavior", "out_of_scope",
    /// "harness_failure", "spec_failure", "retries_exhausted", "skipped"
    pub status: String,
    /// Number of retry attempts (0 = first attempt succeeded).
    #[serde(default)]
    pub retries: usize,
    /// Brief reason for non-confirmed status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Summarized fuzz result for diagnostics (excludes raw_output to keep JSON small).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResultSummary {
    pub harness_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
}

impl Report {
    pub fn new(source: impl Into<String>) -> Self {
        Self {
            findings: Vec::new(),
            source: source.into(),
            duration_ms: 0,
            agents_run: Vec::new(),
            pair_outcomes: Vec::new(),
            fuzz_history: Vec::new(),
            vocab_match_stats: None,
            checkpointed: false,
            checkpoint_reason: None,
        }
    }

    pub fn add_finding(&mut self, finding: Finding) {
        self.findings.push(finding);
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Filter findings by minimum confidence.
    pub fn filter_confidence(&self, min: f64) -> Vec<&Finding> {
        self.findings
            .iter()
            .filter(|f| f.confidence >= min)
            .collect()
    }

    /// Get unique agents that produced findings.
    pub fn agents(&self) -> Vec<String> {
        let mut agents: Vec<String> = self.findings.iter().map(|f| f.agent.clone()).collect();
        agents.sort();
        agents.dedup();
        agents
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_builder() {
        let f = Finding::builder("missing-zero-check", "pattern-matcher")
            .description("Owner can reset the timelock address repeatedly")
            .impact(Impact::Low)
            .element(ElementKind::Function, "deploy", "FraxlendPairDeployer")
            .confidence(0.85)
            .build();

        assert_eq!(f.check, "missing-zero-check");
        assert_eq!(f.impact, Impact::Low);
        assert_eq!(f.confidence, 0.85);
        assert_eq!(f.elements.len(), 1);
    }

    #[test]
    fn test_duplicate_detection() {
        let a = Finding::builder("reentrancy", "pattern")
            .element(ElementKind::Function, "withdraw", "Vault")
            .impact(Impact::High)
            .build();
        let b = Finding::builder("reentrancy", "pattern")
            .element(ElementKind::Function, "withdraw", "Vault")
            .impact(Impact::High)
            .build();
        let c = Finding::builder("reentrancy", "pattern")
            .element(ElementKind::Function, "deposit", "Vault")
            .impact(Impact::High)
            .build();

        assert!(a.is_duplicate_of(&b));
        assert!(!a.is_duplicate_of(&c));
    }
}
