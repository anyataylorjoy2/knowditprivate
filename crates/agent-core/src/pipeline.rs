//! Core types for the Knowdit-style 4-agent auditing pipeline.
//!
//! Based on Knowdit (arXiv:2603.26270), the pipeline consists of:
//! 1. Knowledge Mapper — match project semantics to historical vulnerability patterns
//! 2. Specification Generator — concretize abstract knowledge into project-specific invariants
//! 3. Harness Synthesizer — generate executable Foundry fuzzing harnesses
//! 4. Fuzz Executor — run harness and collect coverage/traces
//! 5. Finding Reflector — validate violations against specifications

use crate::finding::Finding;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Predefined DeFi business types from Knowdit paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BusinessType {
    Lending,
    Dexes,
    Yield,
    Services,
    Derivatives,
    YieldAggregator,
    RealWorldAssets,
    Stablecoins,
    Indexes,
    Insurance,
    NftMarketplace,
    NftLending,
    CrossChain,
    Others,
}

impl BusinessType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Lending => "Lending",
            Self::Dexes => "Dexes",
            Self::Yield => "Yield",
            Self::Services => "Services",
            Self::Derivatives => "Derivatives",
            Self::YieldAggregator => "Yield Aggregator",
            Self::RealWorldAssets => "Real World Assets",
            Self::Stablecoins => "Stablecoins",
            Self::Indexes => "Indexes",
            Self::Insurance => "Insurance",
            Self::NftMarketplace => "NFT Marketplace",
            Self::NftLending => "NFT Lending",
            Self::CrossChain => "Cross Chain",
            Self::Others => "Others",
        }
    }
}

/// Predefined attack types from Knowdit paper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AttackType {
    AccessControl,
    Arithmetic,
    BlockManipulation,
    Cryptographic,
    DenialOfService,
    Reentrancy,
    StorageMemory,
}

impl AttackType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessControl => "Access Control",
            Self::Arithmetic => "Arithmetic",
            Self::BlockManipulation => "Block Manipulation",
            Self::Cryptographic => "Cryptographic",
            Self::DenialOfService => "Denial of Service",
            Self::Reentrancy => "Reentrancy",
            Self::StorageMemory => "Storage & Memory",
        }
    }
}

/// A DeFi semantic — fine-grained economic mechanism extracted from a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefiSemantic {
    pub name: String,
    pub description: String,
    pub category: String,
    pub contracts: Vec<String>,
}

/// A vulnerability pattern — abstract recurring vulnerability from audit history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VulnerabilityPattern {
    pub title: String,
    pub description: String,
    pub root_cause: String,
    pub severity: String,
    pub attack_type: String,
}

/// A semantic-vulnerability pair produced by the Knowledge Mapper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticVulnPair {
    pub semantic: DefiSemantic,
    pub vulnerability: VulnerabilityPattern,
    /// Relevance score from KG (0.0-1.0)
    pub relevance: f64,
}

/// An auditing specification — concrete invariants for a specific project/pair.
///
/// Supports multi-contract targets: `target_contracts[0]` is the primary contract
/// where the vulnerability manifests; subsequent entries are dependencies that
/// need to be deployed and wired in the harness `setUp()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditSpec {
    pub pair_id: String,
    /// Contracts involved in the attack. First entry is the primary target.
    /// Always has at least one entry.
    ///
    /// Accepts either `target_contracts: ["Foo", "Bar"]` or the legacy
    /// `target_contract: "Foo"` (singular) for backward compatibility.
    #[serde(
        default,
        alias = "target_contract",
        deserialize_with = "deserialize_target_contracts"
    )]
    pub target_contracts: Vec<String>,
    pub target_function: Option<String>,
    /// Per-contract deployment recipe (constructor args + post-deploy setters).
    /// Order should match `target_contracts`; contracts not listed here use
    /// default zero-arg constructors.
    #[serde(default)]
    pub dependencies: Vec<ContractDependency>,
    /// State after setUp(): contract deployment + initial accounts/balances.
    pub initial_state: Vec<Invariant>,
    /// Conditions that must hold before the attack triggers.
    pub pre_vuln_state: Vec<Invariant>,
    /// Conditions that should NEVER hold after the attack (violated → vulnerability).
    pub post_vuln_state: Vec<Invariant>,
    /// Brief description of the attack scenario.
    pub attack_scenario: String,
}

impl AuditSpec {
    /// Primary target contract (first entry, panics if empty — invariant of construction).
    pub fn primary_contract(&self) -> &str {
        self.target_contracts
            .first()
            .map(String::as_str)
            .unwrap_or("")
    }
}

/// Custom deserializer that accepts either a list `target_contracts: [...]` or
/// the legacy single string `target_contract: "Foo"` (for backward compat with
/// older LLM outputs and cached JSON).
fn deserialize_target_contracts<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{self, Visitor};
    use std::fmt;

    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            f.write_str("a string or a list of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_string<E: de::Error>(self, v: String) -> Result<Vec<String>, E> {
            Ok(vec![v])
        }
        fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
        fn visit_unit<E: de::Error>(self) -> Result<Vec<String>, E> {
            Ok(Vec::new())
        }
    }
    deserializer.deserialize_any(V)
}

/// A deployment recipe for one contract in a multi-contract audit.
///
/// Used by the Harness Synthesizer to generate `setUp()` that mirrors a
/// real deployment script: instantiate with constructor args, then call
/// post-deploy setters to wire the system together (e.g.,
/// `vault.setStrategy(strategy)`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContractDependency {
    /// Solidity contract name (must appear in `AuditSpec::target_contracts`).
    pub contract: String,
    /// Constructor argument expressions in Solidity syntax. Variables like
    /// `address(this)`, `attacker`, deployed contract names (e.g., `token`)
    /// resolve in the harness scope.
    #[serde(default)]
    pub constructor_args: Vec<String>,
    /// Setter calls executed after all contracts are deployed. Each entry is
    /// the full Solidity statement WITHOUT trailing semicolon, e.g.:
    /// `vault.setStrategy(address(strategy))`.
    #[serde(default)]
    pub post_deploy_setters: Vec<String>,
}

/// A single invariant expression (Solidity-style require condition).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invariant {
    pub expression: String,
    pub description: String,
}

/// A Foundry fuzzing harness generated by the Harness Synthesizer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzHarness {
    pub spec_id: String,
    /// Generated Solidity source for the harness.
    pub source: String,
    /// File path where the harness should be written.
    pub file_path: String,
    /// Foundry test function name (e.g. "test_invariant_priceManipulation").
    pub test_name: String,
}

/// Result of running a fuzzing harness.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub harness_id: String,
    pub outcome: FuzzOutcome,
    /// Line coverage achieved (0.0-1.0) on target contract.
    pub coverage: f64,
    /// Stdout/stderr from forge test for debugging.
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FuzzOutcome {
    /// Fuzzer found a violation of the post-vuln invariant.
    Violation {
        trace: String,
        state_changes: Vec<StateChange>,
    },
    /// Fuzzer ran to completion without finding violations.
    NoViolation,
    /// Harness failed to compile or had setup errors.
    HarnessFailure { reason: String },
    /// Specification was problematic (e.g., contradictory invariants).
    SpecFailure { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub variable: String,
    pub before: String,
    pub after: String,
}

/// Verdict from the Finding Reflector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReflectionVerdict {
    /// Confirmed vulnerability — should be reported.
    Confirmed { finding: Finding },
    /// Violation matched spec but is out-of-scope per project rules.
    OutOfScope { reason: String },
    /// Violation is an expected revert / intended behavior.
    ExpectedBehavior { reason: String },
    /// Specification was wrong/incomplete; regenerate.
    ProblematicSpecification { reason: String },
    /// Harness was wrong/incomplete; regenerate.
    ProblematicHarness { reason: String },
}

/// Shared working memory across agents in the pipeline.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WorkingMemory {
    /// Pairs currently being processed.
    pub pending_pairs: Vec<SemanticVulnPair>,
    /// Pairs already processed (for dedup and avoiding re-work).
    pub completed_pair_ids: Vec<String>,
    /// Line coverage per contract — used by Mapper to prefer less-tested semantics.
    pub coverage: HashMap<String, f64>,
    /// History of fuzz results.
    pub fuzz_history: Vec<FuzzResult>,
    /// Confirmed findings ready to be reported.
    pub confirmed: Vec<Finding>,
    /// Feedback log for prompts / regeneration.
    pub feedback: Vec<FeedbackEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeedbackEntry {
    pub agent: String,
    pub stage: String,
    pub message: String,
    pub timestamp_ms: u64,
}

impl WorkingMemory {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_pair(&mut self, pair: SemanticVulnPair) {
        self.pending_pairs.push(pair);
    }

    pub fn record_feedback(&mut self, agent: &str, stage: &str, message: &str) {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        self.feedback.push(FeedbackEntry {
            agent: agent.to_string(),
            stage: stage.to_string(),
            message: message.to_string(),
            timestamp_ms,
        });
    }

    pub fn confirm(&mut self, finding: Finding) {
        self.confirmed.push(finding);
    }

    pub fn record_fuzz(&mut self, result: FuzzResult) {
        if let FuzzOutcome::NoViolation = result.outcome {
            // Update coverage tracking
            self.coverage
                .insert(result.harness_id.clone(), result.coverage);
        }
        self.fuzz_history.push(result);
    }
}

/// Configuration for a pipeline run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Path to project root.
    pub project_path: String,
    /// Maximum number of semantic-vulnerability pairs to process.
    pub max_pairs: usize,
    /// Maximum retries for spec/harness regeneration per pair.
    pub max_retries: usize,
    /// Fuzz campaign timeout in seconds per harness.
    pub fuzz_timeout_secs: u64,
    /// Whether to skip pairs whose semantic has high coverage already.
    pub coverage_aware: bool,
    /// Minimum confidence to include a finding in the final report.
    pub min_confidence: f64,
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self {
            project_path: ".".to_string(),
            max_pairs: 20,
            max_retries: 3,
            fuzz_timeout_secs: 60,
            coverage_aware: true,
            min_confidence: 0.5,
        }
    }
}
