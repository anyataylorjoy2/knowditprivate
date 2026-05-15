//! Agent traits for the Knowdit pipeline.

use crate::finding::VocabMatchStats;
use crate::pipeline::*;
use async_trait::async_trait;
use std::error::Error;

pub type AgentError = Box<dyn Error + Send + Sync>;
pub type AgentResult<T> = Result<T, AgentError>;

/// Knowledge Mapper: matches project semantics to historical vulnerability patterns
/// via the Knowdit knowledge graph.
#[async_trait]
pub trait KnowledgeMapper: Send + Sync {
    /// Identify the project's business types from its source code & docs.
    async fn classify_business(&self, project_root: &str) -> AgentResult<Vec<BusinessType>>;

    /// Extract DeFi semantics from the project.
    async fn extract_semantics(&self, project_root: &str) -> AgentResult<Vec<DefiSemantic>>;

    /// Given extracted semantics, query the KG for linked vulnerability patterns.
    /// Returns pairs ranked by relevance.
    async fn map_to_pairs(&self, semantics: &[DefiSemantic]) -> AgentResult<Vec<SemanticVulnPair>>;

    /// Optional diagnostic: vocabulary-matching statistics from the most
    /// recent `extract_semantics` call. Default implementation returns
    /// `None`; concrete mappers may override to surface their stats.
    async fn last_vocab_match_stats(&self) -> Option<VocabMatchStats> {
        None
    }
}

/// Specification Generator: concretizes abstract knowledge into project-specific
/// invariants suitable for fuzzing.
#[async_trait]
pub trait SpecificationGenerator: Send + Sync {
    /// Given a semantic-vulnerability pair and project context, generate a spec.
    /// May return None if the pair is not applicable to this project.
    async fn generate(
        &self,
        pair: &SemanticVulnPair,
        project_root: &str,
        memory: &WorkingMemory,
    ) -> AgentResult<Option<AuditSpec>>;

    /// Regenerate a spec given feedback (e.g., "previous spec was contradictory").
    async fn regenerate(
        &self,
        pair: &SemanticVulnPair,
        previous: &AuditSpec,
        feedback: &str,
        project_root: &str,
    ) -> AgentResult<Option<AuditSpec>>;
}

/// Harness Synthesizer: generates Foundry fuzzing harnesses from an audit spec.
#[async_trait]
pub trait HarnessSynthesizer: Send + Sync {
    /// Generate a Foundry harness Solidity source from a spec.
    async fn synthesize(
        &self,
        spec: &AuditSpec,
        project_root: &str,
        memory: &WorkingMemory,
    ) -> AgentResult<FuzzHarness>;

    /// Regenerate harness given compile/runtime errors.
    async fn regenerate(
        &self,
        spec: &AuditSpec,
        previous: &FuzzHarness,
        error: &str,
        project_root: &str,
    ) -> AgentResult<FuzzHarness>;
}

/// Fuzz Executor: runs a harness via Foundry and collects results.
#[async_trait]
pub trait FuzzExecutor: Send + Sync {
    /// Compile and execute the harness; collect coverage and any violations.
    async fn execute(
        &self,
        harness: &FuzzHarness,
        project_root: &str,
        timeout_secs: u64,
    ) -> AgentResult<FuzzResult>;
}

/// Finding Reflector: validates fuzz violations against specifications and
/// project scope, producing final verdicts.
#[async_trait]
pub trait FindingReflector: Send + Sync {
    /// Validate a fuzz result against its originating spec & pair.
    async fn reflect(
        &self,
        pair: &SemanticVulnPair,
        spec: &AuditSpec,
        harness: &FuzzHarness,
        result: &FuzzResult,
        project_root: &str,
    ) -> AgentResult<ReflectionVerdict>;
}
