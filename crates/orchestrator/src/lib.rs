//! Knowdit-style auditing orchestrator.
//!
//! Coordinates four agents through a shared [`WorkingMemory`]:
//! 1. [`KnowledgeMapper`] — derive semantic-vulnerability pairs from project
//! 2. [`SpecificationGenerator`] — concretize pair into project-specific invariants
//! 3. [`HarnessSynthesizer`] — emit Foundry test harness
//! 4. [`FuzzExecutor`] + [`FindingReflector`] — run, validate, classify
//!
//! On failure (problematic spec / harness), the orchestrator regenerates the
//! corresponding artifact according to feedback in working memory.

use agent_core::{
    AgentResult, AuditSpec, FindingReflector, FuzzExecutor, FuzzHarness, FuzzOutcome,
    FuzzResultSummary, HarnessSynthesizer, KnowledgeMapper, PairOutcome, PipelineConfig,
    ReflectionVerdict, Report, SemanticVulnPair, SpecificationGenerator, WorkingMemory,
};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{debug, info, warn};

pub mod fallback;

/// Hook for an external supplier of `(business, semantics, pairs)` so audit
/// runs can resume from a previously generated mapper.json without re-running
/// the mapper phase. See `--from-mapper` in the CLI.
pub type MapperPrelude = (
    Vec<agent_core::BusinessType>,
    Vec<agent_core::DefiSemantic>,
    Vec<SemanticVulnPair>,
);

/// Top-level orchestrator. Caller wires concrete agent implementations.
pub struct KnowditOrchestrator {
    pub mapper: Arc<dyn KnowledgeMapper>,
    pub spec_gen: Arc<dyn SpecificationGenerator>,
    pub harness_synth: Arc<dyn HarnessSynthesizer>,
    pub fuzz_exec: Arc<dyn FuzzExecutor>,
    pub reflector: Arc<dyn FindingReflector>,
    pub config: PipelineConfig,
    /// If set, skip the mapper phase and use these pairs directly. This is
    /// how `--from-mapper` works: load `mapper.json`, then run downstream
    /// agents on the cached pairs without paying for mapper LLM calls again.
    pub mapper_prelude: Option<MapperPrelude>,
    /// Optional disk path where partial reports get checkpointed mid-run.
    /// When the LLM exhausts its quota or another fatal error occurs, we
    /// flush whatever findings + pair_outcomes we have so the run isn't
    /// wasted.
    pub checkpoint_path: Option<PathBuf>,
    /// Per-pair artifact cache (spec + harness). When set, the orchestrator
    /// reuses cached spec/harness for pair_ids it has previously processed,
    /// avoiding redundant LLM calls on resume.
    pub pair_artifacts: Option<Arc<knowdit_client::PairArtifactCache>>,
}

/// Result of processing a single pair through the pipeline.
struct ProcessResult {
    status: String,
    retries: usize,
    reason: Option<String>,
}

/// Outcome of a single pair iteration that signals to the outer loop
/// whether to continue, abort with a checkpoint, or just record the result.
enum PairLoopOutcome {
    Done(ProcessResult),
    /// LLM hit a hard quota / fatal error. Flush a checkpoint and stop the run.
    AbortQuota { reason: String },
}

impl KnowditOrchestrator {
    pub fn new(
        mapper: Arc<dyn KnowledgeMapper>,
        spec_gen: Arc<dyn SpecificationGenerator>,
        harness_synth: Arc<dyn HarnessSynthesizer>,
        fuzz_exec: Arc<dyn FuzzExecutor>,
        reflector: Arc<dyn FindingReflector>,
        config: PipelineConfig,
    ) -> Self {
        Self {
            mapper,
            spec_gen,
            harness_synth,
            fuzz_exec,
            reflector,
            config,
            mapper_prelude: None,
            checkpoint_path: None,
            pair_artifacts: None,
        }
    }

    /// Skip the mapper phase and use a pre-computed `(business, semantics, pairs)` tuple.
    pub fn with_mapper_prelude(mut self, prelude: MapperPrelude) -> Self {
        self.mapper_prelude = Some(prelude);
        self
    }

    /// Enable mid-run checkpointing to the given path.
    pub fn with_checkpoint_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.checkpoint_path = Some(path.into());
        self
    }

    /// Enable per-pair (spec + harness) caching backed by `cache`.
    pub fn with_pair_artifact_cache(
        mut self,
        cache: Arc<knowdit_client::PairArtifactCache>,
    ) -> Self {
        self.pair_artifacts = Some(cache);
        self
    }

    /// Run the full Knowdit pipeline on a single project root.
    /// Returns a final report aggregating confirmed findings.
    pub async fn run(&self) -> AgentResult<Report> {
        let project_root = self.config.project_path.clone();
        let mut memory = WorkingMemory::new();
        let mut pair_outcomes: Vec<PairOutcome> = Vec::new();
        let start = std::time::Instant::now();
        let mut checkpoint_reason: Option<String> = None;
        let mut vocab_stats = None;

        // Phase 1: Knowledge mapping (or skip if prelude was supplied).
        let pairs: Vec<SemanticVulnPair> = if let Some((_b, _s, pairs)) = &self.mapper_prelude {
            info!(
                "[1/4] Knowledge Mapper: SKIPPED (using pre-loaded mapper prelude with {} pairs)",
                pairs.len()
            );
            pairs.clone()
        } else {
            info!("[1/4] Knowledge Mapper: classifying business and extracting semantics");
            let _business = self.mapper.classify_business(&project_root).await?;
            let semantics = self.mapper.extract_semantics(&project_root).await?;
            // Pull diagnostic stats *after* extract has run.
            vocab_stats = self.mapper.last_vocab_match_stats().await;
            let pairs = self.mapper.map_to_pairs(&semantics).await?;
            info!(
                "Knowledge Mapper produced {} semantic-vulnerability pairs",
                pairs.len()
            );
            pairs
        };

        for pair in pairs.iter().take(self.config.max_pairs) {
            memory.add_pair(pair.clone());
        }

        // Phase 2-4: iterate pairs.
        let pending = std::mem::take(&mut memory.pending_pairs);
        let total_pairs = pending.len();
        for (idx, pair) in pending.into_iter().enumerate() {
            let pid = pair_id(&pair);
            match self
                .process_pair_with_quota_check(&pair, &project_root, &mut memory)
                .await?
            {
                PairLoopOutcome::Done(outcome) => {
                    pair_outcomes.push(PairOutcome {
                        pair_id: pid.clone(),
                        semantic: pair.semantic.name.clone(),
                        vulnerability: pair.vulnerability.title.clone(),
                        status: outcome.status,
                        retries: outcome.retries,
                        reason: outcome.reason,
                    });
                    memory.completed_pair_ids.push(pid);
                }
                PairLoopOutcome::AbortQuota { reason } => {
                    warn!(
                        "Aborting audit at pair {}/{} due to LLM quota: {}",
                        idx + 1,
                        total_pairs,
                        reason
                    );
                    pair_outcomes.push(PairOutcome {
                        pair_id: pid,
                        semantic: pair.semantic.name.clone(),
                        vulnerability: pair.vulnerability.title.clone(),
                        status: "aborted_quota".to_string(),
                        retries: 0,
                        reason: Some(reason.clone()),
                    });
                    checkpoint_reason = Some(reason);
                    break;
                }
            }

            // Periodically write a checkpoint so a long-running audit doesn't
            // lose progress on a hard crash later.
            if let Some(path) = &self.checkpoint_path {
                let partial = self.build_report(
                    project_root.clone(),
                    &memory,
                    pair_outcomes.clone(),
                    start,
                    vocab_stats.clone(),
                    None,
                );
                if let Err(e) = std::fs::write(
                    path,
                    serde_json::to_string_pretty(&partial).unwrap_or_default(),
                ) {
                    warn!("Failed to write checkpoint to {}: {}", path.display(), e);
                }
            }
        }

        // Build report.
        let report = self.build_report(
            project_root,
            &memory,
            pair_outcomes,
            start,
            vocab_stats,
            checkpoint_reason,
        );
        // Final checkpoint write so the on-disk file matches the returned report.
        if let Some(path) = &self.checkpoint_path {
            if let Err(e) =
                std::fs::write(path, serde_json::to_string_pretty(&report).unwrap_or_default())
            {
                warn!("Failed to write final checkpoint: {}", e);
            }
        }
        Ok(report)
    }

    fn build_report(
        &self,
        project_root: String,
        memory: &WorkingMemory,
        pair_outcomes: Vec<PairOutcome>,
        start: std::time::Instant,
        vocab_stats: Option<agent_core::VocabMatchStats>,
        checkpoint_reason: Option<String>,
    ) -> Report {
        let fuzz_history: Vec<FuzzResultSummary> = memory
            .fuzz_history
            .iter()
            .map(|r| {
                let (outcome_str, failure_reason) = match &r.outcome {
                    FuzzOutcome::Violation { .. } => ("violation".to_string(), None),
                    FuzzOutcome::NoViolation => ("no_violation".to_string(), None),
                    FuzzOutcome::HarnessFailure { reason } => {
                        ("harness_failure".to_string(), Some(reason.clone()))
                    }
                    FuzzOutcome::SpecFailure { reason } => {
                        ("spec_failure".to_string(), Some(reason.clone()))
                    }
                };
                FuzzResultSummary {
                    harness_id: r.harness_id.clone(),
                    outcome: outcome_str,
                    failure_reason,
                }
            })
            .collect();

        let mut report = Report::new(project_root);
        report.findings = deduplicate_findings(&memory.confirmed);
        report.agents_run = vec![
            "knowledge-mapper".to_string(),
            "spec-generator".to_string(),
            "harness-synthesizer".to_string(),
            "fuzz-executor".to_string(),
            "finding-reflector".to_string(),
        ];
        report.duration_ms = start.elapsed().as_millis() as u64;
        report.pair_outcomes = pair_outcomes;
        report.fuzz_history = fuzz_history;
        report.vocab_match_stats = vocab_stats;
        if let Some(reason) = checkpoint_reason {
            report.checkpointed = true;
            report.checkpoint_reason = Some(reason);
        }
        report
    }

    async fn process_pair_with_quota_check(
        &self,
        pair: &SemanticVulnPair,
        project_root: &str,
        memory: &mut WorkingMemory,
    ) -> AgentResult<PairLoopOutcome> {
        match self.process_pair(pair, project_root, memory).await {
            Ok(outcome) => Ok(PairLoopOutcome::Done(outcome)),
            Err(e) => {
                let msg = e.to_string();
                if is_quota_error(&msg) {
                    Ok(PairLoopOutcome::AbortQuota { reason: msg })
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Process a single semantic-vulnerability pair through spec → harness → fuzz → reflect.
    async fn process_pair(
        &self,
        pair: &SemanticVulnPair,
        project_root: &str,
        memory: &mut WorkingMemory,
    ) -> AgentResult<ProcessResult> {
        let pid = pair_id(pair);
        debug!("Processing pair {}", pid);

        // Try cached spec first; fall through to LLM and persist on success.
        let mut spec: AuditSpec = match self.try_load_or_generate_spec(pair, project_root, memory, &pid).await? {
            Some(s) => s,
            None => {
                memory.record_feedback(
                    "spec-generator",
                    "generate",
                    "spec-generator returned None; skipping pair",
                );
                return Ok(ProcessResult {
                    status: "skipped".to_string(),
                    retries: 0,
                    reason: Some("spec-generator returned None".to_string()),
                });
            }
        };

        // Try cached harness for this spec.
        let mut harness: FuzzHarness = self
            .try_load_or_generate_harness(&spec, project_root, memory, &pid)
            .await?;

        for attempt in 0..self.config.max_retries {
            let result = self
                .fuzz_exec
                .execute(&harness, project_root, self.config.fuzz_timeout_secs)
                .await?;
            memory.record_fuzz(result.clone());

            // Check for harness failure before calling reflector
            if let FuzzOutcome::HarnessFailure { reason } = &result.outcome {
                warn!("Pair {} attempt {}: harness failure — {}", pid, attempt, reason);
                if attempt + 1 < self.config.max_retries {
                    memory.record_feedback("harness-synthesizer", "regenerate", reason);
                    if let Some(cache) = &self.pair_artifacts {
                        cache.invalidate_harness(project_root, &spec.pair_id);
                    }
                    harness = self
                        .harness_synth
                        .regenerate(&spec, &harness, reason, project_root)
                        .await?;
                    if let Some(cache) = &self.pair_artifacts {
                        let _ = cache.store_harness(project_root, &spec.pair_id, &harness);
                    }
                    continue;
                } else {
                    return Ok(ProcessResult {
                        status: "harness_failure".to_string(),
                        retries: attempt,
                        reason: Some(reason.clone()),
                    });
                }
            }

            let verdict = self
                .reflector
                .reflect(pair, &spec, &harness, &result, project_root)
                .await?;

            match verdict {
                ReflectionVerdict::Confirmed { finding } => {
                    if finding.confidence >= self.config.min_confidence {
                        memory.confirm(finding);
                    } else {
                        memory.record_feedback(
                            "reflector",
                            "confidence",
                            "finding rejected by min_confidence threshold",
                        );
                    }
                    return Ok(ProcessResult {
                        status: "confirmed".to_string(),
                        retries: attempt,
                        reason: None,
                    });
                }
                ReflectionVerdict::ExpectedBehavior { reason } => {
                    memory.record_feedback("reflector", "expected", &reason);
                    return Ok(ProcessResult {
                        status: "expected_behavior".to_string(),
                        retries: attempt,
                        reason: Some(reason),
                    });
                }
                ReflectionVerdict::OutOfScope { reason } => {
                    memory.record_feedback("reflector", "out-of-scope", &reason);
                    return Ok(ProcessResult {
                        status: "out_of_scope".to_string(),
                        retries: attempt,
                        reason: Some(reason),
                    });
                }
                ReflectionVerdict::ProblematicSpecification { reason } => {
                    warn!(
                        "Pair {} attempt {}: regenerating spec — {}",
                        pid, attempt, reason
                    );
                    memory.record_feedback("spec-generator", "regenerate", &reason);
                    if let Some(cache) = &self.pair_artifacts {
                        cache.invalidate_spec(project_root, &pid);
                        cache.invalidate_harness(project_root, &spec.pair_id);
                    }
                    spec = match self
                        .spec_gen
                        .regenerate(pair, &spec, &reason, project_root)
                        .await?
                    {
                        Some(s) => s,
                        None => {
                            return Ok(ProcessResult {
                                status: "spec_failure".to_string(),
                                retries: attempt,
                                reason: Some(reason),
                            })
                        }
                    };
                    if let Some(cache) = &self.pair_artifacts {
                        let _ = cache.store_spec(project_root, &pid, &spec);
                    }
                    harness = self
                        .try_load_or_generate_harness(&spec, project_root, memory, &pid)
                        .await?;
                }
                ReflectionVerdict::ProblematicHarness { reason } => {
                    warn!(
                        "Pair {} attempt {}: regenerating harness — {}",
                        pid, attempt, reason
                    );
                    memory.record_feedback("harness-synthesizer", "regenerate", &reason);
                    if let Some(cache) = &self.pair_artifacts {
                        cache.invalidate_harness(project_root, &spec.pair_id);
                    }
                    harness = self
                        .harness_synth
                        .regenerate(&spec, &harness, &reason, project_root)
                        .await?;
                    if let Some(cache) = &self.pair_artifacts {
                        let _ = cache.store_harness(project_root, &spec.pair_id, &harness);
                    }
                }
            }
        }

        memory.record_feedback(
            "orchestrator",
            "retries-exhausted",
            "max_retries reached; abandoning pair",
        );
        Ok(ProcessResult {
            status: "retries_exhausted".to_string(),
            retries: self.config.max_retries,
            reason: Some("max_retries reached".to_string()),
        })
    }

    /// Load spec from cache if present, otherwise generate via LLM and persist.
    async fn try_load_or_generate_spec(
        &self,
        pair: &SemanticVulnPair,
        project_root: &str,
        memory: &mut WorkingMemory,
        pid: &str,
    ) -> AgentResult<Option<AuditSpec>> {
        if let Some(cache) = &self.pair_artifacts {
            if let Some(cached) = cache.load_spec(project_root, pid) {
                info!("Pair {}: spec cache hit (skipping LLM call)", pid);
                return Ok(Some(cached));
            }
        }
        let spec = self.spec_gen.generate(pair, project_root, memory).await?;
        if let (Some(cache), Some(s)) = (&self.pair_artifacts, &spec) {
            if let Err(e) = cache.store_spec(project_root, pid, s) {
                warn!("Failed to persist spec cache for {}: {}", pid, e);
            }
        }
        Ok(spec)
    }

    /// Load harness from cache if present, otherwise synthesize and persist.
    async fn try_load_or_generate_harness(
        &self,
        spec: &AuditSpec,
        project_root: &str,
        memory: &mut WorkingMemory,
        pid: &str,
    ) -> AgentResult<FuzzHarness> {
        if let Some(cache) = &self.pair_artifacts {
            if let Some(cached) = cache.load_harness(project_root, &spec.pair_id) {
                info!("Pair {}: harness cache hit for spec {}", pid, spec.pair_id);
                return Ok(cached);
            }
        }
        let h = self
            .harness_synth
            .synthesize(spec, project_root, memory)
            .await?;
        if let Some(cache) = &self.pair_artifacts {
            if let Err(e) = cache.store_harness(project_root, &spec.pair_id, &h) {
                warn!("Failed to persist harness cache for {}: {}", pid, e);
            }
        }
        Ok(h)
    }
}

/// Heuristic detector for LLM quota / rate-limit / usage-cap errors.
///
/// Triggers checkpointing instead of crashing when the LLM provider rejects
/// requests due to billing or quota limits. We pattern-match conservatively
/// — false negatives are fine (other errors propagate normally), but false
/// positives would mask real bugs.
fn is_quota_error(msg: &str) -> bool {
    let lower = msg.to_lowercase();
    let quota_signals: &[&str] = &[
        "usage limit",
        "quota",
        "rate limit",
        "rate-limit",
        "ratelimit",
        "rate_limit",
        "too many requests",
        "insufficient_quota",
        "billing",
        "credit balance is too low",
        "you exceeded your current quota",
    ];
    if quota_signals.iter().any(|s| lower.contains(s)) {
        return true;
    }
    // Status 429 or 402 in API error string
    lower.contains("status=429") || lower.contains("status=402") || lower.contains(" 429 ")
}

#[cfg(test)]
mod quota_tests {
    use super::is_quota_error;

    #[test]
    fn detects_codex_usage_limit() {
        assert!(is_quota_error("You've hit your usage limit, try again at 7:28 AM"));
    }

    #[test]
    fn detects_429() {
        assert!(is_quota_error("LLM API error: status=429 body=Too Many Requests"));
    }

    #[test]
    fn detects_anthropic_credit_balance() {
        assert!(is_quota_error("Your credit balance is too low to access the API"));
    }

    #[test]
    fn detects_openai_quota() {
        assert!(is_quota_error(
            "You exceeded your current quota, please check your plan and billing"
        ));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!is_quota_error("Connection refused"));
        assert!(!is_quota_error("HTTP error: timed out"));
        assert!(!is_quota_error("LLM API error: status=500 body=Internal"));
    }
}

/// Deterministic id for a pair (used for dedup / file naming).
pub fn pair_id(pair: &SemanticVulnPair) -> String {
    format!(
        "{}::{}",
        pair.semantic.name.replace(' ', "_"),
        pair.vulnerability.title.replace(' ', "_")
    )
}

/// Deduplicate findings by (check, contract, function_name), keeping the
/// one with the highest confidence.
fn deduplicate_findings(findings: &[agent_core::Finding]) -> Vec<agent_core::Finding> {
    let mut best: HashMap<String, agent_core::Finding> = HashMap::new();
    for f in findings {
        let key = format!(
            "{}::{}::{}",
            f.check,
            f.elements
                .first()
                .map(|e| e.contract.as_str())
                .unwrap_or(""),
            f.elements.first().map(|e| e.name.as_str()).unwrap_or(""),
        );
        let entry = best.entry(key);
        use std::collections::hash_map::Entry;
        match entry {
            Entry::Vacant(e) => {
                e.insert(f.clone());
            }
            Entry::Occupied(mut e) => {
                if f.confidence > e.get().confidence {
                    e.insert(f.clone());
                }
            }
        }
    }
    let mut out: Vec<_> = best.into_values().collect();
    out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
    out
}

use std::collections::HashMap;
