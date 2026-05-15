//! End-to-end pipeline test using deterministic stub agents.
//!
//! Verifies that the orchestrator correctly threads pairs through
//! the spec → harness → fuzz → reflect loop, including retry on
//! problematic specifications.

use agent_core::{
    AgentResult, AttackType, AuditSpec, BusinessType, DefiSemantic, Element, ElementKind, Finding,
    FindingReflector, FuzzExecutor, FuzzHarness, FuzzOutcome, FuzzResult, HarnessSynthesizer,
    Impact, Invariant, KnowledgeMapper, PipelineConfig, ReflectionVerdict, SemanticVulnPair,
    SpecificationGenerator, VulnerabilityPattern, WorkingMemory,
};
use async_trait::async_trait;
use orchestrator::KnowditOrchestrator;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Mapper that always produces one pair.
struct FixedMapper;

#[async_trait]
impl KnowledgeMapper for FixedMapper {
    async fn classify_business(&self, _root: &str) -> AgentResult<Vec<BusinessType>> {
        Ok(vec![BusinessType::Dexes])
    }
    async fn extract_semantics(&self, _root: &str) -> AgentResult<Vec<DefiSemantic>> {
        Ok(vec![DefiSemantic {
            name: "price oracle".to_string(),
            description: String::new(),
            category: "Dexes".to_string(),
            contracts: vec!["Pool".to_string()],
        }])
    }
    async fn map_to_pairs(&self, semantics: &[DefiSemantic]) -> AgentResult<Vec<SemanticVulnPair>> {
        Ok(semantics
            .iter()
            .map(|s| SemanticVulnPair {
                semantic: s.clone(),
                vulnerability: VulnerabilityPattern {
                    title: "spot price manipulation".to_string(),
                    description: "spot price manipulated via flash loan".to_string(),
                    root_cause: String::new(),
                    severity: "High".to_string(),
                    attack_type: AttackType::Arithmetic.as_str().to_string(),
                },
                relevance: 0.9,
            })
            .collect())
    }
}

/// Spec generator that returns a deterministic spec.
struct FixedSpecGen;

#[async_trait]
impl SpecificationGenerator for FixedSpecGen {
    async fn generate(
        &self,
        pair: &SemanticVulnPair,
        _root: &str,
        _mem: &WorkingMemory,
    ) -> AgentResult<Option<AuditSpec>> {
        Ok(Some(AuditSpec {
            pair_id: format!(
                "{}::{}",
                pair.semantic.name.replace(' ', "_"),
                pair.vulnerability.title.replace(' ', "_")
            ),
            target_contracts: vec!["Pool".to_string()],
            target_function: Some("swap".to_string()),
            dependencies: vec![],
            initial_state: vec![Invariant {
                expression: "pool.liquidity > 0".to_string(),
                description: "pool seeded".to_string(),
            }],
            pre_vuln_state: vec![],
            post_vuln_state: vec![Invariant {
                expression: "pool.price stayed within bounds".to_string(),
                description: "no extreme price shift".to_string(),
            }],
            attack_scenario: "Manipulate via flash loan".to_string(),
        }))
    }

    async fn regenerate(
        &self,
        pair: &SemanticVulnPair,
        previous: &AuditSpec,
        _feedback: &str,
        _root: &str,
    ) -> AgentResult<Option<AuditSpec>> {
        // Just return the same spec.
        let _ = pair;
        Ok(Some(previous.clone()))
    }
}

/// Harness synthesizer that emits a placeholder harness.
struct FixedHarness;

#[async_trait]
impl HarnessSynthesizer for FixedHarness {
    async fn synthesize(
        &self,
        spec: &AuditSpec,
        _root: &str,
        _mem: &WorkingMemory,
    ) -> AgentResult<FuzzHarness> {
        Ok(FuzzHarness {
            spec_id: spec.pair_id.clone(),
            source: "// stub harness".to_string(),
            file_path: "test/stub.t.sol".to_string(),
            test_name: "test_invariant_stub".to_string(),
        })
    }
    async fn regenerate(
        &self,
        spec: &AuditSpec,
        previous: &FuzzHarness,
        _error: &str,
        _root: &str,
    ) -> AgentResult<FuzzHarness> {
        let _ = spec;
        Ok(previous.clone())
    }
}

/// Configurable fuzz executor: first invocation returns Violation, subsequent NoViolation.
struct FixedFuzzExec {
    counter: AtomicUsize,
}

#[async_trait]
impl FuzzExecutor for FixedFuzzExec {
    async fn execute(
        &self,
        harness: &FuzzHarness,
        _root: &str,
        _timeout_secs: u64,
    ) -> AgentResult<FuzzResult> {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        let outcome = if n == 0 {
            FuzzOutcome::Violation {
                trace: "[FAIL] price shifted beyond bound".to_string(),
                state_changes: vec![],
            }
        } else {
            FuzzOutcome::NoViolation
        };
        Ok(FuzzResult {
            harness_id: harness.spec_id.clone(),
            outcome,
            coverage: 0.5,
            raw_output: "stub".to_string(),
        })
    }
}

/// Reflector that confirms violations as findings.
struct FixedReflector;

#[async_trait]
impl FindingReflector for FixedReflector {
    async fn reflect(
        &self,
        pair: &SemanticVulnPair,
        spec: &AuditSpec,
        _harness: &FuzzHarness,
        result: &FuzzResult,
        _root: &str,
    ) -> AgentResult<ReflectionVerdict> {
        match &result.outcome {
            FuzzOutcome::Violation { trace, .. } => Ok(ReflectionVerdict::Confirmed {
                finding: Finding {
                    check: pair.vulnerability.attack_type.clone(),
                    description: format!("{}: {}", pair.vulnerability.title, trace),
                    impact: Impact::High,
                    elements: vec![Element {
                        kind: ElementKind::Function,
                        name: spec.target_function.clone().unwrap_or_default(),
                        contract: spec.primary_contract().to_string(),
                        line: None,
                        column: None,
                    }],
                    confidence: pair.relevance,
                    agent: "stub-reflector".to_string(),
                    swc_id: None,
                    remediation: None,
                },
            }),
            _ => Ok(ReflectionVerdict::ExpectedBehavior {
                reason: "no violation".to_string(),
            }),
        }
    }
}

/// LLM-error-injecting spec generator. Returns the configured error string on
/// every call. Used to verify quota-error checkpoint paths.
struct FailingSpecGen {
    error_msg: String,
}

#[async_trait]
impl SpecificationGenerator for FailingSpecGen {
    async fn generate(
        &self,
        _pair: &SemanticVulnPair,
        _root: &str,
        _mem: &WorkingMemory,
    ) -> AgentResult<Option<AuditSpec>> {
        Err(Box::<dyn std::error::Error + Send + Sync>::from(
            self.error_msg.clone(),
        ))
    }
    async fn regenerate(
        &self,
        _pair: &SemanticVulnPair,
        _prev: &AuditSpec,
        _f: &str,
        _root: &str,
    ) -> AgentResult<Option<AuditSpec>> {
        Err(Box::<dyn std::error::Error + Send + Sync>::from(
            self.error_msg.clone(),
        ))
    }
}

/// Counts how many times spec_gen and harness_synth get invoked.
#[derive(Default)]
struct CountingCounters {
    spec_calls: AtomicUsize,
    harness_calls: AtomicUsize,
}

struct CountingSpecGen {
    counters: Arc<CountingCounters>,
}

#[async_trait]
impl SpecificationGenerator for CountingSpecGen {
    async fn generate(
        &self,
        pair: &SemanticVulnPair,
        _root: &str,
        _mem: &WorkingMemory,
    ) -> AgentResult<Option<AuditSpec>> {
        self.counters.spec_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(AuditSpec {
            pair_id: format!(
                "{}::{}",
                pair.semantic.name.replace(' ', "_"),
                pair.vulnerability.title.replace(' ', "_")
            ),
            target_contracts: vec!["Pool".to_string()],
            target_function: Some("swap".to_string()),
            dependencies: vec![],
            initial_state: vec![],
            pre_vuln_state: vec![],
            post_vuln_state: vec![],
            attack_scenario: "stub".to_string(),
        }))
    }
    async fn regenerate(
        &self,
        _p: &SemanticVulnPair,
        prev: &AuditSpec,
        _f: &str,
        _r: &str,
    ) -> AgentResult<Option<AuditSpec>> {
        self.counters.spec_calls.fetch_add(1, Ordering::SeqCst);
        Ok(Some(prev.clone()))
    }
}

struct CountingHarness {
    counters: Arc<CountingCounters>,
}

#[async_trait]
impl HarnessSynthesizer for CountingHarness {
    async fn synthesize(
        &self,
        spec: &AuditSpec,
        _r: &str,
        _m: &WorkingMemory,
    ) -> AgentResult<FuzzHarness> {
        self.counters.harness_calls.fetch_add(1, Ordering::SeqCst);
        Ok(FuzzHarness {
            spec_id: spec.pair_id.clone(),
            source: "// stub".to_string(),
            file_path: "test/stub.t.sol".to_string(),
            test_name: "test_stub".to_string(),
        })
    }
    async fn regenerate(
        &self,
        _s: &AuditSpec,
        prev: &FuzzHarness,
        _e: &str,
        _r: &str,
    ) -> AgentResult<FuzzHarness> {
        self.counters.harness_calls.fetch_add(1, Ordering::SeqCst);
        Ok(prev.clone())
    }
}

#[tokio::test]
async fn pipeline_confirms_violation_as_finding() {
    let orch = KnowditOrchestrator::new(
        Arc::new(FixedMapper),
        Arc::new(FixedSpecGen),
        Arc::new(FixedHarness),
        Arc::new(FixedFuzzExec {
            counter: AtomicUsize::new(0),
        }),
        Arc::new(FixedReflector),
        PipelineConfig {
            project_path: ".".to_string(),
            min_confidence: 0.5,
            ..Default::default()
        },
    );

    let report = orch.run().await.expect("pipeline runs");
    assert_eq!(report.findings.len(), 1, "exactly one confirmed finding");
    let f = &report.findings[0];
    assert_eq!(f.elements[0].contract, "Pool");
    assert_eq!(f.elements[0].name, "swap");
    assert!(f.confidence >= 0.5);
    assert!(report.agents_run.len() == 5);
}

/// Mapper that produces 3 distinct pairs — used to verify checkpoint behavior.
struct ThreePairMapper;

#[async_trait]
impl KnowledgeMapper for ThreePairMapper {
    async fn classify_business(&self, _root: &str) -> AgentResult<Vec<BusinessType>> {
        Ok(vec![BusinessType::Dexes])
    }
    async fn extract_semantics(&self, _root: &str) -> AgentResult<Vec<DefiSemantic>> {
        Ok(vec![DefiSemantic {
            name: "swap".to_string(),
            description: String::new(),
            category: "Dexes".to_string(),
            contracts: vec!["Pool".to_string()],
        }])
    }
    async fn map_to_pairs(&self, semantics: &[DefiSemantic]) -> AgentResult<Vec<SemanticVulnPair>> {
        Ok((0..3)
            .map(|i| SemanticVulnPair {
                semantic: semantics[0].clone(),
                vulnerability: VulnerabilityPattern {
                    title: format!("vuln {}", i),
                    description: String::new(),
                    root_cause: String::new(),
                    severity: "High".to_string(),
                    attack_type: "Other".to_string(),
                },
                relevance: 0.9,
            })
            .collect())
    }
}

#[tokio::test]
async fn quota_error_checkpoints_and_aborts_run() {
    // Spec gen returns a quota-style error on every call. The orchestrator
    // should catch it on the first pair and abort with a checkpoint instead
    // of crashing the entire run.
    let orch = KnowditOrchestrator::new(
        Arc::new(ThreePairMapper),
        Arc::new(FailingSpecGen {
            error_msg: "LLM API error: status=429 body=usage limit reached for IP".to_string(),
        }),
        Arc::new(FixedHarness),
        Arc::new(FixedFuzzExec {
            counter: AtomicUsize::new(0),
        }),
        Arc::new(FixedReflector),
        PipelineConfig {
            project_path: ".".to_string(),
            min_confidence: 0.5,
            ..Default::default()
        },
    );

    let report = orch.run().await.expect("run should not bubble error");
    assert!(report.checkpointed, "report must be flagged as checkpointed");
    assert!(report.checkpoint_reason.is_some(), "must record reason");
    // First pair recorded as aborted_quota; remaining pairs not processed.
    let aborted = report
        .pair_outcomes
        .iter()
        .filter(|p| p.status == "aborted_quota")
        .count();
    assert_eq!(aborted, 1, "exactly one pair flagged as aborted_quota");
    assert!(
        report.pair_outcomes.len() <= 2,
        "should stop after the abort (got {} outcomes)",
        report.pair_outcomes.len()
    );
}

#[tokio::test]
async fn non_quota_error_propagates() {
    // Verify that non-quota errors still propagate (we don't want to silently
    // swallow real bugs).
    let orch = KnowditOrchestrator::new(
        Arc::new(ThreePairMapper),
        Arc::new(FailingSpecGen {
            error_msg: "Some unrelated network failure".to_string(),
        }),
        Arc::new(FixedHarness),
        Arc::new(FixedFuzzExec {
            counter: AtomicUsize::new(0),
        }),
        Arc::new(FixedReflector),
        PipelineConfig {
            project_path: ".".to_string(),
            min_confidence: 0.5,
            ..Default::default()
        },
    );
    let result = orch.run().await;
    assert!(result.is_err(), "non-quota error must bubble up");
}

#[tokio::test]
async fn mapper_prelude_skips_mapper_phase() {
    // Pre-supply pairs; verify mapper agent's methods are NOT invoked.
    struct PanickingMapper;
    #[async_trait]
    impl KnowledgeMapper for PanickingMapper {
        async fn classify_business(&self, _r: &str) -> AgentResult<Vec<BusinessType>> {
            panic!("classify_business should not be called when prelude is supplied");
        }
        async fn extract_semantics(&self, _r: &str) -> AgentResult<Vec<DefiSemantic>> {
            panic!("extract_semantics should not be called when prelude is supplied");
        }
        async fn map_to_pairs(&self, _s: &[DefiSemantic]) -> AgentResult<Vec<SemanticVulnPair>> {
            panic!("map_to_pairs should not be called when prelude is supplied");
        }
    }

    let pair = SemanticVulnPair {
        semantic: DefiSemantic {
            name: "swap".to_string(),
            description: String::new(),
            category: "Dexes".to_string(),
            contracts: vec!["Pool".to_string()],
        },
        vulnerability: VulnerabilityPattern {
            title: "spot price manipulation".to_string(),
            description: String::new(),
            root_cause: String::new(),
            severity: "High".to_string(),
            attack_type: AttackType::Arithmetic.as_str().to_string(),
        },
        relevance: 0.9,
    };

    let orch = KnowditOrchestrator::new(
        Arc::new(PanickingMapper),
        Arc::new(FixedSpecGen),
        Arc::new(FixedHarness),
        Arc::new(FixedFuzzExec {
            counter: AtomicUsize::new(0),
        }),
        Arc::new(FixedReflector),
        PipelineConfig {
            project_path: ".".to_string(),
            min_confidence: 0.5,
            ..Default::default()
        },
    )
    .with_mapper_prelude((vec![BusinessType::Dexes], vec![], vec![pair]));

    let report = orch.run().await.expect("prelude run succeeds");
    assert_eq!(report.findings.len(), 1, "still confirms the violation");
}

#[tokio::test]
async fn pair_artifact_cache_skips_llm_on_resume() {
    // First run populates the cache. Second run should hit the cache and
    // never call spec_gen.generate or harness_synth.synthesize again.
    let cache_dir = tempfile::tempdir().expect("tmp");
    let cache = Arc::new(knowdit_client::PairArtifactCache::new(cache_dir.path()));
    let counters = Arc::new(CountingCounters::default());

    let make_orch = || {
        KnowditOrchestrator::new(
            Arc::new(FixedMapper),
            Arc::new(CountingSpecGen {
                counters: counters.clone(),
            }),
            Arc::new(CountingHarness {
                counters: counters.clone(),
            }),
            Arc::new(FixedFuzzExec {
                counter: AtomicUsize::new(0),
            }),
            Arc::new(FixedReflector),
            PipelineConfig {
                project_path: "/proj".to_string(),
                min_confidence: 0.5,
                ..Default::default()
            },
        )
        .with_pair_artifact_cache(cache.clone())
    };

    // First run — cold cache.
    let _ = make_orch().run().await.expect("first run");
    assert_eq!(counters.spec_calls.load(Ordering::SeqCst), 1);
    assert_eq!(counters.harness_calls.load(Ordering::SeqCst), 1);

    // Second run — should hit the cache for both spec and harness.
    counters.spec_calls.store(0, Ordering::SeqCst);
    counters.harness_calls.store(0, Ordering::SeqCst);
    let _ = make_orch().run().await.expect("second run");
    assert_eq!(
        counters.spec_calls.load(Ordering::SeqCst),
        0,
        "spec generator must NOT be called on cache hit"
    );
    assert_eq!(
        counters.harness_calls.load(Ordering::SeqCst),
        0,
        "harness synth must NOT be called on cache hit"
    );
}
