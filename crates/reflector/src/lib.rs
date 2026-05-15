//! Finding Reflector agent — validates fuzz violations against spec & project scope.

use agent_core::{
    AgentResult, AuditSpec, Element, ElementKind, Finding, FindingReflector, FuzzHarness,
    FuzzOutcome, FuzzResult, Impact, ReflectionVerdict, SemanticVulnPair,
};
use agent_llm::LlmClient;
use async_trait::async_trait;
use std::collections::HashSet;
use tracing::{info, warn};

pub use scope::Code4renaScope;

mod scope {
    use super::*;

    /// Code4rena scope configuration for filtering out-of-scope findings.
    #[derive(Debug, Clone, Default)]
    pub struct Code4renaScope {
        /// Contracts that are explicitly out-of-scope
        pub out_of_scope_contracts: HashSet<String>,
        /// Functions that are explicitly out-of-scope (format: "Contract.function")
        pub out_of_scope_functions: HashSet<String>,
        /// Known issues from previous audits (format: "Contract:issue_description")
        pub known_issues: HashSet<String>,
        /// Whether to enforce Code4rena scope rules
        pub enforce_scope: bool,
    }

    impl Code4renaScope {
        pub fn is_enforced(&self) -> bool {
            self.enforce_scope
        }

        /// Create scope configuration from environment variables
        pub fn from_env() -> Self {
            let mut scope = Self::default();

            // Parse SOL_AGENT_ENFORCE_SCOPE
            if let Ok(enforce) = std::env::var("SOL_AGENT_ENFORCE_SCOPE") {
                scope.enforce_scope = enforce.parse().unwrap_or(false);
            }

            // Parse SOL_AGENT_OUT_OF_SCOPE_CONTRACTS (comma-separated)
            if let Ok(contracts) = std::env::var("SOL_AGENT_OUT_OF_SCOPE_CONTRACTS") {
                scope.out_of_scope_contracts = contracts
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }

            // Parse SOL_AGENT_OUT_OF_SCOPE_FUNCTIONS (comma-separated)
            if let Ok(functions) = std::env::var("SOL_AGENT_OUT_OF_SCOPE_FUNCTIONS") {
                scope.out_of_scope_functions = functions
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }

            // Parse SOL_AGENT_KNOWN_ISSUES (comma-separated)
            if let Ok(issues) = std::env::var("SOL_AGENT_KNOWN_ISSUES") {
                scope.known_issues = issues
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }

            scope
        }
    }
}

/// LLM-driven reflector with deterministic fallback when no LLM is available.
pub struct LlmReflector {
    client: Option<LlmClient>,
    scope: Code4renaScope,
}

impl LlmReflector {
    pub fn new(client: Option<LlmClient>) -> Self {
        Self {
            client,
            scope: Code4renaScope::default(),
        }
    }

    pub fn with_scope(mut self, scope: Code4renaScope) -> Self {
        self.scope = scope;
        self
    }

    /// Check if a finding is out of scope according to Code4rena rules
    fn check_scope(&self, finding: &Finding) -> Option<String> {
        if !self.scope.is_enforced() {
            return None;
        }

        // Check if contract is out of scope
        for element in &finding.elements {
            if self
                .scope
                .out_of_scope_contracts
                .contains(&element.contract)
            {
                return Some(format!(
                    "Contract {} is explicitly out of scope",
                    element.contract
                ));
            }

            // Check if function is out of scope
            let func_name = &element.name;
            if !func_name.is_empty() {
                let func_key = format!("{}.{}", element.contract, func_name);
                if self.scope.out_of_scope_functions.contains(&func_key) {
                    return Some(format!("Function {} is explicitly out of scope", func_key));
                }
            }
        }

        // Check if this is a known issue from previous audits
        for known_issue in &self.scope.known_issues {
            if finding.description.contains(known_issue) {
                return Some(format!(
                    "Finding matches known issue from previous audit: {}",
                    known_issue
                ));
            }
        }

        None
    }
}

impl Default for LlmReflector {
    fn default() -> Self {
        Self {
            client: agent_llm::LlmConfig::from_env().map(agent_llm::LlmClient::new),
            scope: Code4renaScope::default(),
        }
    }
}

#[async_trait]
impl FindingReflector for LlmReflector {
    async fn reflect(
        &self,
        pair: &SemanticVulnPair,
        spec: &AuditSpec,
        harness: &FuzzHarness,
        result: &FuzzResult,
        _project_root: &str,
    ) -> AgentResult<ReflectionVerdict> {
        // Fast path: deterministic verdicts for non-violation outcomes.
        match &result.outcome {
            FuzzOutcome::NoViolation => {
                // Try LLM to distinguish between ExpectedBehavior and PoC-style Confirmed
                if let Some(client) = &self.client {
                    if client.is_enabled() {
                        match llm_reflect_no_violation(
                            pair,
                            spec,
                            harness,
                            &result.raw_output,
                            client,
                        )
                        .await
                        {
                            Ok(verdict) => {
                                info!("LLM reflector (NoViolation) returned verdict");
                                // Apply scope check to confirmed findings
                                if let ReflectionVerdict::Confirmed { ref finding } = verdict {
                                    if let Some(scope_reason) = self.check_scope(finding) {
                                        return Ok(ReflectionVerdict::OutOfScope {
                                            reason: scope_reason,
                                        });
                                    }
                                }
                                return Ok(verdict);
                            }
                            Err(e) => {
                                warn!(
                                    "LLM reflection failed: {}, falling back to ExpectedBehavior",
                                    e
                                );
                            }
                        }
                    }
                }
                return Ok(ReflectionVerdict::ExpectedBehavior {
                    reason: "Fuzzer did not violate post-vuln invariant".to_string(),
                });
            }
            FuzzOutcome::HarnessFailure { reason } => {
                return Ok(ReflectionVerdict::ProblematicHarness {
                    reason: reason.clone(),
                });
            }
            FuzzOutcome::SpecFailure { reason } => {
                return Ok(ReflectionVerdict::ProblematicSpecification {
                    reason: reason.clone(),
                });
            }
            FuzzOutcome::Violation { trace, .. } => {
                // Try LLM for nuanced verdict; fall back to simple confirmed.
                if let Some(client) = &self.client {
                    if client.is_enabled() {
                        match llm_reflect(pair, spec, harness, trace, client).await {
                            Ok(verdict) => {
                                info!("LLM reflector returned nuanced verdict");
                                // Apply scope check to confirmed findings
                                if let ReflectionVerdict::Confirmed { ref finding } = verdict {
                                    if let Some(scope_reason) = self.check_scope(finding) {
                                        return Ok(ReflectionVerdict::OutOfScope {
                                            reason: scope_reason,
                                        });
                                    }
                                }
                                return Ok(verdict);
                            }
                            Err(e) => {
                                warn!(
                                    "LLM reflection failed: {}, falling back to deterministic",
                                    e
                                );
                            }
                        }
                    }
                }

                let finding = build_finding(pair, spec, trace);
                // Apply scope check to confirmed findings
                if let Some(scope_reason) = self.check_scope(&finding) {
                    return Ok(ReflectionVerdict::OutOfScope {
                        reason: scope_reason,
                    });
                }
                Ok(ReflectionVerdict::Confirmed { finding })
            }
        }
    }
}

async fn llm_reflect(
    pair: &SemanticVulnPair,
    spec: &AuditSpec,
    harness: &FuzzHarness,
    trace: &str,
    client: &LlmClient,
) -> Result<ReflectionVerdict, agent_llm::LlmError> {
    let prompt = format!(
        r#"You are a senior smart contract security auditor reviewing a fuzzing violation.

VULNERABILITY PATTERN:
- Title: {title}
- Description: {desc}
- Severity: {severity}
- Attack Type: {attack_type}

AUDIT SPEC:
- Target Contract: {contract}
- Target Function: {function}
- Attack Scenario: {scenario}

POST-VULN INVARIANTS THAT SHOULD NEVER BE VIOLATED:
{invariants}

FUZZING HARNESS SOURCE:
```solidity
{source}
```

VIOLATION TRACE / LOG:
```
{trace}
```

Your task: classify this violation into exactly one category. Respond ONLY with the following format (no markdown, no extra text):

VERDICT: <Confirmed|OutOfScope|ExpectedBehavior|ProblematicSpecification|ProblematicHarness>
REASON: <concise explanation>

Definitions:
- Confirmed: the violation is a real, exploitable vulnerability matching the pattern. The PoC must demonstrate concrete impact (loss of funds, unauthorized state change, etc.), not just that a function can be called.
- OutOfScope: the violation exists but is outside the project's threat model or not exploitable in practice.
- ExpectedBehavior: the trace shows intended behavior (e.g., a proper revert).
- ProblematicSpecification: the spec was wrong or impossible to satisfy.
- ProblematicHarness: the test harness has a bug (compilation error, wrong setup, etc.).

CRITICAL — Common false positive patterns to reject:
1. initialize() front-running: If the harness calls initialize() on a freshly deployed contract without going through the factory, this is NOT a real vulnerability. Factories call initialize() atomically in the same transaction as deployment.
2. UUPS implementation initialization: Calling initialize() on the implementation contract of a proxy pattern is NOT exploitable.
3. Tests using vm.prank to bypass access control that exists in the real contract.
4. Violations that only prove a function exists and can be called, without showing concrete exploitable impact.

Be conservative: when in doubt, classify as OutOfScope or ExpectedBehavior rather than Confirmed.
"#,
        title = pair.vulnerability.title,
        desc = pair.vulnerability.description,
        severity = pair.vulnerability.severity,
        attack_type = pair.vulnerability.attack_type,
        contract = format_contracts(&spec.target_contracts),
        function = spec.target_function.as_deref().unwrap_or("(any)"),
        scenario = spec.attack_scenario,
        invariants = spec
            .post_vuln_state
            .iter()
            .map(|i| format!("- {} ({})", i.expression, i.description))
            .collect::<Vec<_>>()
            .join("\n"),
        source = harness.source,
        trace = truncate(trace, 2000),
    );

    let response = client.complete(&prompt).await?;
    Ok(parse_verdict(&response, pair, spec, trace))
}

/// Render target contracts for a prompt (primary first, dependencies in parens).
fn format_contracts(contracts: &[String]) -> String {
    match contracts {
        [] => "(none)".to_string(),
        [primary] => primary.clone(),
        [primary, rest @ ..] => format!("{} (with deps: {})", primary, rest.join(", ")),
    }
}

async fn llm_reflect_no_violation(
    pair: &SemanticVulnPair,
    spec: &AuditSpec,
    harness: &FuzzHarness,
    forge_output: &str,
    client: &LlmClient,
) -> Result<ReflectionVerdict, agent_llm::LlmError> {
    let prompt = format!(
        r#"You are a senior smart contract security auditor reviewing a Foundry test that PASSED.

VULNERABILITY PATTERN:
- Title: {title}
- Description: {desc}
- Severity: {severity}
- Attack Type: {attack_type}

AUDIT SPEC:
- Target Contract: {contract}
- Target Function: {function}
- Attack Scenario: {scenario}

POST-VULN INVARIANTS (should be violated by the bug):
{invariants}

FUZZING HARNESS SOURCE:
```solidity
{source}
```

FORGE TEST OUTPUT:
```
{forge_output}
```

Your task: classify this test result into exactly one category. Respond ONLY with the following format (no markdown, no extra text):

VERDICT: <Confirmed|ExpectedBehavior|OutOfScope>
REASON: <concise explanation>

Definitions:
- Confirmed: The test is a PoC (Proof of Concept) that PASSES because the vulnerability is present. The harness successfully demonstrates the bug. IMPORTANT: The PoC must show an actual exploitable scenario, not just that a function exists and can be called.
- ExpectedBehavior: The test passes because there is no vulnerability - the system behaves correctly as intended.
- OutOfScope: The test passes but the vulnerability is not applicable to this project's context.

CRITICAL — Common false positive patterns to watch for:
1. initialize() front-running: If the harness calls initialize() on a freshly deployed contract without going through the factory, this is NOT a real vulnerability. Factories call initialize() atomically in the same transaction as deployment, leaving no front-running window.
2. UUPS implementation initialization: Calling initialize() on the implementation contract of a proxy pattern is NOT exploitable — the implementation's storage is never used directly.
3. Owner-only functions tested with prank: If the harness uses vm.prank(attacker) to bypass access control but the real contract has proper onlyOwner/onlyRole modifiers, the test is demonstrating the modifier works, not a vulnerability.
4. Tests that only prove "function exists and can be called": A test that calls a function and checks the result is NOT a PoC — it must show an actual loss of funds, unauthorized state change, or other concrete impact.

Be conservative: when in doubt, classify as ExpectedBehavior rather than Confirmed.
"#,
        title = pair.vulnerability.title,
        desc = pair.vulnerability.description,
        severity = pair.vulnerability.severity,
        attack_type = pair.vulnerability.attack_type,
        contract = format_contracts(&spec.target_contracts),
        function = spec.target_function.as_deref().unwrap_or("(any)"),
        scenario = spec.attack_scenario,
        invariants = spec
            .post_vuln_state
            .iter()
            .map(|i| format!("- {} ({})", i.expression, i.description))
            .collect::<Vec<_>>()
            .join("\n"),
        source = harness.source,
        forge_output = truncate(forge_output, 2000),
    );

    let response = client.complete(&prompt).await?;
    Ok(parse_verdict_no_violation(
        &response,
        pair,
        spec,
        forge_output,
    ))
}

fn parse_verdict_no_violation(
    response: &str,
    pair: &SemanticVulnPair,
    spec: &AuditSpec,
    forge_output: &str,
) -> ReflectionVerdict {
    let mut verdict_str = None;
    let mut reason = String::new();

    for line in response.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("VERDICT:") {
            verdict_str = Some(val.trim().to_lowercase());
        } else if let Some(val) = line.strip_prefix("REASON:") {
            reason = val.trim().to_string();
        } else if !reason.is_empty() && !line.is_empty() {
            reason.push(' ');
            reason.push_str(line);
        }
    }

    match verdict_str.as_deref() {
        Some("confirmed") => {
            let finding = build_finding(pair, spec, forge_output);
            ReflectionVerdict::Confirmed { finding }
        }
        Some("expectedbehavior") | Some("expected_behavior") | Some("expected-behavior") => {
            ReflectionVerdict::ExpectedBehavior { reason }
        }
        Some("outofscope") | Some("out_of_scope") | Some("out-of-scope") => {
            ReflectionVerdict::OutOfScope { reason }
        }
        _ => {
            // Default to ExpectedBehavior for ambiguous responses
            ReflectionVerdict::ExpectedBehavior {
                reason: format!(
                    "Ambiguous LLM response, defaulting to ExpectedBehavior. Response: {}",
                    response
                ),
            }
        }
    }
}

fn parse_verdict(
    response: &str,
    pair: &SemanticVulnPair,
    spec: &AuditSpec,
    trace: &str,
) -> ReflectionVerdict {
    let mut verdict_str = None;
    let mut reason = String::new();

    for line in response.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("VERDICT:") {
            verdict_str = Some(val.trim().to_lowercase());
        } else if let Some(val) = line.strip_prefix("REASON:") {
            reason = val.trim().to_string();
        } else if !reason.is_empty() && !line.is_empty() {
            reason.push(' ');
            reason.push_str(line);
        }
    }

    match verdict_str.as_deref() {
        Some("outofscope") | Some("out_of_scope") | Some("out-of-scope") => {
            ReflectionVerdict::OutOfScope { reason }
        }
        Some("expectedbehavior") | Some("expected_behavior") | Some("expected-behavior") => {
            ReflectionVerdict::ExpectedBehavior { reason }
        }
        Some("problematicspecification")
        | Some("problematic_specification")
        | Some("problematic-specification") => {
            ReflectionVerdict::ProblematicSpecification { reason }
        }
        Some("problematicharness") | Some("problematic_harness") | Some("problematic-harness") => {
            ReflectionVerdict::ProblematicHarness { reason }
        }
        _ => {
            let finding = build_finding(pair, spec, trace);
            ReflectionVerdict::Confirmed { finding }
        }
    }
}

fn build_finding(pair: &SemanticVulnPair, spec: &AuditSpec, trace: &str) -> Finding {
    Finding {
        check: pair.vulnerability.attack_type.clone(),
        description: format!(
            "{}\nScenario: {}\nTrace excerpt: {}",
            pair.vulnerability.title,
            spec.attack_scenario,
            truncate(trace, 800),
        ),
        impact: parse_impact(&pair.vulnerability.severity),
        elements: spec
            .target_contracts
            .iter()
            .enumerate()
            .map(|(idx, contract)| Element {
                kind: ElementKind::Function,
                // Only attach the function name to the primary contract.
                name: if idx == 0 {
                    spec.target_function.clone().unwrap_or_default()
                } else {
                    String::new()
                },
                contract: contract.clone(),
                line: None,
                column: None,
            })
            .collect(),
        confidence: pair.relevance,
        agent: "reflector".to_string(),
        swc_id: None,
        remediation: None,
    }
}

fn parse_impact(s: &str) -> Impact {
    match s.to_lowercase().as_str() {
        "critical" => Impact::Critical,
        "high" => Impact::High,
        "medium" => Impact::Medium,
        "low" => Impact::Low,
        _ => Impact::Informational,
    }
}

fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_core::{
        DefiSemantic, FuzzHarness, FuzzOutcome, FuzzResult, Invariant, VulnerabilityPattern,
    };

    fn make_pair() -> SemanticVulnPair {
        SemanticVulnPair {
            semantic: DefiSemantic {
                name: "share accounting".to_string(),
                description: "ERC4626 share/asset conversion".to_string(),
                category: "Yield Aggregator".to_string(),
                contracts: vec!["Vault".to_string()],
            },
            vulnerability: VulnerabilityPattern {
                title: "First depositor share inflation".to_string(),
                description: "Attacker can inflate share price".to_string(),
                root_cause: "Missing min deposit check".to_string(),
                severity: "High".to_string(),
                attack_type: "Arithmetic".to_string(),
            },
            relevance: 0.95,
        }
    }

    fn make_spec() -> AuditSpec {
        AuditSpec {
            pair_id: "test_id".to_string(),
            target_contracts: vec!["Vault".to_string()],
            target_function: Some("deposit".to_string()),
            dependencies: vec![],
            initial_state: vec![],
            pre_vuln_state: vec![],
            post_vuln_state: vec![Invariant {
                expression: "totalAssets >= amount".to_string(),
                description: "assets cover deposit".to_string(),
            }],
            attack_scenario: "Donate then deposit 1 wei".to_string(),
        }
    }

    fn make_harness() -> FuzzHarness {
        FuzzHarness {
            spec_id: "test_id".to_string(),
            source: "contract Test {}".to_string(),
            file_path: "test/Test.t.sol".to_string(),
            test_name: "test_invariant".to_string(),
        }
    }

    #[test]
    fn test_parse_verdict_confirmed() {
        let pair = make_pair();
        let spec = make_spec();
        let trace = "counterexample found";
        let response = "VERDICT: Confirmed\nREASON: The invariant was clearly violated.\n";
        let v = parse_verdict(response, &pair, &spec, trace);
        match v {
            ReflectionVerdict::Confirmed { finding } => {
                assert_eq!(finding.impact, Impact::High);
                assert_eq!(finding.confidence, 0.95);
            }
            _ => panic!("expected Confirmed"),
        }
    }

    #[test]
    fn test_parse_verdict_out_of_scope() {
        let pair = make_pair();
        let spec = make_spec();
        let trace = "counterexample found";
        let response = "VERDICT: OutOfScope\nREASON: Not exploitable in this context.\n";
        let v = parse_verdict(response, &pair, &spec, trace);
        match v {
            ReflectionVerdict::OutOfScope { reason } => {
                assert_eq!(reason, "Not exploitable in this context.");
            }
            _ => panic!("expected OutOfScope"),
        }
    }

    #[test]
    fn test_no_violation_returns_expected() {
        let reflector = LlmReflector::new(None);
        let pair = make_pair();
        let spec = make_spec();
        let harness = make_harness();
        let result = FuzzResult {
            harness_id: "test".to_string(),
            outcome: FuzzOutcome::NoViolation,
            coverage: 0.0,
            raw_output: String::new(),
        };

        // Use a blocking runtime for the test since async_trait requires it
        let rt = tokio::runtime::Runtime::new().unwrap();
        let verdict = rt.block_on(async {
            reflector
                .reflect(&pair, &spec, &harness, &result, "/tmp")
                .await
                .unwrap()
        });

        match verdict {
            ReflectionVerdict::ExpectedBehavior { reason } => {
                assert!(reason.contains("did not violate"));
            }
            _ => panic!("expected ExpectedBehavior"),
        }
    }
}
