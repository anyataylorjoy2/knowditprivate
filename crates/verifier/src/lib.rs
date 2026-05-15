use agent_core::Finding;
use semantic::contract_semantics::ContractSemantics;

/// Multi-layer verification engine to reduce false positives.
pub struct Verifier;

impl Verifier {
    pub fn verify(finding: &Finding, contract: &ContractSemantics) -> VerificationResult {
        // Layer 1: Syntactic validation
        if !Self::syntactic_check(finding) {
            return VerificationResult::Invalid("Syntactic check failed".to_string());
        }

        // Layer 2: Semantic validation
        if !Self::semantic_check(finding, contract) {
            return VerificationResult::Invalid("Semantic check failed".to_string());
        }

        // Layer 3: Confidence threshold
        if finding.confidence < 0.3 {
            return VerificationResult::Invalid("Confidence too low".to_string());
        }

        VerificationResult::Valid {
            adjusted_confidence: Self::adjust_confidence(finding, contract),
        }
    }

    fn syntactic_check(finding: &Finding) -> bool {
        !finding.check.is_empty() && !finding.description.is_empty() && !finding.elements.is_empty()
    }

    fn semantic_check(finding: &Finding, contract: &ContractSemantics) -> bool {
        // Check if the referenced element actually exists
        if let Some(elem) = finding.elements.first() {
            if elem.kind == agent_core::ElementKind::Function {
                if contract.function_by_name(&elem.name).is_none() {
                    return false;
                }
            }
        }

        // Filter out findings on constructors that don't apply
        if let Some(elem) = finding.elements.first() {
            if elem.name == "constructor" {
                // Constructors don't need access control
                if finding.check == "missing-access-control" {
                    return false;
                }
            }
        }

        // Filter out reentrancy findings on functions with ReentrancyGuard
        if finding.check == "reentrancy-events" {
            if let Some(elem) = finding.elements.first() {
                if let Some(func) = contract.function_by_name(&elem.name) {
                    if func.has_reentrancy_guard {
                        return false;
                    }
                    // If there are no actual external calls, it's a false positive
                    // Also filter out calls that are just event emissions (no value transfer)
                    let risky_calls: Vec<_> = func
                        .external_calls
                        .iter()
                        .filter(|c| {
                            c.is_value_transfer
                                || c.is_delegatecall
                                || !c.target_expr.contains("emit")
                        })
                        .collect();
                    if risky_calls.is_empty() {
                        return false;
                    }
                }
            }
        }

        // Filter out missing-access-control on view/pure functions
        if finding.check == "missing-access-control" {
            if let Some(elem) = finding.elements.first() {
                if let Some(func) = contract.function_by_name(&elem.name) {
                    if func.mutability == sol_ast::ast::Mutability::View
                        || func.mutability == sol_ast::ast::Mutability::Pure
                    {
                        return false;
                    }
                }
            }
        }

        true
    }

    fn adjust_confidence(finding: &Finding, contract: &ContractSemantics) -> f64 {
        let mut confidence = finding.confidence;

        // Boost confidence if element exists and has expected properties
        if let Some(elem) = finding.elements.first() {
            if let Some(func) = contract.function_by_name(&elem.name) {
                match finding.check.as_str() {
                    "reentrancy-events" => {
                        if !func.external_calls.is_empty() && !func.state_writes.is_empty() {
                            confidence = (confidence + 0.15).min(1.0);
                        }
                    }
                    "missing-access-control" => {
                        if func.modifiers.is_empty() && !func.state_writes.is_empty() {
                            confidence = (confidence + 0.1).min(1.0);
                        }
                    }
                    _ => {}
                }
            }
        }

        confidence
    }
}

#[derive(Debug, Clone)]
pub enum VerificationResult {
    Valid { adjusted_confidence: f64 },
    Invalid(String),
}
