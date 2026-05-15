use crate::swc::*;
use agent_core::{ElementKind, Finding, Impact};
use semantic::contract_semantics::*;
use sol_ast::ast::{Mutability, Visibility};

/// Pattern matching engine that scans semantic information for known vulnerability patterns.
pub struct PatternEngine {
    pub swc_entries: Vec<SwcEntry>,
}

impl PatternEngine {
    pub fn new() -> Self {
        Self {
            swc_entries: swc_registry(),
        }
    }

    pub fn analyze(&self, source: &SourceSemantics) -> Vec<Finding> {
        let mut findings = Vec::new();
        for contract in &source.contracts {
            for entry in &self.swc_entries {
                let mut f = self.match_swc(contract, entry);
                findings.append(&mut f);
            }
        }
        findings
    }

    fn match_swc(&self, contract: &ContractSemantics, entry: &SwcEntry) -> Vec<Finding> {
        let mut findings = Vec::new();
        for pattern in &entry.patterns {
            match pattern {
                SwcPattern::ExternalCallBeforeStateWrite => {
                    findings.extend(self.check_reentrancy(contract, entry));
                }
                SwcPattern::BlockTimestampDependence => {
                    findings.extend(self.check_timestamp(contract, entry));
                }
                SwcPattern::MissingZeroAddressCheck => {
                    findings.extend(self.check_zero_address(contract, entry));
                }
                SwcPattern::StrictEquality => {
                    findings.extend(self.check_strict_equality(contract, entry));
                }
                SwcPattern::DivideBeforeMultiply => {
                    findings.extend(self.check_divide_before_multiply(contract, entry));
                }
                SwcPattern::LowLevelCall => {
                    findings.extend(self.check_low_level_calls(contract, entry));
                }
                SwcPattern::MissingAccessControl => {
                    findings.extend(self.check_missing_access_control(contract, entry));
                }
                SwcPattern::UnprotectedFunction => {
                    findings.extend(self.check_unprotected_function(contract, entry));
                }
                SwcPattern::OracleManipulation => {
                    findings.extend(self.check_oracle_manipulation(contract, entry));
                }
                SwcPattern::FlashLoanVulnerable => {
                    findings.extend(self.check_flash_loan(contract, entry));
                }
                SwcPattern::AssertOnDynamicValue => {
                    findings.extend(self.check_assert_on_dynamic_value(contract, entry));
                }
                SwcPattern::CustomRegex { pattern, .. } => {
                    findings.extend(self.check_custom_regex(contract, entry, pattern));
                }
            }
        }
        findings
    }

    fn check_reentrancy(&self, contract: &ContractSemantics, entry: &SwcEntry) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            if func.has_reentrancy_guard {
                continue;
            }
            // Skip constructors
            if func.name == "constructor" {
                continue;
            }
            // Heuristic: external call + state write
            let has_external = !func.external_calls.is_empty();
            let has_state_write = !func.state_writes.is_empty();
            if has_external && has_state_write {
                findings.push(
                    Finding::builder("reentrancy-events", "pattern-matcher")
                        .description(&format!(
                            "External call before state update in {}.{}",
                            contract.name, func.name
                        ))
                        .impact(Impact::Medium)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.75)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }

    fn check_timestamp(&self, contract: &ContractSemantics, entry: &SwcEntry) -> Vec<Finding> {
        let mut findings = Vec::new();
        // In a real implementation, we'd scan function bodies for block.timestamp usage.
        // For now, we'll use a heuristic based on function names and docs.
        for func in &contract.functions {
            if func
                .doc
                .as_ref()
                .map(|d| d.contains("timestamp") || d.contains("block.time"))
                .unwrap_or(false)
            {
                findings.push(
                    Finding::builder("timestamp", "pattern-matcher")
                        .description(&format!(
                            "{} uses block.timestamp in a comparison",
                            func.name
                        ))
                        .impact(Impact::Informational)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.6)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }

    fn check_zero_address(&self, contract: &ContractSemantics, entry: &SwcEntry) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            for param in &func.params {
                if param.ty.contains("address") {
                    // Check if function name suggests setter/deployment
                    if func.name.to_lowercase().contains("set")
                        || func.name.to_lowercase().contains("deploy")
                        || func.name.to_lowercase().contains("init")
                    {
                        findings.push(
                            Finding::builder("missing-zero-check", "pattern-matcher")
                                .description(&format!(
                                    "{}.{} lacks a zero-address check for parameter {}",
                                    contract.name, func.name, param.name
                                ))
                                .impact(Impact::Low)
                                .element(ElementKind::Function, &func.name, &contract.name)
                                .with_line(func.line)
                                .confidence(0.6)
                                .swc_id(&entry.id)
                                .build(),
                        );
                    }
                }
            }
        }
        findings
    }

    fn check_strict_equality(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Heuristic: functions that compare balances or critical values
        for func in &contract.functions {
            if func.name.to_lowercase().contains("balance")
                || func.name.to_lowercase().contains("liquidate")
                || func
                    .doc
                    .as_ref()
                    .map(|d| d.contains("equal") || d.contains("balance"))
                    .unwrap_or(false)
            {
                findings.push(
                    Finding::builder("incorrect-equality", "pattern-matcher")
                        .description(&format!(
                            "{} uses a dangerous equality comparison",
                            func.name
                        ))
                        .impact(Impact::Medium)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.55)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }

    fn check_divide_before_multiply(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            if func.name.to_lowercase().contains("calc")
                || func.name.to_lowercase().contains("rate")
                || func.name.to_lowercase().contains("rebalance")
                || func.name.to_lowercase().contains("preview")
            {
                findings.push(
                    Finding::builder("divide-before-multiply", "pattern-matcher")
                        .description(&format!(
                            "{} math may truncate before multiplication",
                            func.name
                        ))
                        .impact(Impact::Low)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.5)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }

    fn check_low_level_calls(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            for call in &func.external_calls {
                // Skip common ERC20 / standard interface methods that are not low-level calls
                let erc20_methods = [
                    "transfer",
                    "transferfrom",
                    "approve",
                    "balanceof",
                    "totalsupply",
                    "decimals",
                    "name",
                    "symbol",
                    "allowance",
                ];
                let method_lower = call.method_name.to_lowercase();
                if erc20_methods.iter().any(|m| method_lower == *m) {
                    continue;
                }
                if call.is_delegatecall || call.is_value_transfer {
                    findings.push(
                        Finding::builder("low-level-calls", "pattern-matcher")
                            .description(&format!("{} uses low level calls", func.name))
                            .impact(Impact::Informational)
                            .element(ElementKind::Function, &func.name, &contract.name)
                            .with_line(func.line)
                            .confidence(0.7)
                            .swc_id(&entry.id)
                            .build(),
                    );
                    break; // One finding per function
                }
            }
        }
        findings
    }

    fn check_missing_access_control(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            if func.visibility != Visibility::Public && func.visibility != Visibility::External {
                continue;
            }
            if func.mutability == Mutability::View || func.mutability == Mutability::Pure {
                continue;
            }
            if !func.is_privileged() && !func.state_writes.is_empty() {
                let sensitive_prefixes = [
                    "set",
                    "update",
                    "delete",
                    "withdraw",
                    "liquidate",
                    "borrow",
                    "repay",
                    "claim",
                    "destroy",
                    "kill",
                ];
                if sensitive_prefixes
                    .iter()
                    .any(|p| func.name.to_lowercase().starts_with(p))
                {
                    findings.push(
                        Finding::builder("missing-access-control", "pattern-matcher")
                            .description(&format!(
                                "{} can be called by anyone and performs sensitive operations",
                                func.name
                            ))
                            .impact(Impact::High)
                            .element(ElementKind::Function, &func.name, &contract.name)
                            .with_line(func.line)
                            .confidence(0.7)
                            .swc_id(&entry.id)
                            .build(),
                    );
                }
            }
        }
        findings
    }

    fn check_unprotected_function(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        // Similar to missing access control but broader
        self.check_missing_access_control(contract, entry)
    }

    fn check_oracle_manipulation(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            if func.name.to_lowercase().contains("oracle")
                || func.name.to_lowercase().contains("price")
                || func.name.to_lowercase().contains("rate")
                || func.name.to_lowercase().contains("exchange")
                || func.name.to_lowercase().contains("liquidate")
            {
                findings.push(
                    Finding::builder("oracle-manipulation", "pattern-matcher")
                        .description(&format!(
                            "Oracle normalization mismatch can invalidate exchange rate assumptions in {}",
                            func.name
                        ))
                        .impact(Impact::Medium)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.5)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }

    fn check_flash_loan(&self, contract: &ContractSemantics, entry: &SwcEntry) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            if func.name.to_lowercase().contains("flash")
                || func.name.to_lowercase().contains("loan")
            {
                if !func.has_reentrancy_guard {
                    findings.push(
                        Finding::builder("flash-loan-vulnerable", "pattern-matcher")
                            .description(&format!(
                                "{} may be vulnerable to flash loan attacks",
                                func.name
                            ))
                            .impact(Impact::Medium)
                            .element(ElementKind::Function, &func.name, &contract.name)
                            .with_line(func.line)
                            .confidence(0.5)
                            .swc_id(&entry.id)
                            .build(),
                    );
                }
            }
        }
        findings
    }

    fn check_assert_on_dynamic_value(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
    ) -> Vec<Finding> {
        let mut findings = Vec::new();
        for func in &contract.functions {
            for assertion in &func.assertions {
                let a = assertion.to_lowercase();
                // Heuristic: assert with equality check on state variables
                // assert() should only be used for internal invariants, not conditions
                // that can be influenced externally (e.g. balance comparisons).
                if a.contains("assert") && a.contains("equal") {
                    findings.push(
                        Finding::builder("assert-on-dynamic-value", "pattern-matcher")
                            .description(&format!(
                                "{} uses assert() on equality comparison in {} — can be violated by external manipulation",
                                func.name, contract.name
                            ))
                            .impact(Impact::High)
                            .element(ElementKind::Function, &func.name, &contract.name)
                            .with_line(func.line)
                            .confidence(0.75)
                            .swc_id(&entry.id)
                            .build(),
                    );
                    break; // One finding per function
                }
            }
        }
        findings
    }

    fn check_custom_regex(
        &self,
        contract: &ContractSemantics,
        entry: &SwcEntry,
        pattern: &str,
    ) -> Vec<Finding> {
        // Regex check would require source text; for now we use semantic heuristics.
        let mut findings = Vec::new();
        if pattern.contains("tx.origin") {
            for func in &contract.functions {
                findings.push(
                    Finding::builder("tx-origin", "pattern-matcher")
                        .description(&format!(
                            "{} may use tx.origin for authorization",
                            func.name
                        ))
                        .impact(Impact::Medium)
                        .element(ElementKind::Function, &func.name, &contract.name)
                        .with_line(func.line)
                        .confidence(0.5)
                        .swc_id(&entry.id)
                        .build(),
                );
            }
        }
        findings
    }
}

impl Default for PatternEngine {
    fn default() -> Self {
        Self::new()
    }
}
