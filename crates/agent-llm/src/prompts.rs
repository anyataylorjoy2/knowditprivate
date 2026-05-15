//! Prompt templates for LLM vulnerability analysis.

use semantic::contract_semantics::{ContractSemantics, FunctionSemantics};

/// Build a prompt asking the LLM to analyze a contract for vulnerabilities.
pub fn contract_analysis_prompt(contract: &ContractSemantics) -> String {
    let functions_summary: Vec<String> = contract
        .functions
        .iter()
        .map(|f| {
            format!(
                "- {} (visibility: {:?}, mutability: {:?}, modifiers: {:?}, writes: {:?}, reads: {:?})",
                f.name, f.visibility, f.mutability, f.modifiers, f.state_writes, f.state_reads
            )
        })
        .collect();

    let state_vars_summary: Vec<String> = contract
        .state_vars
        .iter()
        .map(|v| {
            format!(
                "- {} (type: {}, visibility: {:?})",
                v.name, v.ty, v.visibility
            )
        })
        .collect();

    format!(
        r#"You are an expert smart contract security auditor. Analyze the following Solidity contract for vulnerabilities.

Contract: {}
Kind: {:?}
Base contracts: {:?}

State variables:
{}

Functions:
{}

Identify any vulnerabilities focusing on:
1. Access control gaps (functions that should be protected but aren't)
2. Business logic flaws
3. Reentrancy risks
4. Oracle manipulation risks
5. Flash loan attack vectors
6. Input validation issues
7. Any subtle semantic inconsistencies between comments/names and implementation

For each finding, output in this exact format:
CHECK: <short check name>
IMPACT: <Critical|High|Medium|Low|Informational>
DESCRIPTION: <detailed description>
CONFIDENCE: <0.0-1.0>

If no vulnerabilities are found, say "NO_VULNERABILITIES_FOUND".
"#,
        contract.name,
        contract.kind,
        contract.base_contracts,
        state_vars_summary.join("\n"),
        functions_summary.join("\n")
    )
}

/// Build a prompt for verifying a finding.
pub fn verification_prompt(finding: &agent_core::Finding, contract: &ContractSemantics) -> String {
    format!(
        r#"You are verifying a smart contract security finding.

Finding: {}
Description: {}
Impact: {:?}

Contract: {}

Is this finding valid and actionable? Respond with:
VALID: <yes/no>
REASON: <explanation>
CONFIDENCE: <0.0-1.0>
"#,
        finding.check, finding.description, finding.impact, contract.name
    )
}
