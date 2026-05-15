pub mod client;
pub mod prompts;

use agent_core::{Element, ElementKind, Finding, Impact};
use semantic::contract_semantics::{ContractSemantics, SourceSemantics};

pub use client::{LlmClient, LlmConfig, LlmError, LlmProvider};

/// LLM-powered semantic reasoning agent.
pub struct LlmAgent {
    pub client: LlmClient,
}

impl LlmAgent {
    pub fn new(client: LlmClient) -> Self {
        Self { client }
    }

    pub fn is_enabled(&self) -> bool {
        self.client.is_enabled()
    }

    pub async fn analyze(&self, source: &SourceSemantics) -> Vec<Finding> {
        if !self.is_enabled() {
            return Vec::new();
        }
        let mut findings = Vec::new();
        for contract in &source.contracts {
            let prompt = prompts::contract_analysis_prompt(contract);
            match self.client.complete(&prompt).await {
                Ok(response) => {
                    let parsed = parse_llm_response(&response, &contract.name);
                    findings.extend(parsed);
                }
                Err(e) => {
                    tracing::warn!("LLM call failed for {}: {}", contract.name, e);
                }
            }
        }
        findings
    }

    /// Verify a list of findings using the LLM.
    pub async fn verify_findings(
        &self,
        findings: &[Finding],
        contract: &ContractSemantics,
    ) -> Vec<(Finding, bool, f64)> {
        if !self.is_enabled() {
            return findings
                .iter()
                .map(|f| (f.clone(), true, f.confidence))
                .collect();
        }
        let mut results = Vec::new();
        for finding in findings {
            let prompt = prompts::verification_prompt(finding, contract);
            match self.client.complete(&prompt).await {
                Ok(response) => {
                    let (valid, confidence) = parse_verification_response(&response);
                    results.push((finding.clone(), valid, confidence));
                }
                Err(e) => {
                    tracing::warn!("LLM verification failed: {}", e);
                    results.push((finding.clone(), true, finding.confidence));
                }
            }
        }
        results
    }
}

/// Parse LLM analysis response into structured findings.
fn parse_llm_response(response: &str, contract_name: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_check: Option<String> = None;
    let mut current_impact: Option<String> = None;
    let mut current_desc: Option<String> = None;
    let mut current_confidence: Option<f64> = None;

    for line in response.lines() {
        let line = line.trim();
        if line.is_empty() {
            if let (Some(check), Some(impact), Some(desc), Some(confidence)) = (
                current_check.take(),
                current_impact.take(),
                current_desc.take(),
                current_confidence.take(),
            ) {
                findings.push(Finding {
                    check: check.clone(),
                    description: desc,
                    impact: parse_impact(&impact),
                    elements: vec![Element {
                        kind: ElementKind::Contract,
                        name: contract_name.to_string(),
                        contract: contract_name.to_string(),
                        line: None,
                        column: None,
                    }],
                    confidence: confidence.clamp(0.0, 1.0),
                    agent: "llm-agent".to_string(),
                    swc_id: None,
                    remediation: None,
                });
            }
            continue;
        }
        if let Some(val) = line.strip_prefix("CHECK:") {
            current_check = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("IMPACT:") {
            current_impact = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("DESCRIPTION:") {
            current_desc = Some(val.trim().to_string());
        } else if let Some(val) = line.strip_prefix("CONFIDENCE:") {
            if let Ok(c) = val.trim().parse::<f64>() {
                current_confidence = Some(c);
            }
        } else if current_desc.is_some() {
            // Append multi-line descriptions
            if let Some(ref mut desc) = current_desc {
                desc.push(' ');
                desc.push_str(line);
            }
        }
    }

    // Flush last finding
    if let (Some(check), Some(impact), Some(desc), Some(confidence)) = (
        current_check.take(),
        current_impact.take(),
        current_desc.take(),
        current_confidence.take(),
    ) {
        findings.push(Finding {
            check: check.clone(),
            description: desc,
            impact: parse_impact(&impact),
            elements: vec![Element {
                kind: ElementKind::Contract,
                name: contract_name.to_string(),
                contract: contract_name.to_string(),
                line: None,
                column: None,
            }],
            confidence: confidence.clamp(0.0, 1.0),
            agent: "llm-agent".to_string(),
            swc_id: None,
            remediation: None,
        });
    }

    findings.retain(|f| f.description != "NO_VULNERABILITIES_FOUND");
    findings
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

fn parse_verification_response(response: &str) -> (bool, f64) {
    let mut valid = true;
    let mut confidence = 0.5;
    for line in response.lines() {
        let line = line.trim();
        if let Some(val) = line.strip_prefix("VALID:") {
            valid = val.trim().to_lowercase().starts_with('y');
        } else if let Some(val) = line.strip_prefix("CONFIDENCE:") {
            if let Ok(c) = val.trim().parse::<f64>() {
                confidence = c.clamp(0.0, 1.0);
            }
        }
    }
    (valid, confidence)
}
