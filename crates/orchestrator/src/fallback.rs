//! Static-only fallback path. When Foundry isn't available or LLM cost is a concern,
//! we still want a "cheap first-pass" that uses the existing pattern matcher +
//! semantic analyzer to surface high-confidence static findings.
//!
//! This intentionally mirrors the OLD orchestrator (pre-Knowdit refactor) and is
//! invoked via [`StaticFirstPass::run`].

use agent_core::{Report, finding::*};
use patterns::engine::PatternEngine;
use semantic::contract_semantics::SourceSemantics;
use std::collections::HashSet;
use verifier::Verifier;

/// A cheap, static-only first-pass scanner.
pub struct StaticFirstPass {
    pub pattern_engine: PatternEngine,
    pub min_confidence: f64,
}

impl StaticFirstPass {
    pub fn new(min_confidence: f64) -> Self {
        Self {
            pattern_engine: PatternEngine::new(),
            min_confidence,
        }
    }

    pub fn analyze(&self, source: &SourceSemantics) -> Report {
        let start = std::time::Instant::now();
        let mut report = Report::new(&source.file_path);

        // Pattern matching.
        let pattern_findings = self.pattern_engine.analyze(source);
        for f in &pattern_findings {
            self.add_if_valid(f, source, &mut report);
        }
        report.agents_run.push("pattern-matcher".to_string());

        // Semantic access-control gap detection.
        for contract in &source.contracts {
            let gaps = semantic::access_control::detect_access_control_gaps(contract);
            for gap in gaps {
                let mut builder = Finding::builder("missing-access-control", "semantic-analyzer")
                    .description(&gap.description)
                    .impact(Impact::Medium)
                    .element(ElementKind::Function, &gap.function_name, &contract.name)
                    .confidence(0.7);
                if let Some(line) = gap.line {
                    builder = builder.with_line(line);
                }
                self.add_if_valid(&builder.build(), source, &mut report);
            }
        }
        report.agents_run.push("semantic-analyzer".to_string());

        // Deduplicate + rank.
        report.findings = deduplicate(&report.findings);
        report.findings.sort_by(|a, b| {
            let impact_cmp = b.impact.cmp(&a.impact);
            if impact_cmp != std::cmp::Ordering::Equal {
                impact_cmp
            } else {
                b.confidence
                    .partial_cmp(&a.confidence)
                    .unwrap_or(std::cmp::Ordering::Equal)
            }
        });

        report.duration_ms = start.elapsed().as_millis() as u64;
        report
    }

    fn add_if_valid(&self, finding: &Finding, source: &SourceSemantics, report: &mut Report) {
        let contract = finding
            .elements
            .first()
            .and_then(|elem| source.contracts.iter().find(|c| c.name == elem.contract));

        if let Some(contract) = contract {
            match Verifier::verify(finding, contract) {
                verifier::VerificationResult::Valid {
                    adjusted_confidence,
                } => {
                    if adjusted_confidence >= self.min_confidence {
                        let mut f = finding.clone();
                        f.confidence = adjusted_confidence;
                        report.add_finding(f);
                    }
                }
                verifier::VerificationResult::Invalid(_) => {}
            }
        } else if finding.confidence >= self.min_confidence {
            report.add_finding(finding.clone());
        }
    }
}

fn deduplicate(findings: &[Finding]) -> Vec<Finding> {
    let mut unique = Vec::new();
    let mut seen = HashSet::new();
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
        if seen.insert(key) {
            unique.push(f.clone());
        }
    }
    unique
}
