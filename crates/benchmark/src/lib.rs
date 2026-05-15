use agent_core::{Impact, Report, finding::Finding};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Ground truth entry for a benchmark.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroundTruth {
    pub contract: String,
    pub function: String,
    pub check: String,
    pub impact: Impact,
    pub description: String,
}

/// Benchmark result.
#[derive(Debug, Clone)]
pub struct BenchmarkResult {
    pub total_findings: usize,
    pub true_positives: usize,
    pub false_positives: usize,
    pub false_negatives: usize,
    pub recall: f64,
    pub precision: f64,
    pub f1: f64,
    pub per_category: HashMap<String, CategoryMetrics>,
}

#[derive(Debug, Clone)]
pub struct CategoryMetrics {
    pub tp: usize,
    pub fp: usize,
    pub fn_count: usize,
    pub recall: f64,
    pub precision: f64,
    pub f1: f64,
}

pub struct Benchmark;

impl Benchmark {
    pub fn evaluate(report: &Report, ground_truth: &[GroundTruth]) -> BenchmarkResult {
        let mut tp = 0usize;
        let mut fp = 0usize;
        let mut matched_gt = HashSet::new();

        for finding in &report.findings {
            let mut matched = false;
            for (i, gt) in ground_truth.iter().enumerate() {
                if matched_gt.contains(&i) {
                    continue;
                }
                if Self::is_match(finding, gt) {
                    tp += 1;
                    matched_gt.insert(i);
                    matched = true;
                    break;
                }
            }
            if !matched {
                fp += 1;
            }
        }

        let fn_count = ground_truth.len() - matched_gt.len();
        let recall = if ground_truth.is_empty() {
            0.0
        } else {
            tp as f64 / ground_truth.len() as f64
        };
        let precision = if report.findings.is_empty() {
            0.0
        } else {
            tp as f64 / report.findings.len() as f64
        };
        let f1 = if recall + precision == 0.0 {
            0.0
        } else {
            2.0 * recall * precision / (recall + precision)
        };

        BenchmarkResult {
            total_findings: report.findings.len(),
            true_positives: tp,
            false_positives: fp,
            false_negatives: fn_count,
            recall,
            precision,
            f1,
            per_category: HashMap::new(),
        }
    }

    fn is_match(finding: &Finding, gt: &GroundTruth) -> bool {
        // Fuzzy matching on contract, function, and check
        let contract_match = finding
            .elements
            .first()
            .map(|e| e.contract.to_lowercase() == gt.contract.to_lowercase())
            .unwrap_or(false);
        let func_match = finding
            .elements
            .first()
            .map(|e| e.name.to_lowercase() == gt.function.to_lowercase())
            .unwrap_or(false);
        let check_match = finding.check.to_lowercase() == gt.check.to_lowercase();

        contract_match && func_match && check_match
    }

    pub fn print_report(result: &BenchmarkResult) {
        println!("=== Benchmark Results ===");
        println!("Total findings: {}", result.total_findings);
        println!("True Positives: {}", result.true_positives);
        println!("False Positives: {}", result.false_positives);
        println!("False Negatives: {}", result.false_negatives);
        println!("Recall: {:.2}%", result.recall * 100.0);
        println!("Precision: {:.2}%", result.precision * 100.0);
        println!("F1 Score: {:.2}%", result.f1 * 100.0);
    }
}
