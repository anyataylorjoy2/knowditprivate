use benchmark::{Benchmark, GroundTruth};
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <report.json> <ground_truth.json>", args[0]);
        std::process::exit(1);
    }

    let report_path = &args[1];
    let gt_path = &args[2];

    let report_json = fs::read_to_string(report_path).expect("Failed to read report");
    let report: agent_core::Report =
        serde_json::from_str(&report_json).expect("Failed to parse report");

    let gt_json = fs::read_to_string(gt_path).expect("Failed to read ground truth");
    let ground_truth: Vec<GroundTruth> =
        serde_json::from_str(&gt_json).expect("Failed to parse ground truth");

    let result = Benchmark::evaluate(&report, &ground_truth);
    Benchmark::print_report(&result);
}
