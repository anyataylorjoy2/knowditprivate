#!/usr/bin/env python3
"""Automated benchmark runner for sol-agent against a suite of contracts."""

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional


def run_analysis(contract_path: str, agent_bin: str = "./target/release/sol-agent") -> dict:
    """Run sol-agent on a contract and return the JSON report."""
    report_path = "/tmp/sol_agent_benchmark_report.json"
    result = subprocess.run(
        [agent_bin, "analyze", contract_path, "--output", report_path],
        capture_output=True,
        text=True,
        cwd="/home/bimabima/auditor",
    )
    if result.returncode != 0:
        print(f"ERROR running {contract_path}: {result.stderr}", file=sys.stderr)
        return {}
    try:
        with open(report_path) as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"ERROR parsing report for {contract_path}: {e}", file=sys.stderr)
        return {}


def run_benchmark(report_path: str, ground_truth_path: str, bench_bin: str = "./target/release/benchmark") -> dict:
    """Run benchmark binary and parse results."""
    result = subprocess.run(
        [bench_bin, report_path, ground_truth_path],
        capture_output=True,
        text=True,
        cwd="/home/bimabima/auditor",
    )
    if result.returncode != 0:
        print(f"ERROR benchmarking: {result.stderr}", file=sys.stderr)
        return {}
    # Parse the text output into a dict
    metrics = {}
    for line in result.stdout.splitlines():
        if ":" in line:
            key, val = line.split(":", 1)
            key = key.strip().replace(" ", "_").lower()
            val = val.strip().replace("%", "").replace(",", "")
            try:
                if "." in val:
                    metrics[key] = float(val)
                else:
                    metrics[key] = int(val)
            except ValueError:
                metrics[key] = val
    return metrics


def to_snake_case(name: str) -> str:
    """Convert CamelCase to snake_case."""
    result = []
    for i, ch in enumerate(name):
        if ch.isupper() and i > 0:
            result.append('_')
        result.append(ch.lower())
    return ''.join(result)


def find_ground_truth(contract_path: str, ground_truth_dir: str) -> Optional[str]:
    """Find matching ground truth file for a contract."""
    name = Path(contract_path).stem
    candidates = [
        f"{name}.json",
        f"{name.lower()}.json",
        f"{to_snake_case(name)}.json",
    ]
    for cand in candidates:
        gt_file = os.path.join(ground_truth_dir, cand)
        if os.path.exists(gt_file):
            return gt_file
    return None


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Run benchmark suite for sol-agent")
    parser.add_argument("contracts_dir", help="Directory containing .sol contracts")
    parser.add_argument("--ground-truth-dir", default="benchmark/ground_truth", help="Directory with ground truth JSONs")
    parser.add_argument("--agent-bin", default="./target/release/sol-agent", help="Path to sol-agent binary")
    parser.add_argument("--bench-bin", default="./target/release/benchmark", help="Path to benchmark binary")
    args = parser.parse_args()

    results: List[Dict] = []
    total_tp = total_fp = total_fn = 0

    for root, _, files in os.walk(args.contracts_dir):
        for file in sorted(files):
            if not file.endswith(".sol"):
                continue
            contract_path = os.path.join(root, file)
            gt_path = find_ground_truth(contract_path, args.ground_truth_dir)
            if not gt_path:
                print(f"SKIP {contract_path} (no ground truth)")
                continue

            print(f"\n=== Analyzing {contract_path} ===")
            report = run_analysis(contract_path, args.agent_bin)
            if not report:
                continue

            # Save report temporarily for benchmark binary
            report_path = "/tmp/sol_agent_benchmark_report.json"
            with open(report_path, "w") as f:
                json.dump(report, f, indent=2)

            metrics = run_benchmark(report_path, gt_path, args.bench_bin)
            if metrics:
                results.append({
                    "contract": contract_path,
                    "metrics": metrics,
                })
                total_tp += metrics.get("true_positives", 0)
                total_fp += metrics.get("false_positives", 0)
                total_fn += metrics.get("false_negatives", 0)

    # Aggregate results
    print("\n\n=== AGGREGATE BENCHMARK RESULTS ===")
    print(f"Contracts evaluated: {len(results)}")
    print(f"Total True Positives: {total_tp}")
    print(f"Total False Positives: {total_fp}")
    print(f"Total False Negatives: {total_fn}")

    if total_tp + total_fn > 0:
        recall = total_tp / (total_tp + total_fn)
        print(f"Overall Recall: {recall * 100:.2f}%")
    if total_tp + total_fp > 0:
        precision = total_tp / (total_tp + total_fp)
        print(f"Overall Precision: {precision * 100:.2f}%")
        if precision + (total_tp / (total_tp + total_fn)) > 0:
            f1 = 2 * precision * (total_tp / (total_tp + total_fn)) / (precision + (total_tp / (total_tp + total_fn)))
            print(f"Overall F1 Score: {f1 * 100:.2f}%")

    for r in results:
        m = r["metrics"]
        print(f"\n{r['contract']}: "
              f"TP={m.get('true_positives',0)} FP={m.get('false_positives',0)} FN={m.get('false_negatives',0)} "
              f"Recall={m.get('recall',0):.0f}% Precision={m.get('precision',0):.0f}%")


if __name__ == "__main__":
    main()
