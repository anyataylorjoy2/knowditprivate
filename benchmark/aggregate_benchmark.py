#!/usr/bin/env python3
"""Aggregate benchmark results across multiple projects."""

import json
import sys
from typing import Dict, List


def load_results(results_file: str) -> List[Dict]:
    """Load benchmark results from JSON file."""
    with open(results_file) as f:
        return json.load(f)


def aggregate_metrics(results: List[Dict]) -> Dict[str, float]:
    """Compute aggregate metrics across all projects."""
    total_tp = sum(r.get("true_positives", 0) for r in results)
    total_fp = sum(r.get("false_positives", 0) for r in results)
    total_fn = sum(r.get("false_negatives", 0) for r in results)

    precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
    recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "total_projects": len(results),
        "total_true_positives": total_tp,
        "total_false_positives": total_fp,
        "total_false_negatives": total_fn,
        "aggregate_precision": precision,
        "aggregate_recall": recall,
        "aggregate_f1": f1,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python aggregate_benchmark.py <results.json>")
        sys.exit(1)

    results = load_results(sys.argv[1])
    metrics = aggregate_metrics(results)

    print("=== Aggregate Benchmark Results ===")
    print(f"Projects evaluated: {metrics['total_projects']}")
    print(f"Total True Positives: {metrics['total_true_positives']}")
    print(f"Total False Positives: {metrics['total_false_positives']}")
    print(f"Total False Negatives: {metrics['total_false_negatives']}")
    print(f"Aggregate Precision: {metrics['aggregate_precision'] * 100:.2f}%")
    print(f"Aggregate Recall: {metrics['aggregate_recall'] * 100:.2f}%")
    print(f"Aggregate F1 Score: {metrics['aggregate_f1'] * 100:.2f}%")

    # Per-project breakdown
    print("\n=== Per-Project Results ===")
    for i, r in enumerate(results, 1):
        print(f"Project {i}:")
        print(f"  TP={r.get('true_positives',0)} FP={r.get('false_positives',0)} FN={r.get('false_negatives',0)}")
        print(f"  Precision={r.get('precision',0)*100:.0f}% Recall={r.get('recall',0)*100:.0f}% F1={r.get('f1_score',0)*100:.0f}%")


if __name__ == "__main__":
    main()
