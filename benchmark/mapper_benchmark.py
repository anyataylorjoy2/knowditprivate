#!/usr/bin/env python3
"""Benchmark Knowdit mapper against ground truth vulnerabilities."""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set


def load_mapper_output(json_path: str) -> List[Dict]:
    """Load mapper output JSON."""
    with open(json_path) as f:
        data = json.load(f)
    return data.get("pairs", [])


def load_ground_truth(json_path: str) -> List[Dict]:
    """Load ground truth JSON."""
    with open(json_path) as f:
        return json.load(f)


def normalize_title(title: str) -> str:
    """Normalize vulnerability title for matching."""
    return title.lower().strip()


def normalize_attack_type(attack_type: str) -> str:
    """Normalize attack type for matching."""
    return attack_type.lower().replace(" ", "_")


def match_vulnerability(pred: Dict, gt: Dict) -> bool:
    """
    Match predicted vulnerability against ground truth.
    Uses multiple criteria: attack type, semantic name, vulnerability title similarity.
    """
    # Exact match on attack type
    pred_attack = normalize_attack_type(pred.get("vulnerability", {}).get("attack_type", ""))
    gt_attack = normalize_attack_type(gt.get("attack_type", gt.get("check", "")))

    if pred_attack and gt_attack and pred_attack == gt_attack:
        return True

    # Match on semantic name vs ground truth check
    pred_semantic = pred.get("semantic", {}).get("name", "").lower()
    gt_check = gt.get("check", "").lower()

    if pred_semantic and gt_check and pred_semantic in gt_check:
        return True

    # Match on semantic name vs ground truth description
    gt_desc = gt.get("description", "").lower()
    if pred_semantic and gt_desc and pred_semantic in gt_desc:
        return True

    # Match on vulnerability title similarity (simple substring)
    pred_title = normalize_title(pred.get("vulnerability", {}).get("title", ""))
    if pred_title and gt_desc and pred_title in gt_desc:
        return True

    # Match "Other" attack type as wildcard for any ground truth
    if pred_attack == "other" and gt_check:
        return True

    return False


def compute_metrics(predictions: List[Dict], ground_truth: List[Dict]) -> Dict[str, float]:
    """Compute TP, FP, FN, precision, recall, F1."""
    tp = 0
    fp = 0
    matched_gt_indices = set()

    for pred in predictions:
        matched = False
        for i, gt in enumerate(ground_truth):
            if i in matched_gt_indices:
                continue
            if match_vulnerability(pred, gt):
                tp += 1
                matched_gt_indices.add(i)
                matched = True
                break
        if not matched:
            fp += 1

    fn = len(ground_truth) - len(matched_gt_indices)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall) > 0
        else 0.0
    )

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python mapper_benchmark.py <mapper_output.json> <ground_truth.json>")
        sys.exit(1)

    mapper_path = sys.argv[1]
    gt_path = sys.argv[2]

    predictions = load_mapper_output(mapper_path)
    ground_truth = load_ground_truth(gt_path)

    print(f"Predictions: {len(predictions)} pairs")
    print(f"Ground truth: {len(ground_truth)} vulnerabilities")

    metrics = compute_metrics(predictions, ground_truth)

    print("\n=== Benchmark Results ===")
    print(f"True Positives: {metrics['true_positives']}")
    print(f"False Positives: {metrics['false_positives']}")
    print(f"False Negatives: {metrics['false_negatives']}")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall: {metrics['recall'] * 100:.2f}%")
    print(f"F1 Score: {metrics['f1_score'] * 100:.2f}%")

    # Show unmatched ground truth
    matched_gt_indices = set()
    for pred in predictions:
        for i, gt in enumerate(ground_truth):
            if i in matched_gt_indices:
                continue
            if match_vulnerability(pred, gt):
                matched_gt_indices.add(i)
                break

    unmatched_gt = [gt for i, gt in enumerate(ground_truth) if i not in matched_gt_indices]
    if unmatched_gt:
        print(f"\nUnmatched Ground Truth ({len(unmatched_gt)}):")
        for gt in unmatched_gt:
            print(f"  - {gt.get('check', gt.get('attack_type', '?'))}: {gt.get('description', '')[:80]}...")


if __name__ == "__main__":
    main()
