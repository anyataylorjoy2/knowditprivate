#!/usr/bin/env python3
"""Benchmark audit pipeline output against ground truth vulnerabilities.

Unlike mapper_benchmark.py which matches mapper pairs (semantic + vulnerability),
this script matches confirmed findings from the full pipeline against ground truth.

Matching criteria:
1. Contract name match + description similarity
2. Function name match
3. Attack type / check category match
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Set, Tuple
from difflib import SequenceMatcher


def load_audit_output(json_path: str) -> List[Dict]:
    """Load audit output JSON."""
    with open(json_path) as f:
        data = json.load(f)
    return data.get("findings", [])


def load_ground_truth(json_path: str) -> List[Dict]:
    """Load ground truth JSON."""
    with open(json_path) as f:
        return json.load(f)


def normalize(s: str) -> str:
    """Normalize string for comparison."""
    return s.lower().strip().replace("_", " ").replace("-", " ")


def description_similarity(desc1: str, desc2: str) -> float:
    """Compute similarity between two descriptions using SequenceMatcher."""
    return SequenceMatcher(None, normalize(desc1), normalize(desc2)).ratio()


def match_finding(pred: Dict, gt: Dict) -> Tuple[bool, float]:
    """
    Match a predicted finding against a ground truth entry.
    Returns (is_match, confidence_score).
    """
    pred_contracts = [e.get("contract", "") for e in pred.get("elements", [])]
    pred_functions = [e.get("name", "") for e in pred.get("elements", []) if e.get("name")]

    gt_contract = gt.get("contract", "")
    gt_function = gt.get("function", "")

    score = 0.0

    # 1. Contract name match (most important signal)
    contract_match = False
    for pc in pred_contracts:
        if normalize(pc) == normalize(gt_contract):
            contract_match = True
            score += 0.4
            break
        # Partial match (e.g., "LamboRebalanceOnUniwap" vs "LamboRebalanceOnUniswap")
        if normalize(pc)[:10] == normalize(gt_contract)[:10]:
            contract_match = True
            score += 0.3
            break

    # 2. Function name match
    for pf in pred_functions:
        if pf and gt_function and normalize(pf) == normalize(gt_function):
            score += 0.3
            break

    # 3. Description similarity
    pred_desc = pred.get("description", "")
    gt_desc = gt.get("description", "")
    sim = description_similarity(pred_desc, gt_desc)
    if sim > 0.3:
        score += sim * 0.3

    # 4. Check/attack_type match
    pred_check = normalize(pred.get("check", ""))
    gt_check = normalize(gt.get("check", ""))
    gt_attack = normalize(gt.get("attack_type", ""))

    if pred_check and (pred_check == gt_check or pred_check == gt_attack):
        score += 0.2
    elif pred_check == "other":
        # "Other" is a weak signal — only counts if contract matches
        if contract_match:
            score += 0.1

    # 5. Impact/severity match
    pred_impact = normalize(pred.get("impact", ""))
    gt_impact = normalize(gt.get("impact", ""))
    if pred_impact and gt_impact and pred_impact == gt_impact:
        score += 0.05

    # Threshold: need at least 0.4 to count as a match
    return (score >= 0.4, score)


def compute_metrics(predictions: List[Dict], ground_truth: List[Dict]) -> Dict:
    """Compute TP, FP, FN, precision, recall, F1 with greedy matching."""
    matched_gt: Set[int] = set()
    matched_pred: Set[int] = set()
    match_details = []

    # Build match scores matrix
    scores = []
    for pi, pred in enumerate(predictions):
        for gi, gt in enumerate(ground_truth):
            is_match, score = match_finding(pred, gt)
            if is_match:
                scores.append((score, pi, gi))

    # Greedy match by highest score first
    scores.sort(key=lambda x: -x[0])
    for score, pi, gi in scores:
        if pi not in matched_pred and gi not in matched_gt:
            matched_pred.add(pi)
            matched_gt.add(gi)
            match_details.append({
                "pred_idx": pi,
                "gt_idx": gi,
                "gt_id": ground_truth[gi].get("id", f"GT-{gi}"),
                "gt_check": ground_truth[gi].get("check", ""),
                "score": round(score, 3),
            })

    tp = len(matched_gt)
    fp = len(predictions) - len(matched_pred)
    fn = len(ground_truth) - len(matched_gt)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0

    return {
        "true_positives": tp,
        "false_positives": fp,
        "false_negatives": fn,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "match_details": match_details,
        "unmatched_gt": [gt for i, gt in enumerate(ground_truth) if i not in matched_gt],
        "unmatched_pred": [pred for i, pred in enumerate(predictions) if i not in matched_pred],
    }


def main():
    if len(sys.argv) < 3:
        print("Usage: python audit_benchmark.py <audit_output.json> <ground_truth.json>")
        sys.exit(1)

    audit_path = sys.argv[1]
    gt_path = sys.argv[2]

    predictions = load_audit_output(audit_path)
    ground_truth = load_ground_truth(gt_path)

    print(f"Findings: {len(predictions)}")
    print(f"Ground truth: {len(ground_truth)} vulnerabilities")

    metrics = compute_metrics(predictions, ground_truth)

    print("\n=== Audit Benchmark Results ===")
    print(f"True Positives: {metrics['true_positives']}")
    print(f"False Positives: {metrics['false_positives']}")
    print(f"False Negatives: {metrics['false_negatives']}")
    print(f"Precision: {metrics['precision'] * 100:.2f}%")
    print(f"Recall: {metrics['recall'] * 100:.2f}%")
    print(f"F1 Score: {metrics['f1_score'] * 100:.2f}%")

    if metrics["match_details"]:
        print(f"\nMatched Findings ({len(metrics['match_details'])}):")
        for m in metrics["match_details"]:
            print(f"  Finding #{m['pred_idx']+1} <-> {m['gt_id']} ({m['gt_check']}) [score={m['score']}]")

    if metrics["unmatched_gt"]:
        print(f"\nUnmatched Ground Truth ({len(metrics['unmatched_gt'])}):")
        for gt in metrics["unmatched_gt"]:
            gid = gt.get("id", "?")
            print(f"  - {gid} {gt.get('check', '?')}: {gt.get('description', '')[:80]}...")

    if metrics["unmatched_pred"]:
        print(f"\nUnmatched Predictions ({len(metrics['unmatched_pred'])}):")
        for i, pred in enumerate(metrics["unmatched_pred"]):
            contracts = [e.get("contract", "?") for e in pred.get("elements", [])]
            funcs = [e.get("name", "?") for e in pred.get("elements", []) if e.get("name")]
            desc = pred.get("description", "")[:80].replace("\n", " ")
            print(f"  - {contracts[0]}.{funcs[0] if funcs else '?'} [{pred.get('impact','?')}]: {desc}...")


if __name__ == "__main__":
    main()
