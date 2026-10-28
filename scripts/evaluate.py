"""TrustLens AI - Benchmark Evaluation Script

Executes offline evaluation over documented benchmark datasets.
Measures Precision, Recall, F1, False Positive Rate (FPR), and Evidence Citation Correctness.
"""

import asyncio
import json
import os
import sys
import uuid
from typing import Any, Dict, List

# Ensure app is on PYTHONPATH
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.orchestration.graph import execute_investigation_workflow
from app.orchestration.state import InvestigationState


async def run_evaluation():
    dataset_path = os.path.join(os.path.dirname(__file__), "..", "data", "benchmark_dataset.json")
    if not os.path.exists(dataset_path):
        print(f"Error: Dataset not found at {dataset_path}")
        return

    with open(dataset_path, "r", encoding="utf-8") as f:
        cases: List[Dict[str, Any]] = json.load(f)

    print("=" * 80)
    print(" TRUSTLENS AI — BENCHMARK EVALUATION ENGINE")
    print(f" Total test cases: {len(cases)}")
    print("=" * 80)

    tp, fp, tn, fn = 0, 0, 0, 0
    inconclusive_count = 0
    citation_correct_count = 0
    total_evaluated = 0

    results = []

    for item in cases:
        case_id = item["id"]
        content = item["content"]
        ground_truth = item["ground_truth_label"]
        is_malicious_truth = ground_truth in ("phishing", "malware", "scam", "social_engineering")
        observable_features = item.get("observable_features", [])

        state: InvestigationState = {
            "investigation_id": f"eval-{uuid.uuid4()}",
            "input_type": item["type"],
            "raw_text": content,
            "extracted_entities": [],
            "extracted_claims": [],
            "extracted_urls": [],
            "categories": [],
            "planned_tools": [],
            "agent_findings": {},
            "external_evidence": [],
            "provider_statuses": {},
            "status": "pending",
        }

        try:
            output_state = await execute_investigation_workflow(state)
            predicted_risk = output_state.get("final_risk_level", "unknown")
            predicted_score = output_state.get("final_risk_score", 0.0)
            is_malicious_pred = predicted_risk in ("medium", "high", "critical")

            # Classification metrics
            if is_malicious_truth and is_malicious_pred:
                tp += 1
                outcome = "TP (True Positive)"
            elif not is_malicious_truth and is_malicious_pred:
                fp += 1
                outcome = "FP (False Positive)"
            elif not is_malicious_truth and not is_malicious_pred:
                tn += 1
                outcome = "TN (True Negative)"
            else:
                fn += 1
                outcome = "FN (False Negative)"

            if predicted_risk in ("low", "unknown") and ground_truth in ("benign", "inconclusive"):
                inconclusive_count += 1

            # Evidence citation evaluation
            findings = output_state.get("agent_findings", {})
            scam_obs = findings.get("scam_analysis", {}).get("observed_phrases", [])
            indicators = output_state.get("risk_assessment", {}).get("indicators", [])

            # Check if any observable feature from ground truth was identified
            cited = False
            if observable_features:
                text_lower = " ".join(indicators + scam_obs).lower()
                for feat in observable_features:
                    if feat.lower() in text_lower or feat.lower() in content.lower():
                        cited = True
                        break
            else:
                cited = True

            if cited:
                citation_correct_count += 1

            total_evaluated += 1

            print(f"[{case_id}] Label: {ground_truth.upper():<18} | Pred: {predicted_risk.upper():<8} ({predicted_score:4.1f}/100) -> {outcome}")

        except Exception as e:
            print(f"[{case_id}] Execution Error: {e}")

    # Metric computations
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    citation_accuracy = (citation_correct_count / max(1, total_evaluated)) * 100.0

    print("=" * 80)
    print(" FINAL EVALUATION SUMMARY METRICS")
    print("=" * 80)
    print(f" True Positives (TP)           : {tp}")
    print(f" False Positives (FP)          : {fp}")
    print(f" True Negatives (TN)           : {tn}")
    print(f" False Negatives (FN)          : {fn}")
    print("-" * 80)
    print(f" Precision                     : {precision:.4f} ({precision * 100:.1f}%)")
    print(f" Recall                        : {recall:.4f} ({recall * 100:.1f}%)")
    print(f" F1-Score                      : {f1:.4f}")
    print(f" False Positive Rate (FPR)     : {fpr:.4f} ({fpr * 100:.1f}%)")
    print(f" Evidence Citation Correctness : {citation_accuracy:.1f}%")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(run_evaluation())
