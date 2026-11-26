"""
AGENT SHIELD - Standalone Model Training & Validation Script
Trains the Scikit-learn Isolation Forest model on synthetic baseline agent behavior.

Usage:
    python ml/train_model.py
    python ml/train_model.py --samples 3000 --contamination 0.08 --estimators 250
    python ml/train_model.py --help
"""

import sys
import os
import time
import argparse

# Set up project path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from backend.anomaly_detector import (
    train_model,
    get_model_status,
    evaluate_model,
    FEATURE_NAMES
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Agent Shield - Train and Validate Isolation Forest Anomaly Detector"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=2500,
        help="Number of synthetic normal activity samples to generate (default: 2500)"
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.08,
        help="Expected proportion of outliers in the data (default: 0.08)"
    )
    parser.add_argument(
        "--estimators",
        type=int,
        default=200,
        help="Number of base estimators / decision trees (default: 200)"
    )
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="Skip post-training model validation benchmark"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    print("=" * 65)
    print("🛡️  AGENT SHIELD — Isolation Forest Model Training Pipeline")
    print("=" * 65)
    print(f"• Target Samples:        {args.samples:,}")
    print(f"• Contamination Rate:    {args.contamination * 100:.1f}%")
    print(f"• Estimators (Trees):    {args.estimators}")
    print(f"• Behavioral Features ({len(FEATURE_NAMES)}):")
    for i, feat in enumerate(FEATURE_NAMES, 1):
        print(f"   {i}. {feat}")
    print("-" * 65)

    start_time = time.time()
    print("⏳ Generating synthetic training data and fitting Isolation Forest...")

    success = train_model(
        n_samples=args.samples,
        contamination=args.contamination,
        n_estimators=args.estimators
    )

    elapsed = time.time() - start_time

    if not success:
        print("❌ Model training failed! Check logs for details.")
        sys.exit(1)

    status = get_model_status()
    model_path = status.get("model_path", "unknown")
    file_size_kb = os.path.getsize(model_path) / 1024 if os.path.exists(model_path) else 0

    print(f"✅ Model successfully trained and persisted in {elapsed:.2f} seconds!")
    print(f"• File Location:         {model_path}")
    print(f"• Model File Size:       {file_size_kb:.1f} KB")

    # Evaluation Benchmark
    if not args.no_eval:
        print("-" * 65)
        print("🔬 Running Validation Benchmark (Normal vs. Outlier Test Set)...")
        eval_metrics = evaluate_model()

        print(f"• Normal Baseline Accuracy:   {eval_metrics['normal_accuracy'] * 100:.1f}%")
        print(f"• Outlier Detection Rate:     {eval_metrics['anomaly_detection_rate'] * 100:.1f}%")
        print(f"• Mean Normal Anomaly Score:  {eval_metrics['avg_normal_score']:+.4f} (higher = normal)")
        print(f"• Mean Outlier Anomaly Score: {eval_metrics['avg_anomaly_score']:+.4f} (lower = anomalous)")
        print(f"• Test Cases Evaluated:       {eval_metrics['samples_evaluated']}")

    print("=" * 65)
    print("🎯 Model is fully operational and ready for runtime inference.")
    print("=" * 65)


if __name__ == "__main__":
    main()
