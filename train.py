"""Local model training, validation, evaluation, and reporting script.

Usage (Windows PowerShell / POSIX):
    python train.py
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import matplotlib
matplotlib.use("Agg")  # Non-interactive offline backend for saving PNG charts
import matplotlib.pyplot as plt
import numpy as np

from src.classifier import (
    RANDOM_SEED,
    VALID_CATEGORIES,
    evaluate_model_bundle,
    load_and_validate_dataset,
    load_model_bundle,
    predict_with_bundle,
    save_model_bundle,
    split_dataset,
    train_scam_detector,
)

PROJECT_ROOT = Path(__file__).resolve().parent
CANONICAL_DATA_PATH = PROJECT_ROOT / "data" / "sample_messages.csv"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "scam_detector.joblib"
REPORTS_DIR = PROJECT_ROOT / "reports"


def _save_confusion_matrix_plot(
    test_metrics: dict[str, Any],
    output_png: Path,
) -> None:
    """Render and save binary and category confusion matrices to a local PNG."""
    output_png.parent.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # 1. Binary Confusion Matrix
    cm_bin_dict = test_metrics["binary"]["confusion_matrix"]
    cm_bin = np.array(
        [
            [cm_bin_dict["tn"], cm_bin_dict["fp"]],
            [cm_bin_dict["fn"], cm_bin_dict["tp"]],
        ]
    )
    ax0 = axes[0]
    im0 = ax0.imshow(cm_bin, cmap="Blues")
    ax0.set_title("Held-Out Test: Binary Confusion Matrix")
    ax0.set_xticks([0, 1])
    ax0.set_yticks([0, 1])
    ax0.set_xticklabels(["Predicted SAFE", "Predicted SCAM"])
    ax0.set_yticklabels(["Actual SAFE", "Actual SCAM"])
    for i in range(2):
        for j in range(2):
            ax0.text(
                j,
                i,
                str(cm_bin[i, j]),
                ha="center",
                va="center",
                color="white" if cm_bin[i, j] > cm_bin.max() / 2 else "black",
                fontsize=12,
                fontweight="bold",
            )
    fig.colorbar(im0, ax=ax0, fraction=0.046, pad=0.04)

    # 2. Category Confusion Matrix
    cm_cat = np.array(test_metrics["category"]["confusion_matrix"])
    cat_labels = test_metrics["category"]["labels"]
    ax1 = axes[1]
    im1 = ax1.imshow(cm_cat, cmap="Oranges")
    ax1.set_title("Held-Out Test: Scam Category Confusion Matrix")
    ax1.set_xticks(range(len(cat_labels)))
    ax1.set_yticks(range(len(cat_labels)))
    ax1.set_xticklabels(cat_labels, rotation=30, ha="right", fontsize=8)
    ax1.set_yticklabels(cat_labels, fontsize=8)
    for i in range(len(cat_labels)):
        for j in range(len(cat_labels)):
            ax1.text(
                j,
                i,
                str(cm_cat[i, j]),
                ha="center",
                va="center",
                color="white" if cm_cat[i, j] > max(cm_cat.max() / 2, 1) else "black",
                fontsize=9,
                fontweight="bold",
            )
    fig.colorbar(im1, ax=ax1, fraction=0.046, pad=0.04)

    plt.tight_layout()
    plt.savefig(output_png, dpi=150)
    plt.close(fig)


def _write_markdown_summary(report: dict[str, Any], summary_path: Path) -> None:
    """Write a clean, human-readable Markdown evaluation report."""
    ds = report["dataset_validation"]
    val_m = report["validation_metrics"]
    test_m = report["test_metrics"]
    perf = report["performance_benchmarks"]

    lines = [
        "# Tinyverse Scam Detector — Measured Evaluation Summary (Milestone 2)",
        "",
        "## 1. Dataset Validation & Distribution",
        f"- **Canonical Dataset (Read-Only):** `data/sample_messages.csv`",
        f"- **Total Validated Rows:** `{ds['total_rows']}` (`{ds['scam_count']} SCAM`, `{ds['safe_count']} SAFE`)",
        f"- **Duplicates Found:** `{ds['duplicate_count']}` | **Missing Values:** `{ds['missing_value_count']}`",
        f"- **Language Breakdown:** `{ds['language_counts']}`",
        f"- **Scam Category Breakdown:** `{ds['category_counts']}`",
        f"- **Split Sizes (Stratified, Seed={RANDOM_SEED}):** Train=`{report['split_sizes']['train']}`, Validation=`{report['split_sizes']['val']}`, Held-Out Test=`{report['split_sizes']['test']}`",
        "",
        "## 2. Stage-1 Binary Classification Metrics (`SCAM` vs `SAFE`)",
        "",
        "| Metric | Validation Split (22 rows) | Held-Out Test Split (22 rows) |",
        "|---|---|---|",
        f"| **Accuracy** | `{val_m['binary']['accuracy'] * 100:.2f}%` | `{test_m['binary']['accuracy'] * 100:.2f}%` |",
        f"| **Scam Precision** | `{val_m['binary']['precision'] * 100:.2f}%` | `{test_m['binary']['precision'] * 100:.2f}%` |",
        f"| **Scam Recall** | `{val_m['binary']['recall'] * 100:.2f}%` | `{test_m['binary']['recall'] * 100:.2f}%` |",
        f"| **Scam F1-Score** | `{val_m['binary']['f1_score'] * 100:.2f}%` | `{test_m['binary']['f1_score'] * 100:.2f}%` |",
        f"| **SAFE False-Positive Rate (FPR)** | `{val_m['binary']['safe_false_positive_rate'] * 100:.2f}%` | `{test_m['binary']['safe_false_positive_rate'] * 100:.2f}%` |",
        f"| **SCAM False-Negative Rate (FNR)** | `{val_m['binary']['scam_false_negative_rate'] * 100:.2f}%` | `{test_m['binary']['scam_false_negative_rate'] * 100:.2f}%` |",
        f"| **Confusion Matrix (TN, FP, FN, TP)** | `{val_m['binary']['confusion_matrix']}` | `{test_m['binary']['confusion_matrix']}` |",
        "",
        f"- **5-Fold Cross-Validation F1 on Training Set:** `{report['model_metadata']['cv5_train_f1_mean'] * 100:.2f}% ± {report['model_metadata']['cv5_train_f1_std'] * 100:.2f}%`",
        "",
        "## 3. Stage-2 Scam Category Classification Metrics (Held-Out Test Split)",
        f"- **Category Accuracy (on SCAM rows):** `{test_m['category']['accuracy'] * 100:.2f}%`",
        f"- **Category Macro-F1:** `{test_m['category']['macro_f1'] * 100:.2f}%`",
        f"- **Category Weighted-F1:** `{test_m['category']['weighted_f1'] * 100:.2f}%`",
        "",
        "| Scam Category | Precision | Recall | F1-Score | Test Support |",
        "|---|---|---|---|---|",
    ]

    for cat in VALID_CATEGORIES:
        cm_cat = test_m["category"]["per_category"][cat]
        lines.append(
            f"| `{cat}` | `{cm_cat['precision'] * 100:.1f}%` | `{cm_cat['recall'] * 100:.1f}%` | "
            f"`{cm_cat['f1_score'] * 100:.1f}%` | `{cm_cat['support']}` |"
        )

    lines.extend(
        [
            "",
            "## 4. Measured Local Performance Benchmarks",
            f"- **Training Time:** `{perf['training_time_ms']:.2f} ms`",
            f"- **Serialized Model Artifact Size:** `{perf['model_size_kb']:.2f} KB` (`models/scam_detector.joblib`)",
            f"- **Cold-Start Model Load Time:** `{perf['model_load_time_ms']:.2f} ms`",
            f"- **Single-Message Inference Latency:** `{perf['single_prediction_latency_ms']:.3f} ms`",
            "",
            "## 5. Honest Methodological Limitations",
            "- The current 146-row dataset is synthetic (`source=synthetic`), which means the held-out test split contains 22 messages (14 SCAM, 8 SAFE).",
            "- While strict split-before-vectorize hygiene guarantees zero data leakage between splits, high scores on a compact synthetic test set do not guarantee equivalent performance on all unseen real-world campaigns.",
        ]
    )

    summary_path.parent.mkdir(parents=True, exist_ok=True)
    summary_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_training_pipeline(
    data_path: Path = CANONICAL_DATA_PATH,
    model_path: Path = DEFAULT_MODEL_PATH,
    reports_dir: Path = REPORTS_DIR,
) -> dict[str, Any]:
    """Execute the full validation, training, evaluation, and persistence pipeline.

    Treats the canonical dataset (data/sample_messages.csv) strictly as read-only.
    """
    t0 = time.perf_counter()
    df, val_report = load_and_validate_dataset(data_path, deduplicate=True)
    train_df, val_df, test_df = split_dataset(df, random_state=RANDOM_SEED)

    bundle = train_scam_detector(train_df, val_df, random_state=RANDOM_SEED)
    train_elapsed_ms = (time.perf_counter() - t0) * 1000.0

    # Evaluate on Train, Validation, and Held-Out Test splits
    train_metrics = evaluate_model_bundle(bundle, train_df, split_name="train")
    val_metrics = evaluate_model_bundle(bundle, val_df, split_name="validation")
    test_metrics = evaluate_model_bundle(bundle, test_df, split_name="test")

    # Save model artifact and measure file size + cold-start reload latency
    saved_path = save_model_bundle(bundle, model_path)
    model_size_kb = saved_path.stat().st_size / 1024.0

    t_load0 = time.perf_counter()
    reloaded_bundle = load_model_bundle(saved_path)
    load_elapsed_ms = (time.perf_counter() - t_load0) * 1000.0

    # Measure average single-message prediction latency across 20 runs
    sample_msg = "Your KYC will expire today. Click bit.ly/kyc-update and share your OTP."
    t_pred0 = time.perf_counter()
    for _ in range(20):
        _ = predict_with_bundle(reloaded_bundle, sample_msg)
    single_pred_ms = ((time.perf_counter() - t_pred0) * 1000.0) / 20.0

    report: dict[str, Any] = {
        "model_metadata": {
            "model_version": bundle["model_version"],
            "created_at_utc": bundle["created_at_utc"],
            "random_seed": bundle["random_seed"],
            "decision_threshold": bundle["decision_threshold"],
            "feature_count": bundle["feature_count"],
            "cv5_train_f1_mean": bundle["cv5_train_f1_mean"],
            "cv5_train_f1_std": bundle["cv5_train_f1_std"],
        },
        "dataset_validation": val_report.to_dict(),
        "split_sizes": {
            "train": int(len(train_df)),
            "val": int(len(val_df)),
            "test": int(len(test_df)),
        },
        "train_metrics": train_metrics,
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics,
        "performance_benchmarks": {
            "training_time_ms": round(train_elapsed_ms, 2),
            "model_size_kb": round(model_size_kb, 2),
            "model_load_time_ms": round(load_elapsed_ms, 2),
            "single_prediction_latency_ms": round(single_pred_ms, 3),
        },
    }

    reports_dir.mkdir(parents=True, exist_ok=True)
    report_json_path = reports_dir / "evaluation_report.json"
    report_md_path = reports_dir / "evaluation_summary.md"
    cm_png_path = reports_dir / "confusion_matrix.png"

    report_json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    _write_markdown_summary(report, report_md_path)
    _save_confusion_matrix_plot(test_metrics, cm_png_path)

    return report


def main() -> None:
    print("=" * 72)
    print("TINYVERSE ON-DEVICE SCAM DETECTOR — LOCAL TRAINING PIPELINE")
    print("=" * 72)
    report = run_training_pipeline()

    ds = report["dataset_validation"]
    print(f"[1/4] Dataset Validated: {ds['total_rows']} rows "
          f"({ds['scam_count']} SCAM, {ds['safe_count']} SAFE), "
          f"Duplicates: {ds['duplicate_count']}")
    print(f"      Splits -> Train: {report['split_sizes']['train']}, "
          f"Val: {report['split_sizes']['val']}, "
          f"Test: {report['split_sizes']['test']}")

    tm_bin = report["test_metrics"]["binary"]
    tm_cat = report["test_metrics"]["category"]
    print(f"[2/4] Held-Out Test Binary Metrics:")
    print(f"      Accuracy:  {tm_bin['accuracy'] * 100:.2f}% | "
          f"Precision: {tm_bin['precision'] * 100:.2f}% | "
          f"Recall: {tm_bin['recall'] * 100:.2f}% | "
          f"F1: {tm_bin['f1_score'] * 100:.2f}%")
    print(f"      SAFE False-Positive Rate: {tm_bin['safe_false_positive_rate'] * 100:.2f}% | "
          f"SCAM False-Negative Rate: {tm_bin['scam_false_negative_rate'] * 100:.2f}%")
    print(f"      Confusion Matrix: {tm_bin['confusion_matrix']}")

    print(f"[3/4] Held-Out Test Category Metrics:")
    print(f"      Category Accuracy: {tm_cat['accuracy'] * 100:.2f}% | "
          f"Macro-F1: {tm_cat['macro_f1'] * 100:.2f}% | "
          f"Weighted-F1: {tm_cat['weighted_f1'] * 100:.2f}%")

    perf = report["performance_benchmarks"]
    print(f"[4/4] Local Artifacts & Performance:")
    print(f"      Model Saved: {DEFAULT_MODEL_PATH} ({perf['model_size_kb']:.2f} KB)")
    print(f"      Training Time: {perf['training_time_ms']:.2f} ms | "
          f"Load Time: {perf['model_load_time_ms']:.2f} ms | "
          f"Inference Latency: {perf['single_prediction_latency_ms']:.3f} ms")
    print("=" * 72)


if __name__ == "__main__":
    main()
