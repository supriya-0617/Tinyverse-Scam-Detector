# Tinyverse Scam Detector — Measured Evaluation Summary (Milestone 2)

## 1. Dataset Validation & Distribution
- **Canonical Dataset (Read-Only):** `data/sample_messages.csv`
- **Total Validated Rows:** `146` (`94 SCAM`, `52 SAFE`)
- **Duplicates Found:** `0` | **Missing Values:** `0`
- **Language Breakdown:** `{'en': 99, 'hi-Latn': 42, 'mixed': 5}`
- **Scam Category Breakdown:** `{'KYC/Bank': 28, 'Lottery/Prize': 20, 'Loan/Credit': 17, 'Job/Investment': 17, 'Other': 12}`
- **Split Sizes (Stratified, Seed=42):** Train=`102`, Validation=`22`, Held-Out Test=`22`

## 2. Stage-1 Binary Classification Metrics (`SCAM` vs `SAFE`)

| Metric | Validation Split (22 rows) | Held-Out Test Split (22 rows) |
|---|---|---|
| **Accuracy** | `95.45%` | `95.45%` |
| **Scam Precision** | `93.33%` | `93.33%` |
| **Scam Recall** | `100.00%` | `100.00%` |
| **Scam F1-Score** | `96.55%` | `96.55%` |
| **SAFE False-Positive Rate (FPR)** | `12.50%` | `12.50%` |
| **SCAM False-Negative Rate (FNR)** | `0.00%` | `0.00%` |
| **Confusion Matrix (TN, FP, FN, TP)** | `{'tn': 7, 'fp': 1, 'fn': 0, 'tp': 14}` | `{'tn': 7, 'fp': 1, 'fn': 0, 'tp': 14}` |

- **5-Fold Cross-Validation F1 on Training Set:** `92.11% ± 1.24%`

## 3. Stage-2 Scam Category Classification Metrics (Held-Out Test Split)
- **Category Accuracy (on SCAM rows):** `92.86%`
- **Category Macro-F1:** `90.48%`
- **Category Weighted-F1:** `92.18%`

| Scam Category | Precision | Recall | F1-Score | Test Support |
|---|---|---|---|---|
| `KYC/Bank` | `100.0%` | `100.0%` | `100.0%` | `4` |
| `Lottery/Prize` | `75.0%` | `100.0%` | `85.7%` | `3` |
| `Loan/Credit` | `100.0%` | `100.0%` | `100.0%` | `2` |
| `Job/Investment` | `100.0%` | `100.0%` | `100.0%` | `3` |
| `Other` | `100.0%` | `50.0%` | `66.7%` | `2` |

## 4. Measured Local Performance Benchmarks
- **Training Time:** `776.43 ms`
- **Serialized Model Artifact Size:** `228.02 KB` (`models/scam_detector.joblib`)
- **Cold-Start Model Load Time:** `91.79 ms`
- **Single-Message Inference Latency:** `16.775 ms`

## 5. Honest Methodological Limitations
- The current 146-row dataset is synthetic (`source=synthetic`), which means the held-out test split contains 22 messages (14 SCAM, 8 SAFE).
- While strict split-before-vectorize hygiene guarantees zero data leakage between splits, high scores on a compact synthetic test set do not guarantee equivalent performance on all unseen real-world campaigns.
