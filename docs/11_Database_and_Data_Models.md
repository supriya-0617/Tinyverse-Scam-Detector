# 11 — Database and Data Models Specification

## 1. Storage Architecture Decision: Why No Database Engine Is Used

**Decision:** The Tinyverse On-Device Scam Message Detector intentionally **does not use a relational (SQLite/PostgreSQL) or NoSQL (MongoDB/Firestore) database**.

### Engineering Justification
1. **Privacy by Statelessness (`NFR-003`):** A core requirement is that user-submitted SMS and WhatsApp messages must **never be stored permanently**. Introducing a database for runtime predictions would create an unnecessary data-retention liability on the user's machine.
2. **Simplicity & Zero Daemon Overhead:** The training corpus is static during inference (`146` rows, `~22 KB`), and the trained ML pipeline (`~150–300 KB`) fits entirely in RAM. Storing the training corpus in a human-auditable UTF-8 CSV (`data/sample_messages.csv`) and the fitted model in a single local binary artifact (`models/scam_detector.joblib`) eliminates database daemon setup, schema migrations, and locking issues.

---

## 2. Training Dataset Schema (`data/sample_messages.csv`)

The single canonical training dataset is stored at `data/sample_messages.csv` and is read-only during training.

| Column Name | Data Type | Nullable? | Allowed Values / Constraints | Description |
|---|---|---|---|---|
| `text` | `string` (UTF-8) | No | `1 <= len(text) <= 2000`; unique after normalization | Raw SMS or WhatsApp message text. |
| `label` | `string` (Enum) | No | `"SCAM"` or `"SAFE"` | Ground-truth binary classification label. |
| `category` | `string` (Enum) | Conditional | If `label == "SCAM"`: `"KYC/Bank"`, `"Lottery/Prize"`, `"Loan/Credit"`, `"Job/Investment"`, `"Other"`. If `label == "SAFE"`: `""` (empty string). | Ground-truth scam category. Strictly empty for `SAFE` rows. |
| `source` | `string` (Enum) | No | `"synthetic"`, `"public_dataset"`, `"consented_anonymized"` | Provenance tag ensuring synthetic data is never misrepresented as real user data. |
| `language` | `string` (Enum) | No | `"en"`, `"hi-Latn"`, `"mixed"`, `"other"` | Primary language/script tag (`hi-Latn` denotes Hinglish / Latin-script Hindi). |

---

## 3. Model Artifact Schema (`models/scam_detector.joblib`)

When `python train.py` executes, it serializes a versioned Python dictionary to `models/scam_detector.joblib` with the following exact structure:

```python
{
    "model_version": "1.0.0-m2-ml-baseline",
    "created_at_utc": "2026-11-23T...",
    "random_seed": 42,
    "vectorizer": FeatureUnion(
        transformer_list=[
            ("word_tfidf", TfidfVectorizer(analyzer="word", ngram_range=(1, 2), ...)),
            ("char_tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), ...)),
        ]
    ),
    "binary_classifier": CalibratedClassifierCV(...),   # Predicts P(SAFE), P(SCAM)
    "binary_linear_model": LogisticRegression(...),     # Used for exact feature weight attribution
    "category_classifier": LogisticRegression(...),     # Predicts 5 scam categories (trained on SCAM rows)
    "decision_threshold": 0.50,                         # Validated probability threshold for SCAM
    "calibration_info": {
        "is_calibrated": True,
        "method": "sigmoid_cv3",
        "dataset_size": 146,
        "train_size": 102,
        "disclosure": "Confidence score is calibrated on a held-out synthetic split and should be treated as an experimental model confidence score."
    },
    "valid_categories": ["KYC/Bank", "Lottery/Prize", "Loan/Credit", "Job/Investment", "Other"]
}
```

---

## 4. Prediction Input & Output Schemas

### 4.1 Prediction Input Schema
- **Raw Input:** Single Python `str` passed to `predict_message(text: str)`.
- **Validated Internal Representation (`InputValidationResult`):**
  ```python
  {
      "is_valid": True,
      "cleaned_text": "Your KYC will expire today...",
      "warnings": [],
      "error_message": None
  }
  ```

### 4.2 Prediction Output Schema (`PredictionResult` / `.to_dict()`)

Every call to `predict_message(text)` returns a `PredictionResult` instance whose `.to_dict()` method conforms to this schema:

#### Example 1: Scam Message Output
```json
{
  "is_valid": true,
  "verdict": "SCAM",
  "category": "KYC/Bank",
  "confidence": 93.4,
  "confidence_ratio": 0.934,
  "scam_probability": 0.934,
  "reasons": [
    "Contains high-risk scam phrasing: 'kyc', 'account', 'otp', 'link'",
    "Contains a shortened URL or suspicious link pattern",
    "Matches statistical patterns associated with KYC/Bank scams"
  ],
  "warnings": [
    "Confidence score is derived from a local synthetic dataset. Always verify requests for money, OTPs, or credentials independently through official channels."
  ],
  "indicators": [],
  "model_version": "1.0.0-m2-ml-baseline"
}
```

#### Example 2: Safe Message Output (`category` is strictly `null`/`None`)
```json
{
  "is_valid": true,
  "verdict": "SAFE",
  "category": null,
  "confidence": 89.7,
  "confidence_ratio": 0.897,
  "scam_probability": 0.103,
  "reasons": [
    "Contains legitimate protective warning ('do not share' / 'never share')",
    "Matches benign notification patterns: 'otp', 'do not', 'share'",
    "No upfront fee, lottery claim, or credential harvesting link detected"
  ],
  "warnings": [
    "Automated SAFE assessment is not a guarantee. Never share OTPs, PINs, or passwords with anyone."
  ],
  "indicators": [],
  "model_version": "1.0.0-m2-ml-baseline"
}
```

---

## 5. Evaluation Report Schema (`reports/evaluation_report.json`)

Generated automatically by `python train.py` to store real, unfabricated metrics for the UI and documentation:
- `dataset_summary`: row counts, class balance, category counts, language counts, duplicate count.
- `split_sizes`: `train` (`102`), `val` (`22`), `test` (`22`).
- `validation_metrics` & `test_metrics`:
  - `binary`: `accuracy`, `precision`, `recall`, `f1`, `safe_false_positive_rate`, `scam_false_negative_rate`, `confusion_matrix` (`tn`, `fp`, `fn`, `tp`).
  - `category`: `accuracy`, `macro_f1`, `weighted_f1`, `per_category` precision/recall/F1/support, `confusion_matrix`.
- `performance_benchmarks`: `training_time_ms`, `model_size_kb`, `model_load_time_ms`, `single_prediction_latency_ms`.
