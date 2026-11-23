# 09 — Deliverables and Acceptance Criteria

## 1. Master Deliverables Inventory

### 1.1 Application Source Code Deliverables
| File Path | Description | Target Milestone |
|---|---|---|
| `src/__init__.py` | Package initialization and version metadata. | M1 (Completed) |
| `src/features.py` | Input validation, Unicode/leetspeak normalization, structural tags, and Word+Char TF-IDF vectorizer builder. | M2 (Completed) |
| `src/classifier.py` | Dataset validator, leakage-free stratified splitter, Stage-1 Binary & Stage-2 Category ML models, feature attribution, and `joblib` persistence. | M2 (Completed) |
| `train.py` | End-to-end CLI script for dataset validation, model training, evaluation report generation, and artifact saving. | M2 (Completed) |
| `predict.py` | Local inference API and CLI entry point returning structured `PredictionResult` objects. | M2/M3 (Completed) |
| `src/rules.py` | Modular, explainable rule engine for URLs, KYC/bank threats, lottery fees, loan fees, job scams, and safe dampeners. | M3 (Completed) |
| `app.py` | Streamlit local cybersecurity dashboard bound strictly to `127.0.0.1`. | M4 (Completed) |
| `src/privacy_audit.py` | Static AST and runtime privacy/offline inspection module. | M6 (Completed) |

### 1.2 Data, Model & Evaluation Deliverables
| File Path | Description | Target Milestone |
|---|---|---|
| `data/sample_messages.csv` | Single canonical 146-row labeled synthetic dataset (`en`, `hi-Latn`, `mixed`), treated as read-only during training. | M1/M2 (Completed) |
| `models/scam_detector.joblib` | Locally serialized bundle containing fitted TF-IDF `FeatureUnion`, binary classifier, category classifier, threshold, and metadata. | M2 (Completed) |
| `reports/evaluation_report.json` | Machine-readable JSON containing dataset statistics, train/val/test metrics, confusion matrices, and latency benchmarks. | M2 (Completed) |
| `reports/evaluation_summary.md` | Human-readable Markdown evaluation report generated from actual held-out runs. | M2 (Completed) |
| `reports/confusion_matrix.png` | Locally rendered Matplotlib visualization of binary and category confusion matrices. | M2 (Completed) |

### 1.3 Documentation Deliverables
- **Root Entry Documents (8 files):** `README.md`, `IMPLEMENTATION.md`, `ARCHITECTURE.md`, `DATA_AND_MODEL.md`, `PRIVACY_AND_OFFLINE.md`, `TEST_PLAN.md`, `DEMO_SCRIPT.md`, `MASTER_PROMPT.md`.
- **Technical Engineering Suite in `docs/` (15 files):** `00_README_Project_Documentation_Index.md` through `14_Risk_Register.md`.

### 1.4 Automated Testing Deliverables
- `tests/test_prediction.py` — Dataset validation, normalization, binary & category predictions, Hinglish, obfuscation, borderline false-positive protection, and latency tests.
- `tests/test_rules.py` — Rule engine unit tests (Milestone 3).
- `tests/test_privacy.py` — Offline execution and privacy compliance tests (Milestone 6).

---

## 2. Formal Acceptance Criteria Checklist

| ID | Acceptance Criterion | Verification Command / Artifact |
|---|---|---|
| **AC-01** | Single message input produces exact output schema (`verdict`, `category`, `confidence`, `reasons`, `warnings`). | `python predict.py "Your KYC will expire today..."` |
| **AC-02** | `verdict` is strictly `"SCAM"` or `"SAFE"` for valid inputs, and `None` (`is_valid=False`) for empty inputs. | `python -m pytest tests/test_prediction.py` |
| **AC-03** | `category` is one of the 5 valid categories when `verdict == "SCAM"` and strictly `None` when `verdict == "SAFE"`. | `python -m pytest tests/test_prediction.py` |
| **AC-04** | Confidence score is bounded between `0.0` and `100.0` and derived from model probability estimates. | `python -m pytest tests/test_prediction.py` |
| **AC-05** | Genuine bank alerts, OTP warnings, courier updates, and personal chats are classified as `SAFE` without high false-positive rates. | `reports/evaluation_summary.md` & `tests/test_prediction.py` |
| **AC-06** | Hinglish (`hi-Latn`) and obfuscated (`K.Y.C`, `fr33`, `l0an`, `acc0unt`) scams are accurately detected. | `python -m pytest tests/test_prediction.py` |
| **AC-07** | Zero external API, cloud LLM, telemetry, or outbound socket calls occur during inference. | `tests/test_privacy.py` & Wi-Fi off demo |
| **AC-08** | All 15 `docs/` files exist, contain substantive engineering specifications, and are cross-linked from `README.md`. | `Get-ChildItem docs/` |

---

## 3. Definition of Done (DoD)

A milestone or feature is considered **DONE** only when:
1. Code is modular, type-annotated, commented for beginners, and free of hardcoded fake outputs.
2. Model artifacts and evaluation reports are generated reproducibly via `python train.py` using `RANDOM_SEED = 42`.
3. All active automated tests pass via `python -m pytest -q` with `0` failures and `0` skipped broken tests.
4. Documentation accurately reflects the measured metrics and actual function signatures.
