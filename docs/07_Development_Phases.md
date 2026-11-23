# 07 — Development Phases & Milestone Plan

## 1. Milestone Tracking Table

Status values follow strict engineering governance: `NOT STARTED`, `IN PROGRESS`, `COMPLETED`, `BLOCKED`.

| Milestone ID | Milestone Name | Dependencies | Key Deliverables | Status |
|---|---|---|---|---|
| **M1** | Project Inspection and Setup | None | Folder structure, `requirements.txt`, 146-row synthetic dataset (`data/sample_messages.csv`), initial module stubs. | **COMPLETED** |
| **M2** | Dataset Validation & Machine Learning Baseline | M1 | `docs/00`–`14` suite, `src/features.py`, `src/classifier.py`, `train.py`, `predict.py`, `models/scam_detector.joblib`, `reports/*`, initial `pytest` suite. | **COMPLETED** |
| **M3** | Explainable Rule Engine & Hybrid Detection | M2 | `src/rules.py`, URL/KYC/Lottery/Loan/Job/Hinglish/Obfuscation rules, hybrid score fusion in `predict.py`, `tests/test_rules.py`. | **COMPLETED** |
| **M4** | Local User Interface (Streamlit Dashboard) | M2, M3 | `app.py` bound to `127.0.0.1`, Analyze/Clear controls, color-coded verdict cards, model & evaluation tabs. | **COMPLETED** |
| **M5** | Comprehensive Testing, Edge Cases & Debugging | M2, M3, M4 | Full scam, safe, Hinglish, obfuscated, borderline, and performance test suite in `tests/`. | **COMPLETED** |
| **M6** | Privacy & Offline Verification Audit | M4, M5 | `src/privacy_audit.py`, static AST network scanner, socket-blocked offline tests (`tests/test_privacy.py`), offline checklist. | **COMPLETED** |
| **M7** | Hackathon Readiness & Final Polish | M1–M6 | Synchronized docs, demo message collection, judge Q&A guide, final verification pass. | **COMPLETED** |

---

## 2. Detailed Phase Breakdown

### Milestone 1 — Project Inspection and Setup (`COMPLETED`)
- **Tasks:**
  1. Inspect existing starter pack files and preserve useful documentation.
  2. Verify Python (`3.12.10`) and package availability.
  3. Create `src/`, `models/`, `tests/` directories and module entry points.
  4. Expand `data/sample_messages.csv` to 146 non-duplicate labeled examples covering English, Hinglish (`hi-Latn`), mixed script, obfuscated scams, and diverse legitimate (`SAFE`) messages.
- **Completion Criteria:** Folder tree matches specification; dataset contains zero duplicates and valid schema.

### Milestone 2 — Dataset Validation, Documentation Suite & ML Baseline (`COMPLETED`)
- **Tasks:**
  1. Author the complete 15-document technical specification suite in `docs/` (`00` through `14`) and cross-link root documentation.
  2. Implement dataset schema and hygiene validation in `src/classifier.py`.
  3. Implement Unicode NFKC normalization, dotted-acronym compaction, leetspeak de-obfuscation, and `FeatureUnion` (Word 1–2 TF-IDF + Char-WB 3–5 TF-IDF) in `src/features.py`.
  4. Perform a leakage-free stratified 70% Train / 15% Validation / 15% Test split before fitting vectorizers.
  5. Train Stage-1 Binary Classifier (`SCAM` vs `SAFE`) and Stage-2 Category Classifier (`KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other`).
  6. Generate evaluation metrics, confusion matrices, and latency/size benchmarks in `reports/`.
  7. Implement `predict.py` and verify with automated `pytest` tests in `tests/test_prediction.py`.
- **Completion Criteria:** `python train.py`, `python predict.py`, and `python -m pytest -q` execute cleanly with zero errors and measurable held-out metrics.

### Milestone 3 — Rule Engine and Hybrid Detection (`COMPLETED`)
- **Tasks:**
  1. Implement modular explainable detectors in `src/rules.py` for suspicious URLs, KYC/bank suspension threats, OTP/PIN requests, lottery release fees, loan advance fees, and job/investment scams.
  2. Implement contextual safe-message dampeners (e.g., `"do not share OTP"`, `"debited from A/c"`, `"out for delivery"`).
  3. Combine rule evidence with ML probabilities in `predict.py` without allowing a single benign keyword to trigger a false positive.
  4. Validate threshold on the validation set and write unit tests in `tests/test_rules.py`.
- **Risks & Blockers:** Over-aggressive regex rules could increase `SAFE` false positives; mitigated by requiring multi-signal confirmation or ML alignment.

### Milestone 4 — User Interface (`COMPLETED`)
- **Tasks:**
  1. Build the Streamlit cybersecurity dashboard in `app.py`.
  2. Implement message input area, `Analyze Message` button, `Clear` button, and sample message quick-loader.
  3. Render color-coded verdict banners (Red for `SCAM`, Green for `SAFE`), category badge, confidence bar, explanation bullets, and safety reminder.
  4. Add `About`, `How It Works`, `Privacy`, `Model Info`, `Evaluation`, and `Limitations` sections fed directly from `reports/evaluation_report.json`.

### Milestone 5 — Testing and Debugging (`COMPLETED`)
- **Tasks:**
  1. Expand automated tests across all 15 scam scenarios, 15 safe scenarios, Hinglish/obfuscation cases, and 7 borderline/contradictory scenarios.
  2. Test invalid, empty, whitespace, and 2,000+ character inputs.
  3. Benchmark cold-start load time (`~25 ms`) and warm single-message inference latency (`~4.5 ms`).

### Milestone 6 — Privacy and Offline Verification (`COMPLETED`)
- **Tasks:**
  1. Implement `src/privacy_audit.py` to scan project AST for network clients (`requests`, `urllib`, `httpx`, `socket.connect`, cloud SDKs).
  2. Implement runtime socket-blocking and file-write-interception tests in `tests/test_privacy.py` (`115` total tests passing).
  3. Complete manual OS-level verification (`PA-MAN-01` physical Wi-Fi off test and `PA-MAN-02` `Get-NetTCPConnection` loopback verification).

### Milestone 7 — Hackathon Readiness (`COMPLETED`)
- **Tasks:**
  1. Finalize all root and `docs/` documentation with verified Milestone 1–6 metrics and audit outcomes.
  2. Prepare live 3–4 minute demo script, 12-message quick-test table, and judge technical Q&A guide in `DEMO_SCRIPT.md`.
  3. Run final verification across all 115 automated tests and CLI tools.
