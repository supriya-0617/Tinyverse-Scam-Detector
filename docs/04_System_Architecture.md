# 04 — System Architecture Specification

## 1. Architectural Vision & Design Principles

The Tinyverse Scam Detector follows a **Local-First, Modular, Dual-Stage Hybrid Architecture**:
1. **Strict Local Execution Boundary:** All components run inside a single user-owned operating system process. There are no external microservices, no cloud inference endpoints, and no remote databases.
2. **Separation of Concerns:** UI rendering (`app.py`), orchestration (`predict.py`, `train.py`), feature normalization (`src/features.py`), statistical ML (`src/classifier.py`), explainable domain rules (`src/rules.py`), and privacy auditing (`src/privacy_audit.py`) are isolated into independent modules with clean interfaces.
3. **Phased Hybrid Evolution:**
   - **Milestone 2 (Current Implementation):** Establishes the complete, leakage-free **Machine Learning Pipeline** (`src/features.py`, `src/classifier.py`, `train.py`, `predict.py`) so baseline ML accuracy and false-positive rates can be measured independently.
   - **Milestone 3 (Planned Next Step):** Integrates the **Explainable Rule Engine** (`src/rules.py`) with the ML probabilities via calibrated decision fusion.
   - **Milestone 4 (Planned UI):** Connects the **Streamlit Dashboard** (`app.py`) to `predict.py` and `reports/`.

---

## 2. Diagram 1: Overall System Architecture

```mermaid
flowchart TD
    subgraph LocalMachine["User's Local Computer (127.0.0.1 — Offline Boundary)"]
        User["User (Pastes SMS / WhatsApp Message)"] --> UI["app.py: Streamlit Local UI (Milestone 4)"]
        User --> CLI["predict.py: CLI & Python Inference API (Milestone 2)"]
        
        UI --> Validator["Input Validation & Length Guard (src/features.py)"]
        CLI --> Validator
        
        Validator --> Normalizer["Text Normalizer & De-obfuscator (src/features.py)"]
        
        Normalizer --> RuleEngine["src/rules.py: Explainable Rule Engine (Milestone 3)"]
        Normalizer --> FeatureUnion["Word TF-IDF + Char-WB TF-IDF (src/features.py)"]
        
        FeatureUnion --> BinModel["Stage-1 Binary Classifier: SCAM vs SAFE (src/classifier.py)"]
        FeatureUnion --> CatModel["Stage-2 Category Classifier: 5 Scam Classes (src/classifier.py)"]
        
        RuleEngine --> DecisionEngine["Decision & Explanation Engine (predict.py)"]
        BinModel --> DecisionEngine
        CatModel --> DecisionEngine
        
        ModelStore[("models/scam_detector.joblib")] -.->|"Loaded into RAM"| BinModel
        ModelStore -.->|"Loaded into RAM"| CatModel
        
        DecisionEngine --> Output["Structured PredictionResult (Verdict, Category, Confidence, Reasons)"]
        Output --> UI
        Output --> CLI
    end
```

---

## 3. Diagram 2: Reproducible Training Pipeline Architecture (`train.py`)

```mermaid
flowchart LR
    CSV[("data/sample_messages.csv")] --> Loader["load_and_validate_dataset()"]
    Loader --> Checks["Schema, Missing Value, Label, Category & Duplicate Checks"]
    Checks --> Split["Stratified Train (70%) / Val (15%) / Test (15%) Split (Seed=42)"]
    
    Split -->|"Train Text Only (No Leakage)"| FitVec["Fit Word (1-2) + Char (3-5) TF-IDF Vectorizer"]
    FitVec --> TrainBin["Train & Calibrate Binary LogisticRegression (SCAM vs SAFE)"]
    FitVec -->|"SCAM Rows Only"| TrainCat["Train Category LogisticRegression (5 Categories)"]
    
    Split -->|"Validation Split"| ValTune["Verify Threshold & Calibration"]
    Split -->|"Held-Out Test Split"| Eval["Compute Test Metrics, Confusion Matrix, FPR & FNR"]
    
    TrainBin --> SaveModel["Save Artifact: models/scam_detector.joblib"]
    TrainCat --> SaveModel
    Eval --> SaveReports["Write reports/evaluation_report.json & Summary Plots"]
```

---

## 4. Diagram 3: Runtime Prediction Pipeline (`predict.py`)

```mermaid
sequenceDiagram
    participant Caller as User / UI / Test
    participant Predict as predict.py (predict_message)
    participant Feat as src/features.py
    participant Clf as src/classifier.py (Loaded Artifact)
    participant Rules as src/rules.py (Milestone 3 Hook)

    Caller->>Predict: predict_message(raw_text)
    Predict->>Feat: validate_and_prepare_input(raw_text)
    alt Input is Empty or Invalid
        Feat-->>Predict: Validation Error / Warnings
        Predict-->>Caller: PredictionResult(is_valid=False, verdict=None)
    else Input is Valid
        Feat->>Feat: normalize_text(raw_text)
        Feat-->>Predict: normalized_text, metadata_signals
        Predict->>Clf: predict_with_model(normalized_text)
        Clf->>Clf: Transform via fitted Word+Char TF-IDF
        Clf->>Clf: Compute Binary P(SCAM) & Top Contributing Features
        alt Verdict == SCAM
            Clf->>Clf: Predict Scam Category (KYC/Bank, Lottery, Loan, Job, Other)
        else Verdict == SAFE
            Clf->>Clf: Set Category = None
        end
        Clf-->>Predict: ML Verdict, Category, Confidence, Feature Explanations
        opt Milestone 3 Hybrid Rule Fusion Enabled
            Predict->>Rules: evaluate_rules(raw_text, normalized_text)
            Rules-->>Predict: Rule Indicators & Score Adjustments
        end
        Predict-->>Caller: PredictionResult(verdict, category, confidence, reasons, warnings)
    end
```

---

## 5. Diagram 4: Privacy & Trust Boundary Architecture

```mermaid
flowchart TB
    subgraph TrustedLocalZone["TRUSTED LOCAL EXECUTION ZONE (User Device)"]
        direction TB
        Browser["Local Web Browser (http://127.0.0.1:8501)"]
        Loopback["OS Loopback Interface (127.0.0.1 ONLY)"]
        AppProc["Python Process (app.py / predict.py) — Volatile RAM Only"]
        LocalFiles[("Read-Only At Inference: models/*.joblib")]
        
        Browser <-->|"Local Loopback HTTP (Never leaves OS)"| Loopback
        Loopback <--> AppProc
        LocalFiles -->|"Read once at startup"| AppProc
    end

    subgraph BlockedExternalZone["BLOCKED EXTERNAL ZONE (Untrusted Network / Disk Persistence)"]
        direction TB
        CloudAI["Cloud LLM APIs (OpenAI, Gemini, Groq) — FORBIDDEN"]
        ExtNet["External HTTP / DNS / Telemetry — BLOCKED"]
        DiskLogs["Message Logs / Databases — PROHIBITED"]
    end

    AppProc -.->|"X Blocked by Architecture & Verified by test_privacy.py"| CloudAI
    AppProc -.->|"X Blocked by Architecture & Air-Gapped Demo"| ExtNet
    AppProc -.->|"X Zero Message Persistence Policy"| DiskLogs
```

---

## 6. Component & Module Responsibilities

| Module Path | Layer | Core Responsibilities | Status |
|---|---|---|---|
| `src/features.py` | Preprocessing & Feature Engineering | Input length/type validation, Unicode NFKC normalization, obfuscation/leetspeak normalization, structural metadata extraction, and Scikit-learn `FeatureUnion` TF-IDF builder. | **Implemented (Milestone 2)** |
| `src/classifier.py` | Machine Learning Core | Dataset schema validator, stratified train/val/test splitter, binary `SCAM`/`SAFE` classifier, 5-class scam category classifier, per-message feature attribution, and `joblib` persistence. | **Implemented (Milestone 2)** |
| `train.py` | Training & Reporting CLI | Orchestrates dataset validation, training, held-out evaluation, confusion matrix plotting, and saving `models/scam_detector.joblib` and `reports/*`. | **Implemented (Milestone 2)** |
| `predict.py` | Inference API & CLI | Loads local model artifact once (cached), runs end-to-end prediction on a single message, enforces output schema (`SAFE` -> `category=None`), and provides CLI testing. | **Implemented (Milestone 2)** |
| `src/rules.py` | Explainable Rule Engine | Modular pattern detectors for suspicious URLs, KYC/bank threats, OTP/PIN harvesting, advance fees, lottery claims, and safe-message dampeners. | **Planned (Milestone 3)** |
| `app.py` | Local User Interface | Streamlit dashboard bound to `127.0.0.1` with input box, Analyze/Clear buttons, color-coded result cards, and model/evaluation tabs. | **Planned (Milestone 4)** |
| `src/privacy_audit.py` | Security & Privacy Verification | AST-based static scanner for banned network libraries, dependency auditor, and runtime socket-blocking verification helpers. | **Planned (Milestone 6)** |

---

## 7. Key Architecture Decisions (ADRs)

- **ADR-01: Two-Stage Hierarchical Classification vs. Single 6-Class Classifier:**
  - *Decision:* Separate Binary Classification (`SCAM` vs `SAFE`) from Scam Category Classification (`5 categories`).
  - *Rationale:* Binary scam detection requires high recall and low false-positive rates across two broad classes, whereas category classification only applies to confirmed scams. Separating them guarantees that `SAFE` messages never receive a scam category and prevents the `SAFE` class (52 rows) from dominating smaller scam subcategories (12–28 rows).
- **ADR-02: Combined Word + Character-WB TF-IDF (`FeatureUnion`):**
  - *Decision:* Combine word n-grams (`1, 2`) with character word-boundary n-grams (`3, 5`).
  - *Rationale:* Word n-grams provide readable phrase explanations (`"share otp"`, `"processing fee"`), while character n-grams capture subword roots across Hinglish spelling variants and leetspeak obfuscations (`K.Y.C`, `fr33`, `l0an`).
- **ADR-03: Single Read-Only Canonical Dataset Source:**
  - *Decision:* Designate `data/sample_messages.csv` as the single authoritative canonical dataset and treat it strictly as read-only during `train.py`.
  - *Rationale:* Prevents unnecessary file writes into `data/` during training and avoids schema or content drift.
