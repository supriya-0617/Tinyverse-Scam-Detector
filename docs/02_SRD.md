# 02 — Software Requirements Document (SRD)

## 1. Introduction

### 1.1 Purpose
This Software Requirements Document (SRD) specifies the functional, non-functional, interface, error-handling, and verification requirements for the **Tinyverse On-Device Scam Message Detector**. Every requirement is assigned a unique identifier (`FR-xxx` or `NFR-xxx`) and mapped to implementation modules and automated tests in the Requirement Traceability Matrix (Section 10).

### 1.2 Scope
The software is a standalone, local-only Python application comprising a training pipeline (`train.py`), an inference engine (`predict.py`, `src/`), a browser-based local user interface (`app.py`), a privacy audit utility (`src/privacy_audit.py`), and an automated verification suite (`tests/`).

---

## 2. Overall System Description

The system operates in two local modes:
1. **Training & Evaluation Mode (`python train.py`):** Reads the canonical local CSV dataset (`data/sample_messages.csv`), validates schema and data hygiene, splits records into stratified train/validation/test partitions, fits word and character TF-IDF vectorizers on the training split only, trains binary and category classifiers, evaluates metrics on held-out partitions, and serializes artifacts to `models/` and `reports/`.
2. **Inference & UI Mode (`python predict.py` / `streamlit run app.py`):** Loads the serialized local model artifact from `models/`, accepts a single message string, executes input validation, normalization, ML classification, and rule-based analysis in memory, and renders the structured result locally without opening any external network connections.

---

## 3. Functional Requirements (FR)

| Req ID | Requirement Title | Detailed Testable Specification | Priority |
|---|---|---|---|
| **FR-001** | Single Message Input | The system SHALL accept a single plain-text SMS or WhatsApp message via UI text area or Python API function call. | Must Have |
| **FR-002** | Input Validation & Length Bounds | The system SHALL reject empty/whitespace-only inputs with a clear validation status and bound maximum input length to `2,000` characters (`MAX_MESSAGE_LENGTH = 2000`) to prevent memory exhaustion. | Must Have |
| **FR-003** | Safe Text Normalization | The system SHALL normalize Unicode (NFKC), strip zero-width obfuscation characters, standardize whitespace, and produce normalized text views without stripping punctuation or digits needed for obfuscation/URL detection. | Must Have |
| **FR-004** | Binary Scam Classification | The system SHALL classify every valid input message into exactly one binary verdict: `"SCAM"` or `"SAFE"`. | Must Have |
| **FR-005** | Conditional Scam Categorization | When the verdict is `"SCAM"`, the system SHALL assign exactly one category from `{"KYC/Bank", "Lottery/Prize", "Loan/Credit", "Job/Investment", "Other"}`. | Must Have |
| **FR-006** | Null Category on SAFE Verdict | When the verdict is `"SAFE"`, the system SHALL return `None` (or empty/null in UI display) for the scam category. It SHALL NEVER assign a scam category to a `SAFE` message. | Must Have |
| **FR-007** | Confidence Score Generation | The system SHALL output a numeric confidence percentage in the closed interval `[0.0, 100.0]` (`[0.0, 1.0]` probability internal representation) derived from model probability estimates and clearly disclose whether it is calibrated or experimental. | Must Have |
| **FR-008** | Human-Readable Explanations | The system SHALL generate a non-empty list of human-readable explanation strings (`reasons`) detailing the top statistical TF-IDF signals and/or rule-based indicators behind the verdict. | Must Have |
| **FR-009** | Legitimate-Message Protection | The system SHALL NOT classify a message as `"SCAM"` solely because it contains sensitive keywords such as `OTP`, `Bank`, `KYC`, `Account`, `Payment`, `Delivery`, `Urgent`, `Loan`, `Prize`, or a standard URL (`https://`). | Must Have |
| **FR-010** | Multilingual & Hinglish Support | The system SHALL process and classify English (`en`), Hinglish / transliterated Hindi (`hi-Latn`), and mixed-script (`mixed`) messages without using external translation APIs. | Must Have |
| **FR-011** | Obfuscation & Leetspeak Detection | The system SHALL utilize character-level n-gram features (`char_wb`, 3–5 chars) and normalization to detect deliberately obfuscated tokens (e.g., `K.Y.C`, `fr33`, `l0an`, `acc0unt`, `cl1ck`). | Must Have |
| **FR-012** | Dataset Schema & Hygiene Validation | The training pipeline SHALL validate that the dataset contains required columns (`text,label,category,source,language`), contains no duplicate texts, has valid labels, and enforces category consistency before training. | Must Have |
| **FR-013** | Leakage-Free Split & Evaluation | The training pipeline SHALL split data into train, validation, and held-out test sets BEFORE fitting TF-IDF vectorizers or classifiers, and compute accuracy, precision, recall, F1, FPR, FNR, and confusion matrices. | Must Have |
| **FR-014** | Local Model Persistence | The training pipeline SHALL save trained model artifacts and metadata to `models/` using `joblib` and write evaluation metrics to `reports/evaluation_report.json` and `reports/evaluation_summary.md`. | Must Have |
| **FR-015** | Interactive Local UI Controls | The Streamlit UI SHALL provide functional `Analyze Message` and `Clear` buttons, visual color coding (Red for `SCAM`, Green for `SAFE`), and informational sections (`About`, `How it works`, `Privacy`, `Model Info`, `Evaluation`, `Limitations`). | Must Have |

---

## 4. Non-Functional Requirements (NFR)

| Req ID | Category | Detailed Measurable Requirement | Target Metric |
|---|---|---|---|
| **NFR-001** | Offline Operation | Inference (`predict.py` and `app.py`) SHALL operate with 0 external network socket connections when Wi-Fi/Ethernet is disabled. | `0` outbound packets during prediction |
| **NFR-002** | Network Binding Security | The Streamlit server SHALL bind exclusively to loopback `127.0.0.1` and never to `0.0.0.0` or external LAN interfaces. | `--server.address 127.0.0.1` |
| **NFR-003** | Zero Message Persistence | User-submitted messages during inference SHALL be processed strictly in volatile RAM and SHALL NOT be written to disk, databases, or log files. | `0` bytes written to disk per prediction |
| **NFR-004** | Prediction Latency | Single-message inference latency (after model load) on a standard CPU laptop SHALL be under `50 ms`. | `< 50 ms` per message (typical `< 5 ms`) |
| **NFR-005** | Cold-Start Model Load Time | Loading the serialized `.joblib` model artifact from disk into memory SHALL complete in under `1.0 second`. | `< 1000 ms` |
| **NFR-006** | Model Artifact Footprint | Total disk size of serialized model artifacts in `models/` SHALL remain lightweight for CPU laptops. | `< 10 MB` (typical `< 500 KB`) |
| **NFR-007** | Training Time | Full dataset validation, training, calibration, and evaluation in `train.py` SHALL finish in under `15 seconds` on CPU. | `< 15 s` |
| **NFR-008** | Reproducibility | All dataset splits and model training steps SHALL use fixed deterministic random seeds (`RANDOM_SEED = 42`). | Identical metrics across runs |
| **NFR-009** | Safe URL & HTML Handling | The system SHALL never open, fetch, or render clickable suspicious URLs or unescaped user HTML in the UI. | `0` auto-fetched URLs; escaped text |
| **NFR-010** | Automated Test Verification | All unit tests in `tests/` SHALL execute and pass via `python -m pytest -q`. | `100%` test pass rate |

---

## 5. User Requirements & System Constraints

### 5.1 User Requirements
- **UR-01:** A beginner user must be able to install dependencies, train the model, and start the dashboard using copy-pasteable PowerShell or Bash commands.
- **UR-02:** A user pasting a message must immediately understand *why* it was flagged (e.g., "Requests OTP/PIN sharing", "Contains shortened URL with urgency") and what action to take.
- **UR-03:** Users must be explicitly reminded that `"SAFE"` is an automated statistical assessment, not a guarantee of sender authenticity.

### 5.2 System Constraints
- **No Cloud LLM/API Usage:** OpenAI, Gemini, Groq, Anthropic, HuggingFace Inference API, and Google Translate APIs are strictly forbidden.
- **Hardware Constraints:** Must run smoothly on a standard Windows/macOS/Linux laptop with 4 GB+ RAM and no dedicated GPU.
- **Software Constraints:** Python `3.11+` (verified on `3.12.10`) using only approved open-source packages (`streamlit`, `scikit-learn`, `pandas`, `joblib`, `pytest`, `matplotlib`).

---

## 6. Hardware & Software Requirements

| Resource Type | Minimum Specification | Recommended / Verified Specification |
|---|---|---|
| **Operating System** | Windows 10/11, Ubuntu 20.04+, or macOS 12+ | Windows 11 (64-bit) with PowerShell |
| **Processor (CPU)** | Dual-core x86_64 or ARM64 CPU | Quad-core CPU (no GPU required) |
| **Memory (RAM)** | 2 GB free RAM | 4 GB+ RAM |
| **Disk Space** | 250 MB (including Python packages) | 500 MB free space |
| **Python Runtime** | Python `3.11+` | Python `3.12.10` |
| **Web Browser** | Any modern local browser (Edge, Chrome, Firefox) | Local browser accessing `http://127.0.0.1:8501` |

---

## 7. Primary Use Cases

### Use Case UC-01: Analyze a Suspicious SMS/WhatsApp Message
- **Actor:** End User
- **Precondition:** Local model is trained (`models/scam_detector.joblib` exists) and UI is running at `http://127.0.0.1:8501`.
- **Main Flow:**
  1. User copies a suspicious message (e.g., *"Aapka KYC band ho jayega, link par OTP bhejo"*).
  2. User pastes the message into the input box and clicks **Analyze Message**.
  3. System validates input length, normalizes text, extracts TF-IDF features and rule indicators, and computes verdict.
  4. UI displays a Red `SCAM` badge, category `KYC/Bank`, confidence score, detected indicators, and safety advice.

### Use Case UC-02: Verify a Genuine Banking or OTP Alert
- **Actor:** End User
- **Main Flow:**
  1. User pastes *"Your OTP is 482913. Do not share it with anyone."* and clicks **Analyze Message**.
  2. System identifies legitimate protective phrasing and low scam probability.
  3. UI displays a Green `SAFE` badge, `Category: None / Not Applicable`, confidence score, and a standard reminder never to share OTPs.

### Use Case UC-03: Reproducible Offline Model Training & Audit
- **Actor:** Developer / Hackathon Judge
- **Main Flow:**
  1. Actor runs `python train.py` in terminal.
  2. System validates `data/sample_messages.csv`, trains binary & category models, saves artifacts to `models/` and metrics to `reports/`.
  3. Actor disconnects Wi-Fi and runs `python -m pytest -q` and `python predict.py` to verify offline accuracy.

---

## 8. Input / Output & Error-Handling Specifications

### 8.1 Input Specification
- **Type:** `str`
- **Valid Range:** `1` to `2,000` characters after trimming leading/trailing whitespace.
- **Invalid Inputs:** `None`, non-string types, empty string `""`, whitespace-only `"   "`, or strings `> 2,000` characters.

### 8.2 Output Specification
Structured dictionary / `PredictionResult` object:
- `is_valid`: `bool` (`True` if input passed validation, `False` if empty/invalid)
- `verdict`: `"SCAM"` | `"SAFE"` | `None` (if `is_valid` is `False`)
- `category`: `"KYC/Bank"` | `"Lottery/Prize"` | `"Loan/Credit"` | `"Job/Investment"` | `"Other"` | `None`
- `confidence`: `float` (`0.0` to `100.0` percentage)
- `scam_probability`: `float` (`0.0` to `1.0`)
- `reasons`: `list[str]`
- `warnings`: `list[str]`
- `indicators`: `list[dict]` (rule indicators when rule engine is active)
- `model_version`: `str`

### 8.3 Error-Handling Requirements
- **Empty / Whitespace Input:** Must not crash or invoke the ML vectorizer; must return a graceful validation error message (`ValueError` in strict API mode or structured validation warning in UI mode).
- **Oversized Input (`> 2,000` chars):** Must either reject with a clear length error or safely truncate with an explicit warning flag (`warnings` list) so regex/vectorizer operations remain bounded in time and memory.
- **Missing Model Artifact:** If `predict.py` or `app.py` is called before `train.py` has created `models/scam_detector.joblib`, the system must raise/display a beginner-friendly message instructing the user to run `python train.py`.

---

## 9. Acceptance Criteria Summary

1. All 15 `FR-001`–`FR-015` and 10 `NFR-001`–`NFR-010` requirements are implemented and verified.
2. `SAFE` messages never receive a scam category (`category is None`).
3. Held-out test evaluation metrics are computed from a leakage-free split and saved in `reports/`.
4. All automated tests in `tests/` pass (`python -m pytest -q`).

---

## 10. Requirement Traceability Matrix (RTM)

| Requirement ID | Implementation Module(s) | Verification Method / Test File |
|---|---|---|
| **FR-001, FR-002** | `src/features.py`, `predict.py`, `app.py` | `tests/test_prediction.py` (`test_empty_and_whitespace_input`, `test_long_input_handling`) |
| **FR-003, FR-011** | `src/features.py` | `tests/test_prediction.py` (`test_normalization_and_obfuscation`) |
| **FR-004, FR-005, FR-006** | `src/classifier.py`, `predict.py` | `tests/test_prediction.py` (`test_scam_predictions`, `test_safe_predictions_have_no_category`) |
| **FR-007, FR-008** | `src/classifier.py`, `src/rules.py`, `predict.py` | `tests/test_prediction.py` (`test_output_contract_and_confidence_bounds`) |
| **FR-009, FR-010** | `data/sample_messages.csv`, `src/classifier.py`, `src/rules.py` | `tests/test_prediction.py` (`test_borderline_and_false_positive_protection`, `test_hinglish_messages`) |
| **FR-012, FR-013, FR-014** | `train.py`, `src/classifier.py` | `tests/test_prediction.py` (`test_dataset_validation_and_artifacts`) |
| **FR-015** | `app.py` | Manual UI Walkthrough & `tests/test_privacy.py` |
| **NFR-001, NFR-002, NFR-003, NFR-009** | `src/privacy_audit.py`, `predict.py`, `app.py` | `tests/test_privacy.py` |
| **NFR-004, NFR-005, NFR-006, NFR-007** | `train.py`, `predict.py`, `reports/evaluation_report.json` | `tests/test_prediction.py` (`test_inference_latency_and_model_size`) |
| **NFR-008, NFR-010** | `train.py`, `tests/` | `python -m pytest -q` |
