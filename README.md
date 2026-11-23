# Tinyverse — On-Device Scam Message Detector

**Problem Statement:** Tinyverse PS 1 — On-Device Scam Message Detector  
**Status:** Milestone 7 Complete (Hackathon-Ready, 115 Automated Tests Passing, Offline & Loopback Verified)

---

## 1. Project Overview & Problem Statement

Scam messages delivered via SMS and WhatsApp are a pervasive cybersecurity threat in India—ranging from **fake KYC and bank account suspension alerts** to **KBC lottery scams**, **instant 0%-interest loan advance fee traps**, **work-from-home YouTube/Telegram task scams**, and **electricity/customs disconnection threats**.

Many spam filters transmit message text to cloud servers or external LLM APIs, exposing private conversations, bank balances, partial account numbers, and live One-Time Passwords (OTPs) outside the user's device.

**Tinyverse Scam Detector** solves this by analyzing copied SMS and WhatsApp messages **100% locally on the user's laptop (`127.0.0.1`)**. Given a single pasted message, the detector outputs:
1. **Verdict:** `SCAM` or `SAFE`
2. **Scam Category (only when `SCAM`):** `KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, or `Other` (`None` when `SAFE`)
3. **Experimental Hybrid Detection Score:** `0.0%–100.0%` (separating raw ML probability, rule evidence, and combined score)
4. **Review Status:** `CLEAR` or `NEEDS_REVIEW` (when mixed or borderline signals are detected)
5. **Human-Readable Explanation & Safety Recommendation:** Specific statistical terms, fired suspicious/safe rule indicators, and actionable verification guidance.

---

## 2. Key Features

- **100% Offline & Local Execution:** Zero OpenAI, Gemini, Groq, cloud translation, remote database, or telemetry calls. Bound strictly to `127.0.0.1` loopback.
- **Two-Stage Local Machine Learning (`src/classifier.py`):**
  - Combines **Word-level TF-IDF (`1–2` n-grams)** and **Character-WB TF-IDF (`3–5` n-grams)** (`6,376` total vocabulary features fit strictly on the training split).
  - **Stage-1 Binary Classifier:** Calibrated Logistic Regression separating `SCAM` vs. `SAFE`.
  - **Stage-2 Category Classifier:** Multinomial Logistic Regression trained exclusively on `SCAM` examples across the 5 required categories.
- **Explainable Rule Engine & Safe-Message Protections (`src/rules.py`):**
  - **9 Modular Suspicious Rules (`R-*`):** Credential/OTP harvesting (`R-CRED-01`), upfront/advance fees (`R-FEE-01`), lottery/prize claims (`R-LOT-01`), KYC/account suspension threats (`R-KYC-01`), unverified instant loans (`R-LOAN-01`), fake job/investment schemes (`R-JOB-01`), impersonation/customs/QR traps (`R-OTH-01`), shortened/IP/APK/high-risk URLs (`R-URL-01`), leetspeak obfuscation (`R-OBF-01`), and coercive deadlines (`R-URG-01`).
  - **6 Modular Safe-Message Protections (`S-*`):** Protects genuine OTP security advisories (`"Do not share"` / `"Bank kabhi OTP nahi maangta"`), bank debit/credit/ATM alerts (`Avl Bal`), UPI payment confirmations (`UPI Ref`), courier/delivery updates, loan EMI receipts, job application acknowledgements, and personal conversations from false positives—while never suppressing a message that also contains a suspicious request.
- **Hinglish (`hi-Latn`) & Obfuscation Resilience (`src/features.py`):**
  - Handles transliterated Hindi (*"Aapka KYC band ho jayega"*), dotted acronyms (`K.Y.C` $\rightarrow$ `kyc`), and leetspeak substitutions (`fr33` $\rightarrow$ `free`, `l0an` $\rightarrow$ `loan`, `acc0unt` $\rightarrow$ `account`, `cl1ck` $\rightarrow$ `click`, `upd@te` $\rightarrow$ `update`).
- **Auditable Privacy Verification (`src/privacy_audit.py`):**
  - Multi-layer AST import inspection, file-write verification, runtime socket/DNS blocking probes, and manual OS-level verification checklist.

---

## 3. Technology Stack

| Component | Technology | Verified Version | Purpose |
|---|---|---|---|
| **Language** | Python | `3.12.10` (`>=3.11`) | Core runtime for ML, rule engine, UI, and tests |
| **Frontend UI** | Streamlit | `1.67.0` (`>=1.36,<2`) | Local cybersecurity dashboard bound to `127.0.0.1:8501` |
| **Machine Learning** | Scikit-learn | `1.9.1` (`>=1.4,<2`) | Word + Char-WB `TfidfVectorizer`, `LogisticRegression`, calibration |
| **Data Processing** | Pandas | `3.1.1` (`>=2.2,<4`) | Read-only CSV dataset validation and split reporting |
| **Model Storage** | Joblib | `1.6.0` (`>=1.3,<2`) | Local serialization (`models/scam_detector.joblib`, `228 KB`) |
| **Testing** | Pytest | `8.4.2` (`>=8,<9`) | `115` automated unit, rule, hybrid, UI, and privacy tests |
| **Visualization** | Matplotlib | `3.11.2` (`>=3.8,<4`) | Offline generation of `reports/confusion_matrix.png` |

---

## 4. Complete Project Structure

```text
Tinyverse_Scam_Detector_Starter_Pack/
├── README.md                       # Main project overview, setup, and offline demo guide
├── IMPLEMENTATION.md               # Step-by-step implementation architecture and guide
├── ARCHITECTURE.md                 # Hybrid architecture summary and design decisions
├── DATA_AND_MODEL.md               # Dataset schema, split strategy, and evaluation summary
├── PRIVACY_AND_OFFLINE.md          # Privacy safeguards and executed Milestone 6 audit results
├── TEST_PLAN.md                    # Test matrix and acceptance criteria summary
├── DEMO_SCRIPT.md                  # 3-4 minute hackathon pitch, demo messages, and judge Q&A
├── MASTER_PROMPT.md                # Original problem specification
├── requirements.txt                # Pinned Python package constraints
├── pytest.ini                      # Pytest configuration (-p no:cacheprovider)
├── .gitignore                      # Git ignore rules
├── .streamlit/
│   └── config.toml                 # Loopback binding (127.0.0.1) & gatherUsageStats = false
├── app.py                          # Local Streamlit cybersecurity dashboard
├── train.py                        # Dataset validation, model training, and report generator
├── predict.py                      # Hybrid ML + Rule inference API and CLI entrypoint
├── src/
│   ├── __init__.py                 # Package metadata
│   ├── features.py                 # Input validation, normalization, de-obfuscation & TF-IDF
│   ├── classifier.py               # Two-stage ML pipeline, attribution & joblib persistence
│   ├── rules.py                    # Modular explainable scam & safe-protection rule engine
│   └── privacy_audit.py            # AST, config, and runtime socket-isolation privacy auditor
├── data/
│   ├── README.md                   # Dataset documentation
│   └── sample_messages.csv         # Canonical 146-row synthetic dataset (read-only)
├── models/
│   ├── .gitkeep
│   └── scam_detector.joblib        # Trained local ML model bundle (228.02 KB)
├── reports/
│   ├── .gitkeep
│   ├── evaluation_report.json      # Measured train/val/test metrics & latency benchmarks
│   ├── evaluation_summary.md       # Human-readable evaluation summary
│   └── confusion_matrix.png        # Offline binary & category confusion matrix plots
├── docs/                           # Complete 15-document technical specification suite (00..14)
└── tests/
    ├── test_prediction.py          # Dataset, split, ML/hybrid inference, latency & UI tests
    ├── test_rules.py               # Modular rule, safe-protection, Hinglish & security tests
    └── test_privacy.py             # AST, config, socket-lock & non-persistence privacy tests
```

---

## 5. Complete Technical Documentation Suite (`docs/`)

Start at the master documentation index for deep technical specifications:
- **[docs/00_README_Project_Documentation_Index.md](docs/00_README_Project_Documentation_Index.md)**
  - [01 — Project Overview & Problem Definition](docs/01_Project_Overview_PD.md)
  - [02 — Software Requirements Document (SRD)](docs/02_SRD.md)
  - [03 — Technology Stack Specification](docs/03_Technology_Stack.md)
  - [04 — System Architecture (with Mermaid Diagrams)](docs/04_System_Architecture.md)
  - [05 — Message Processing Pipeline](docs/05_Processing_Pipeline.md)
  - [06 — Implementation Specification](docs/06_Implementation_Specification.md)
  - [07 — Development Phases & Milestones](docs/07_Development_Phases.md)
  - [08 — Evaluation and Test Plan](docs/08_Evaluation_and_Test_Plan.md)
  - [09 — Deliverables and Acceptance Criteria](docs/09_Deliverables_and_Acceptance.md)
  - [10 — Privacy and Security Specification](docs/10_Privacy_and_Security_Specification.md)
  - [11 — Database and Data Models](docs/11_Database_and_Data_Models.md)
  - [12 — UI/UX Specification](docs/12_UI_UX_Specification.md)
  - [13 — Setup and Offline Deployment Guide](docs/13_Setup_and_Deployment_Guide.md)
  - [14 — Technical Risk Register](docs/14_Risk_Register.md)

---

## 6. Installation & Execution From a Fresh Setup

### Windows PowerShell (Recommended)
```powershell
# 1. Navigate to the project root directory
cd "C:\Users\supri\Downloads\Tinyverse-Scam-Detector\Tinyverse_Scam_Detector_Starter_Pack"

# 2. (Optional) Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install pinned dependencies (requires internet once during initial setup)
python -m pip install -r requirements.txt

# 4. Train and evaluate the local ML models (saves models/scam_detector.joblib and reports/*)
python train.py

# 5. Run the CLI hybrid prediction demo
python predict.py

# 6. Run the standalone privacy & offline audit check
python -m src.privacy_audit

# 7. Run the complete 115-test automated verification suite
python -m pytest -vv --tb=short

# 8. Launch the local Streamlit dashboard (strictly bound to 127.0.0.1:8501)
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

### Linux / macOS (Bash / Zsh)
```bash
cd /path/to/Tinyverse_Scam_Detector_Starter_Pack
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python train.py
python predict.py
python -m src.privacy_audit
python -m pytest -vv --tb=short
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

---

## 7. Step-by-Step Offline Demonstration Guide

1. Install dependencies and run `python train.py` beforehand.
2. **Disconnect Wi-Fi** (or enable Airplane Mode) in Windows Network Settings.
3. Launch the local dashboard:
   ```powershell
   python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
   ```
4. Open **`http://127.0.0.1:8501`** in your local browser.
5. Paste a scam message (e.g., *"Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately."*) and click **Analyze Message** $\rightarrow$ Verify `SCAM` (`KYC/Bank`).
6. Click **Clear**, paste a legitimate message (e.g., *"Your OTP is 482913. Do not share it with anyone."*) and click **Analyze Message** $\rightarrow$ Verify `SAFE` (`Category: None`).
7. Explain to judges that `127.0.0.1` is the operating system's internal loopback interface—the browser and local Python process communicate strictly inside local RAM with zero external network traffic (verified via `Get-NetTCPConnection -LocalPort 8501`).

---

## 8. Measured Performance & Known Limitations

- **Measured Performance:** Model artifact size is `228.02 KB`, cold load time is `~25 ms`, and warm single-message hybrid inference latency is `~4.5 ms` (`n=50` average).
- **Synthetic Dataset Limitation:** The canonical dataset (`data/sample_messages.csv`) contains `146` synthetic examples (`102` train, `22` validation, `22` held-out test). High held-out metrics (`95.45%` pure ML binary test accuracy, `100.0%` hybrid binary accuracy on the 22-row split, `92.86%` category accuracy) confirm pipeline correctness and zero data leakage, **not** guaranteed accuracy on all unseen real-world campaigns.
- **Experimental Confidence Score:** The displayed hybrid score combines local ML probability with heuristic rule weights (`confidence_type = hybrid_heuristic_ml_score`) and must not be interpreted as a calibrated real-world probability.
- **Safety Disclaimer:** An automated `SAFE` verdict is a decision-support assessment, never a guarantee of sender authenticity. Users should always verify requests for money, OTPs, PINs, or credentials through official channels.
