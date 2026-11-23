# 01 — Project Overview & Problem Definition (PD)

## 1. Problem Statement

**Tinyverse Problem Statement (PS 1): On-Device Scam Message Detector**

Users across India receive a high daily volume of fraudulent messages via SMS and WhatsApp. These scams impersonate banks, government agencies, telecom operators, courier companies, and employers to steal One-Time Passwords (OTPs), Unified Payments Interface (UPI) PINs, advance fees, or banking credentials.

While cloud-based spam filters and Large Language Model (LLM) APIs can classify suspicious text, **transmitting personal SMS and WhatsApp messages to external servers introduces a severe privacy vulnerability**: genuine banking alerts, account balances, personal conversations, and confidential OTPs leave the user's device.

**Objective:** Design and build a completely offline, privacy-preserving scam message detector that runs locally on an ordinary laptop, accepts a single copied SMS or WhatsApp message, and produces an accurate, explainable verdict (`SCAM` or `SAFE`), scam category, calibrated confidence score, and human-readable reasoning without any internet connectivity during inference.

---

## 2. Background and Motivation

### 2.1 The Indian Scam Landscape
In India's rapidly growing digital payments ecosystem (driven by UPI, Aadhaar e-KYC, and mobile banking), attackers exploit specific local anxieties and linguistic habits:
1. **Fake KYC & Account Suspension Alerts:** Messages claiming SBI, HDFC, ICICI, Paytm, or FASTag accounts—or electricity connections and SIM cards—will be blocked tonight unless the user clicks a shortened link or shares an OTP.
2. **Lottery, KBC & Bumper Prize Scams:** Claims of winning ₹25 Lakh, cars, or iPhones that require an upfront "processing charge," "RBI release tax," or "GST fee."
3. **Instant Loan & Credit Line Traps:** Promises of 0%-interest, paperless Aadhaar/Mudra loans with no CIBIL check that demand an advance "file charge," "NOC fee," or "insurance fee" before disbursement.
4. **Work-from-Home Job & Crypto/Stock Investment Fraud:** YouTube video-liking tasks, fake Tata/Amazon/Railway job offers demanding registration fees, or "VIP trading groups" promising 200%–300% guaranteed returns.
5. **Hinglish & Obfuscation:** Scammers frequently write in **Hinglish** (Hindi transliterated into Latin characters, e.g., *"Aapka KYC band ho jayega, turant OTP bhejo"*) or use **leetspeak obfuscation** (`K.Y.C upd@te`, `Acc0unt bl0ck`, `Fr33 pr1ze`, `L0an appr0ved`) to bypass simplistic English keyword filters.

### 2.2 Why Cloud AI Is Unsuitable for Personal Message Screening
- **Exposure of Financial PII:** Genuine SMS inbox messages contain partial account numbers, UPI IDs, transaction amounts, and active 6-digit OTPs.
- **Third-Party Data Retention:** Cloud LLM providers may log prompts for abuse monitoring or model training.
- **Offline Availability:** Users in low-connectivity areas or security-conscious environments need a detector that works with Wi-Fi disabled.

---

## 3. Problem Definition

Given an arbitrary single text message $x$ of bounded length ($1 \le |x| \le 2000$ characters) written in English, Hinglish (`hi-Latn`), or mixed script, the system must compute a local function $f(x)$ entirely in local RAM with zero outbound network sockets such that:

$$f(x) \rightarrow (\hat{y}_{\text{binary}}, \hat{y}_{\text{category}}, \hat{p}, E, W)$$

Where:
- $\hat{y}_{\text{binary}} \in \{\text{SCAM}, \text{SAFE}\}$
- $\hat{y}_{\text{category}} \in \{\text{KYC/Bank}, \text{Lottery/Prize}, \text{Loan/Credit}, \text{Job/Investment}, \text{Other}\}$ if $\hat{y}_{\text{binary}} = \text{SCAM}$, else $\text{None}$
- $\hat{p} \in [0, 100]$ represents the confidence percentage
- $E = [e_1, e_2, \dots, e_k]$ is a list of human-readable explanations (rule indicators and/or statistical TF-IDF feature signals)
- $W = [w_1, \dots, w_m]$ is a list of safety warnings and verification reminders

---

## 4. Proposed Solution

We implement a **Dual-Path Hybrid Local Detection Engine**:
1. **Path A — Local Statistical Machine Learning (`src/classifier.py`):**
   - Uses a `FeatureUnion` combining **Word-level TF-IDF** (1–2 n-grams) and **Character-level TF-IDF** (`char_wb`, 3–5 n-grams).
   - Trains a **Stage-1 Binary Classifier** (`LogisticRegression` + probability calibration) to separate `SCAM` from `SAFE`.
   - Trains a **Stage-2 Category Classifier** exclusively on `SCAM` messages to assign one of the 5 scam categories.
2. **Path B — Explainable Modular Rule Engine (`src/rules.py`):**
   - Evaluates transparent, domain-specific cybersecurity patterns (suspicious URLs/shorteners/IP links, credential harvesting requests, upfront fee demands, account suspension threats, and legitimate-message contextual dampeners).
3. **Decision & Explanation Engine (`predict.py`):**
   - Combines ML probabilities with rule evidence (introduced in Milestone 3 on top of the Milestone 2 pure ML baseline) so that neither brittle rules nor dataset shortcuts act alone.

---

## 5. Project Objectives

1. **100% Offline Execution:** Zero external API calls, zero telemetry, zero remote assets, and strict `127.0.0.1` loopback binding.
2. **High Legitimate-Message Protection (Low False Positives):** Correctly classify genuine bank debit/credit alerts, OTP messages with "do not share" warnings, courier updates, loan EMI receipts, and personal chats as `SAFE`.
3. **Multilingual & Obfuscation Resilience:** Accurately detect English, Hinglish (`hi-Latn`), mixed-script, and leetspeak-obfuscated scam messages.
4. **Honest, Measurable Evaluation:** Prevent data leakage by splitting train/validation/test sets before fitting vectorizers, and report real precision, recall, F1, confusion matrices, and false-positive rates.
5. **Beginner-Accessible Engineering:** Clean, modular, PEP-8 compliant Python code with comprehensive documentation and single-command reproducibility.

---

## 6. Scope and Out-of-Scope Features

### 6.1 In Scope
- Single copied SMS or WhatsApp text message analysis via a local Streamlit web UI (`app.py`) and CLI/Python API (`predict.py`).
- Binary classification (`SCAM` vs `SAFE`) and 5-class scam categorization.
- Explainable indicator generation and feature attribution.
- Reproducible local training pipeline (`train.py`) with automated report generation (`reports/`).
- Static and runtime privacy auditing (`src/privacy_audit.py`) and automated `pytest` suite (`tests/`).

### 6.2 Out of Scope
- Direct OS-level interception of live SMS inboxes or WhatsApp encrypted databases on Android/iOS.
- Automated opening, crawling, or active network probing of URLs found inside messages (strictly prohibited for security and offline compliance).
- Cloud deployment, multi-tenant remote API hosting, or user account management.
- Persistent storage or database logging of user-submitted messages.

---

## 7. Target Users

1. **Everyday Indian Mobile & Desktop Users:** Citizens who receive suspicious bank, KYC, electricity, job, or lottery messages on WhatsApp Web or SMS and want a second opinion without uploading private messages online.
2. **Senior Citizens & First-Time Digital Payment Users:** High-risk targets for KBC lottery, electricity disconnection, and fake relative impersonation scams who benefit from clear red/green visual verdicts and plain-language explanations.
3. **Cybersecurity Educators & Hackathon Judges:** Technical evaluators seeking a transparent, auditable, lightweight on-device ML reference implementation.

---

## 8. Expected Outcomes, Innovation & Hackathon Relevance

- **Privacy by Architecture, Not Just Policy:** Instead of promising "we don't store your data on our server," there *is* no remote server—inference runs inside a local Python process verified by static AST checks and socket blocking tests.
- **Character N-Gram Defense Against Obfuscation:** By pairing word n-grams with character-level subword n-grams (`3–5` chars), the model naturally bridges spelling variations in Hinglish (`karo`/`karein`, `bhejo`/`bhejein`) and adversarial character substitutions (`fr33`, `l0an`, `K.Y.C`) in under `5 ms` on a standard laptop CPU.
- **False-Positive Awareness:** Specifically engineered around the reality that words like `OTP`, `Bank`, `KYC`, `Urgent`, and `Prize` appear constantly in benign daily messages.
