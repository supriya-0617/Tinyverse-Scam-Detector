# Hackathon Demo Script, Curated Demo Messages & Judge Q&A Guide

> **Reference:** See [docs/01_Project_Overview_PD.md](docs/01_Project_Overview_PD.md), [docs/04_System_Architecture.md](docs/04_System_Architecture.md), [docs/08_Evaluation_and_Test_Plan.md](docs/08_Evaluation_and_Test_Plan.md), and [docs/10_Privacy_and_Security_Specification.md](docs/10_Privacy_and_Security_Specification.md).

---

## 1. 3–4 Minute Live Presentation Script

### Part 1 — The Problem & Why Cloud AI Fails Privacy (30 seconds)
> *"Every day in India, millions of citizens receive scary SMS and WhatsApp messages threatening bank account suspension, electricity disconnection, or promising KBC lottery prizes and work-from-home payouts. Existing cloud spam detectors ask users to upload their messages to external APIs—meaning genuine bank balances, account numbers, and live 6-digit OTPs leave the user's device. For Tinyverse Problem Statement 1, we built a **100% On-Device Hybrid Scam Detector** that runs locally on an ordinary laptop in under 5 milliseconds with zero internet access."*

### Part 2 — Technical Architecture: Why Hybrid ML + Rules? (45 seconds)
> *"Instead of using a heavy black-box LLM or brittle keyword filters alone, we engineered a two-path local pipeline:*
> 1. *First, our normalization layer (`src/features.py`) handles Unicode, compacts dotted acronyms like `K.Y.C`, and de-obfuscates leetspeak like `fr33`, `l0an`, and `acc0unt` while preserving legitimate UPI handles like `swiggy@axisbank`.*
> 2. *Second, a Scikit-learn `FeatureUnion` combines **Word TF-IDF (1–2 n-grams)** with **Character-WB TF-IDF (3–5 n-grams)** feeding a Stage-1 Binary Classifier (`SCAM` vs `SAFE`) and a Stage-2 Scam Category Classifier (`KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other`).*
> 3. *Third, our Explainable Rule Engine (`src/rules.py`) evaluates 9 modular suspicious rules and 6 safe-message protection dampeners using bounded non-additive fusion (`predict.py`), exposing both the raw ML score and the rule evidence transparently."*

### Part 3 — Live Offline Demonstration (90 seconds)
*(Have the Streamlit dashboard open at `http://127.0.0.1:8501` with **Wi-Fi turned OFF** in the Windows taskbar.)*
1. **Point out the Wi-Fi icon and `127.0.0.1` URL:** Show judges that Wi-Fi is disconnected and the browser is communicating over OS loopback (`127.0.0.1:8501`).
2. **Test 1 — Hinglish Scam (`Lottery/Prize`):** Paste or select:
   `"Aapne lottery jeeti hai 25 lakh rupaye ki! Prize lene ke liye pehle Rs 5000 processing fee bhejo."`
   - Click **Analyze Message** $\rightarrow$ Shows Red `SCAM` banner, Category `Lottery/Prize`, fired rules `R-FEE-01` and `R-LOT-01`, and plain-English explanation.
3. **Test 2 — Obfuscated Leetspeak Scam (`KYC/Bank`):** Paste or select:
   `"URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz"`
   - Click **Analyze Message** $\rightarrow$ Shows Red `SCAM` banner, Category `KYC/Bank`, fired rules `R-KYC-01`, `R-URL-01`, `R-OBF-01`.
4. **Test 3 — Genuine Bank Debit Alert (`SAFE` False-Positive Protection):** Click **Clear**, then paste or select:
   `"Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank (UPI Ref 632819402112). Avl Bal: Rs. 18,430.50."`
   - Click **Analyze Message** $\rightarrow$ Shows Green `SAFE` banner, `Scam Category: None`, and fired safe rule `S-BNK-01`.
5. **Test 4 — Contradictory / Ambiguous Message (`NEEDS_REVIEW`):** Paste or select:
   `"Congratulations! You won a lottery prize of Rs 10,00,000 in KBC Lucky Draw. Note: Do not share your OTP with anyone."`
   - Click **Analyze Message** $\rightarrow$ Shows the Amber `NEEDS_REVIEW` warning banner because both `R-LOT-01` and `S-OTP-01` fired.

### Part 4 — Honest Evaluation, Privacy Proof & Close (30 seconds)
> *"Switch to the **Model & Evaluation** and **Privacy** tabs: our canonical dataset (`data/sample_messages.csv`) has 146 synthetic examples split strictly before vectorizer fitting (102 train / 22 val / 22 test). On the 22-row held-out test split, the pure ML baseline achieved 95.45% accuracy (1 false positive), and our hybrid engine resolved that false positive while running in 4.5 milliseconds per message with a 228 KB model artifact. All 115 automated pytest tests and all 9 privacy/offline verification checks—including AST scanning, socket blocking, `Get-NetTCPConnection`, and physical Wi-Fi disconnection—have passed."*

---

## 2. Ready-to-Paste Demo Messages Cheat Sheet

| Demo Scenario | Message to Copy-Paste | Expected Verdict | Expected Category | Expected Review Status |
|---|---|---|---|---|
| **1. Fake KYC Link + OTP Scam** | `Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately.` | `SCAM` | `KYC/Bank` | `CLEAR` |
| **2. Hinglish Lottery Fee Scam** | `Aapne lottery jeeti hai 25 lakh rupaye ki! Prize lene ke liye pehle Rs 5000 processing fee bhejo.` | `SCAM` | `Lottery/Prize` | `CLEAR` |
| **3. Obfuscated Leetspeak Scam** | `URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz` | `SCAM` | `KYC/Bank` | `CLEAR` |
| **4. 0% Interest Loan Advance Fee** | `Instant personal loan of Rs 3,00,000 approved with 0% interest and no CIBIL check. Pay Rs 1,500 advance file charge now.` | `SCAM` | `Loan/Credit` | `CLEAR` |
| **5. Fake YouTube Job Task Scam** | `Work from home job selected! Earn Rs 5000 daily liking YouTube videos. Pay Rs 999 registration fee today to start.` | `SCAM` | `Job/Investment` | `CLEAR` |
| **6. Fake UPI Collect Refund Trap** | `I accidentally sent Rs 15,000 to your UPI ID by mistake. Please approve the collect request and enter your UPI PIN to refund.` | `SCAM` | `Other` | `CLEAR` |
| **7. Genuine Bank UPI Debit Alert** | `Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank (UPI Ref 632819402112). Avl Bal: Rs. 18,430.50.` | `SAFE` | `None` | `CLEAR` |
| **8. Genuine Login OTP Warning** | `Your OTP is 482913. Do not share it with anyone.` | `SAFE` | `None` | `CLEAR` |
| **9. Hinglish Anti-Fraud Advisory** | `OTP kisi ke saath share mat karna. Bank kabhi OTP nahi maangta.` | `SAFE` | `None` | `CLEAR` |
| **10. Borderline Urgent Delivery** | `URGENT: Your package delivery is scheduled for today. Please be available.` | `SAFE` | `None` | `CLEAR` |
| **11. Adversarial Bank + OTP Scam** | `Rs. 500 debited from A/c XX4821. Avl Bal: Rs 12,000. To cancel this transaction, click bit.ly/sbi-cancel and share your 6-digit OTP and ATM PIN immediately.` | `SCAM` | `KYC/Bank` | `CLEAR` |
| **12. Contradictory Signals** | `Congratulations! You won a lottery prize of Rs 10,00,000 in KBC Lucky Draw. Note: Do not share your OTP with anyone.` | `SCAM` | `Lottery/Prize` | `NEEDS_REVIEW` |

---

## 3. Likely Hackathon Judge Questions & Technical Answers

### Q1: "Why didn't you use a local LLM like Llama-3 or Phi-3 via Ollama?"
- **Answer:** A 3B–8B parameter LLM requires `2 GB to 5 GB` of disk/RAM, takes `500 ms to 3,000 ms` per message on a CPU-only laptop, and acts as an opaque black box whose feature weights cannot be audited easily. Our combined **Word (1–2) + Character-WB (3–5) TF-IDF + Logistic Regression + Rule Engine** artifact is only **`228 KB`**, loads in **`25 ms`**, runs inference in **`4.5 ms`** on any standard CPU, and provides exact mathematical feature attributions ($w_i \times x_i$) alongside deterministic rule matches.

### Q2: "How does your detector handle Hinglish and deliberate spelling obfuscation (`K.Y.C`, `fr33`, `l0an`) without calling a translation API?"
- **Answer:** Three mechanisms work together locally:
  1. `src/features.py` compacts dotted acronyms (`K.Y.C` $\rightarrow$ `kyc`) and applies targeted leetspeak de-obfuscation (`fr33` $\rightarrow$ `free`, `l0an` $\rightarrow$ `loan`, `acc0unt` $\rightarrow$ `account`, `upd@te` $\rightarrow$ `update`) while specifically protecting legitimate UPI handles (`swiggy@axisbank`) and ordinals (`5G`, `1st`).
  2. Our `FeatureUnion` pairs word n-grams with **character word-boundary n-grams (`char_wb`, 3–5 chars)**, which capture shared morphological roots across Hinglish spelling variants (`bhejo`/`bhejein`, `karo`/`karein`).
  3. Our training dataset and rule engine explicitly include transliterated Hindi scam and safe patterns.

### Q3: "How do you prevent false positives on genuine bank messages that contain words like 'OTP', 'KYC', 'Bank', or 'Urgent'?"
- **Answer:** First, `35.6%` (`52` rows) of our training dataset consists of genuine bank debit/credit alerts, OTP warnings, courier updates, EMI receipts, and personal chats containing those exact words. Second, our rule engine includes 6 contextual safe-protection rules (`S-OTP-01`, `S-BNK-01`, `S-UPI-01`, `S-DLV-01`, `S-LJK-01`, `S-PER-01`) that dampen false-positive ML spikes **only when zero suspicious rules fire**. If a message looks like a bank alert *and* asks to share an OTP or click a `bit.ly` link, the safe rule is automatically disabled and `R-CRED-01` flags it as `SCAM`.

### Q4: "How do we know your confidence percentage is honest and that you didn't have data leakage?"
- **Answer:** We enforce a strict **split-before-vectorize** protocol in `src/classifier.py`: the 146 deduplicated rows are split (`70%` Train = 102, `15%` Val = 22, `15%` Test = 22) *before* `vectorizer.fit_transform()` is called on the 102 training rows. Furthermore, because our final hybrid score combines statistical ML probability with heuristic rule weights on a small synthetic dataset, we explicitly label `confidence_type = "hybrid_heuristic_ml_score"` in both the API and UI as an *experimental hybrid detection score, not a calibrated real-world probability*.

### Q5: "If it opens in a web browser at `http://127.0.0.1:8501`, isn't it using the internet?"
- **Answer:** No. `127.0.0.1` is the operating system's internal **loopback interface**. The browser tab and the local Python process are both running on the same laptop and communicating through OS memory without touching the Wi-Fi card or router. We verified this across three layers:
  1. Static AST code scanning (`PA-AST-01`, `PA-AST-02`) confirming zero HTTP/cloud/telemetry imports and zero inference file writes.
  2. Runtime socket-blocking tests (`PA-RUN-01`) where `socket.socket` and `urllib.request.urlopen` are monkeypatched to raise `RuntimeError` during inference.
  3. Physical OS-level verification (`PA-MAN-01` and `PA-MAN-02`), confirming `Get-NetTCPConnection -LocalPort 8501` binds solely to `127.0.0.1` and predictions work with Wi-Fi physically turned off.
