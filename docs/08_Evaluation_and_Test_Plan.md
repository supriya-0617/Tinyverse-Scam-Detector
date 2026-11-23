# 08 — Evaluation and Test Plan

## 1. Dataset Description & Canonical Read-Only Source

- **Single Canonical Dataset File:** `data/sample_messages.csv` (treated strictly as read-only by `train.py`).
- **Dataset Size:** `146` labeled messages (`source="synthetic"`).
- **Honest Provenance Disclosure:** Every row in `data/sample_messages.csv` is synthetic (`synthetic`), crafted to reflect realistic Indian SMS and WhatsApp templates across English, Hinglish (`hi-Latn`), mixed script, and leetspeak obfuscations. Synthetic data is essential for privacy-safe prototyping and pipeline verification, **but high metrics on a 146-row synthetic dataset do not guarantee equivalent accuracy on all wild real-world traffic**.

### 1.1 Dataset Distribution (146 Total Rows)
- **Binary Label Distribution:**
  - `SCAM`: `94` rows (`64.4%`)
  - `SAFE`: `52` rows (`35.6%`)
- **Scam Category Distribution (across the 94 `SCAM` rows):**
  - `KYC/Bank`: `28` rows (`29.8%` of scams)
  - `Lottery/Prize`: `20` rows (`21.3%` of scams)
  - `Loan/Credit`: `17` rows (`18.1%` of scams)
  - `Job/Investment`: `17` rows (`18.1%` of scams)
  - `Other`: `12` rows (`12.8%` of scams)
  - `SAFE` (empty category `""`): `52` rows (`100%` of safe rows have empty category)
- **Language Distribution:**
  - `en` (English): `99` rows (`67.8%`)
  - `hi-Latn` (Hinglish / Transliterated Hindi): `42` rows (`28.8%`)
  - `mixed` (Mixed English + Devanagari/script): `5` rows (`3.4%`)

---

## 2. Dataset Quality Checks & Leakage Prevention

Before any model training occurs, `load_and_validate_dataset()` enforces:
1. **Schema Check:** Verifies exact columns `text,label,category,source,language`.
2. **Missing Value Check:** Rejects null/empty `text` or `label` fields.
3. **Label & Category Consistency:** Verifies `label in {"SCAM", "SAFE"}`. Verifies that every `SAFE` row has `category == ""` and every `SCAM` row has `category in {"KYC/Bank", "Lottery/Prize", "Loan/Credit", "Job/Investment", "Other"}`.
4. **Deduplication:** Normalizes whitespace/case to verify `0` duplicate messages exist (`duplicate_count == 0`).
5. **Strict Split-Before-Vectorize Protocol (Leakage Prevention):**
   - The dataset is split into **Training (`70%`, 102 rows)**, **Validation (`15%`, 22 rows)**, and **Held-Out Test (`15%`, 22 rows)** partitions using deterministic stratified sampling (`RANDOM_SEED = 42`) stratified on `(label, category)`.
   - The `FeatureUnion` TF-IDF vocabulary and inverse-document-frequency (IDF) weights are fit **exclusively on the 102 Training rows**.
   - Neither validation nor held-out test messages are ever seen during vocabulary construction or IDF weighting.

---

## 3. Why Training, Validation, and Held-Out Test Metrics Differ

For beginners and judges, it is critical to distinguish our three evaluation partitions:
1. **Training Set (`102 rows`):** The examples the model directly studies to learn word and character weights. High training accuracy only shows the model memorized its study material.
2. **Validation Set (`22 rows`):** Used during development to check probability calibration and verify the decision threshold ($\tau = 0.50$) so we minimize false positives on `SAFE` messages.
3. **Held-Out Test Set (`22 rows`):** Locked away until training is finished. It measures how well the model generalizes to **unseen messages** (`14 SCAM`, `8 SAFE`). Because `22` rows is a small sample (`1` error changes accuracy by `~4.5%`), we report both exact counts (Confusion Matrix) and percentages, plus full cross-validation statistics.

---

## 4. Meaning of Each Evaluation Metric (Beginner-Friendly Guide)

- **True Positive (`TP`):** A real `SCAM` message correctly flagged as `SCAM`.
- **True Negative (`TN`):** A genuine `SAFE` message correctly marked `SAFE`.
- **False Positive (`FP` — False Alarm):** A genuine `SAFE` message wrongly flagged as `SCAM`. *Reducing this is a top priority so users don't ignore real bank/OTP alerts.*
- **False Negative (`FN` — Missed Scam):** A `SCAM` message wrongly marked `SAFE`.
- **Accuracy:** $\frac{TP + TN}{TP + TN + FP + FN}$ — Overall fraction of correct predictions.
- **Scam Precision:** $\frac{TP}{TP + FP}$ — When the detector says `SCAM`, how often is it actually a scam?
- **Scam Recall (Sensitivity):** $\frac{TP}{TP + FN}$ — Out of all actual scams, what percentage did the detector catch?
- **F1-Score:** Harmonic mean of Precision and Recall ($2 \cdot \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$).
- **SAFE False-Positive Rate (`FPR`):** $\frac{FP}{FP + TN}$ — Percentage of genuine `SAFE` messages falsely flagged as `SCAM` (Target: as close to `0%` as possible).
- **SCAM False-Negative Rate (`FNR`):** $\frac{FN}{FN + TP}$ — Percentage of `SCAM` messages missed.
- **Category Macro-F1:** Unweighted average of F1-scores across all 5 scam categories (`KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other`), giving equal importance to smaller categories like `Other`.

---

## 5. Required Test Scenarios & Acceptance Matrix

Our automated test plan (`tests/`) and benchmark suite evaluate:

### Group A — Scam Detection Coverage
1. Fake KYC expiry / link scam (`KYC/Bank`)
2. Fake bank account suspension / electricity disconnect scam (`KYC/Bank`)
3. Fake lottery / KBC lucky draw claim (`Lottery/Prize`)
4. Prize release / customs / GST fee scam (`Lottery/Prize`)
5. Fake instant 0%-interest loan (`Loan/Credit`)
6. Loan advance processing / NOC fee scam (`Loan/Credit`)
7. Fake work-from-home job requesting registration fee (`Job/Investment`)
8. Guaranteed high-return crypto/stock investment fraud (`Job/Investment`)
9. Suspicious shortened URL (`bit.ly`, `tinyurl.com`) & `.xyz`/`.top` domains
10. Direct OTP / UPI PIN harvesting scam
11. Hinglish (`hi-Latn`) scam messages (*"Aapka KYC band ho jayega..."*)
12. Obfuscated / leetspeak scam messages (*"Acc0unt bl0ck"*, *"Fr33 pr1ze"*, *"L0an appr0ved"*)

### Group B — Legitimate (`SAFE`) Message Protection
1. Genuine bank debit alert (`Rs. 1,250 debited from A/c...`)
2. Genuine bank credit / salary alert
3. Genuine login OTP message
4. Explicit OTP safety warning (*"Do not share this OTP with anyone"*)
5. UPI payment confirmation receipt
6. Courier / parcel out-for-delivery notification
7. Personal chat in English and Hinglish (*"Kal milte hain, 5 baje coffee pe chalte hain"*)
8. Genuine job interview / application acknowledgement (*"We never charge any fee"*)
9. Monthly loan EMI repayment confirmation
10. Doctor / clinic appointment reminder

### Group C — Borderline & Adversarial False-Positive Tests
1. Message containing an `https://` URL (e.g., official Python docs or GitHub repo) with no credential request.
2. Message mentioning `KYC` in an informational/completed context (*"Your periodic KYC update has been processed at your home branch"*).
3. Genuine urgent message (*"URGENT: Your package delivery is scheduled for today"* / flight gate change).
4. Personal conversation mentioning winning a college `prize`.
5. Message mentioning a `bank` holiday or statement email with no suspicious action.
6. Hinglish message warning never to share an `OTP` (*"OTP kisi ke saath share mat karna"*).

---

## 6. Performance, Offline & Regression Testing

- **Measured Milestone 2 Baseline Results (Saved in `reports/evaluation_report.json`):**
  - **Held-Out Test Binary (`22` rows: `14 SCAM`, `8 SAFE`):** Accuracy `95.45%`, Precision `93.33%`, Recall `100.00%`, F1-Score `96.55%`, `SAFE` False-Positive Rate `12.50%` (`1` FP out of `8` SAFE), `SCAM` False-Negative Rate `0.00%` (`0` FN out of `14` SCAM). Confusion Matrix: `TN=7, FP=1, FN=0, TP=14`.
  - **5-Fold Stratified Cross-Validation F1 on Training Split (`102` rows):** `92.11% ± 1.24%`.
  - **Held-Out Test Category (`14` SCAM rows):** Category Accuracy `92.86%`, Macro-F1 `90.48%`, Weighted-F1 `92.18%`.
  - **Measured Local Benchmarks:** Training time `776.43 ms`, Model size `228.02 KB`, Cold-start load time `91.79 ms`, Single-message inference latency `16.775 ms`.
- **Performance Benchmarks:** Automated assertions in `tests/test_prediction.py` verify model artifact size `< 10 MB`, model load time `< 1.0 s`, and single-message prediction latency `< 50 ms`.
- **Offline Verification:** Automated test monkeypatches `socket.socket` during `predict_message()` to prove zero network calls occur during inference.
- **Regression Suite:** Executed via `python -m pytest -vv --tb=short` (configured via `pytest.ini` with `-p no:cacheprovider` so read-only/sandboxed runs never hang writing `.pytest_cache`). In Milestone 5 and Milestone 6, the automated suite was expanded to **115 test cases** covering 15 scam scenarios, 15 safe scenarios, 10 Hinglish/obfuscation scenarios, 14 security/input-validation payloads, contradictory `NEEDS_REVIEW` cases, UI state tests, and 9 multi-layer privacy/offline verification tests in `tests/test_privacy.py`.
- **Measured Milestone 5 Latency Benchmarks (Repeatable `n=50` warm average):**
  - **Model Artifact Size:** `228.02 KB` (`models/scam_detector.joblib`)
  - **Model Loading Time:** `~25.2 ms`
  - **Cold Hybrid Prediction Latency (including model load):** `~50.5 ms`
  - **Warm Pure ML Prediction Latency (`n=50`):** `~3.20 ms` per message
  - **Warm Hybrid Prediction Latency (`n=50`, ML + 15 Rules):** `~4.48 ms` per message
- **Important Distinction Between Held-Out Model Evaluation and Scenario Testing:**
  - The held-out test split (`22` rows from the `146`-row synthetic dataset) evaluates statistical model generalization on unseen split partitions (`95.45%` pure ML binary accuracy, `100.0%` hybrid binary accuracy on the `22`-row split, `92.86%` category accuracy).
  - The 106-item `pytest` suite and 54-item diagnostic scenario matrix verify functional behavior, rule-engine coverage, input bounds, and regression safety; manually constructed test fixtures are **not** claimed as an independent real-world accuracy evaluation.
