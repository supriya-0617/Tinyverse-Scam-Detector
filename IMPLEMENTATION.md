# Implementation Plan

> **Authoritative Engineering Reference:** See [docs/00_README_Project_Documentation_Index.md](docs/00_README_Project_Documentation_Index.md), [docs/06_Implementation_Specification.md](docs/06_Implementation_Specification.md), [docs/07_Development_Phases.md](docs/07_Development_Phases.md), and [docs/13_Setup_and_Deployment_Guide.md](docs/13_Setup_and_Deployment_Guide.md) for detailed module contracts and milestone tracking.

## 1. Goal

Build a desktop-friendly web interface that accepts one copied SMS/WhatsApp message and returns:

- Verdict: `SCAM` or `SAFE`
- Category for scams: `KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, or `Other`
- Confidence score (0–100%)
- Short explanation showing the strongest signals
- A safety reminder to independently verify suspicious requests

The entire prediction path must work without internet access after dependencies and model files have been installed locally.

## 2. Recommended stack

| Layer | Choice | Reason |
|---|---|---|
| Runtime | Python 3.11+ | Easy to run on ordinary laptops |
| UI | Streamlit | Fast, simple local interface |
| Text processing | scikit-learn TF-IDF | Lightweight and CPU-friendly |
| Text model | LogisticRegression or LinearSVC + calibration | Fast baseline; easy to inspect |
| Model storage | joblib | Local model artifact |
| Tests | pytest | Repeatable verification |

Avoid large language models and cloud APIs. A compact classical ML model is easier to audit, explain, and run offline.

## 3. Prediction pipeline

```text
User pastes message
        |
        v
Input validation (empty / length limit)
        |
        v
Normalize text (case-fold, whitespace; preserve useful tokens)
        |
        +----------------------------+
        |                            |
        v                            v
Rule-based indicators          Local ML classifier
(URL, urgency, OTP,             word TF-IDF +
money request, KYC,             character TF-IDF
lottery, job, loan)                   |
        |                            |
        +-------------+--------------+
                      |
                      v
             Decision / score fusion
                      |
                      v
        Verdict + category + confidence
                      |
                      v
          Local UI (no network request)
```

The model must be trained with examples of both scams and legitimate messages. Rules are supporting evidence, not a substitute for representative training data.

## 4. Suggested module responsibilities

- `app.py`: Streamlit UI, input box, result rendering. Bind only to localhost.
- `train.py`: Load labelled CSV, validate columns, split train/validation data, train vectorizer and classifier, calibrate if enough data, save model locally.
- `predict.py`: Load local model and return a structured prediction.
- `src/features.py`: Safe text normalization and URL/phone/number feature extraction.
- `src/rules.py`: Explainable indicators and category hints. Do not automatically classify every OTP or bank message as scam.
- `src/classifier.py`: Model training, inference, calibration, category model.
- `src/privacy_audit.py`: Static checks / runtime checks documenting that prediction code makes no outbound network calls.
- `tests/`: Unit tests for rules, prediction contract, and privacy safeguards.

## 5. Labels and categories

Use two separate prediction tasks:

1. Binary label: `SCAM` or `SAFE`.
2. Scam category, trained only on scam-labelled rows:
   - `KYC/Bank`
   - `Lottery/Prize`
   - `Loan/Credit`
   - `Job/Investment`
   - `Other`

Do not force a category on safe messages. Return `category: null` for `SAFE`.

## 6. Confidence

- Prefer calibrated probabilities (for example, `CalibratedClassifierCV`) when there are enough independent labelled examples.
- Split data before fitting vectorizers or models to avoid leakage.
- Keep near-duplicates and messages from the same template in the same split where possible.
- Report validation metrics: precision, recall, F1, confusion matrix, false-positive rate on safe messages, and category macro-F1.
- If calibration cannot be supported by the available data, show a clearly labelled confidence score and disclose this in the UI and report.
- Do not turn a weak model score into 99% confidence just because one rule fired.

## 7. Legitimate-message protection

Include diverse legitimate examples:
- Bank debit/credit alerts
- OTP and login verification messages
- UPI transaction confirmations
- Courier and delivery updates
- Appointment reminders
- Personal conversations
- Job application acknowledgements
- Loan repayment receipts

A bank name, the word `OTP`, a URL, or urgency alone must not imply scam. Evaluate false positives explicitly.

## 8. Local run

After the agent creates the project:

```bash
python -m venv .venv
```

Windows PowerShell:
```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python train.py
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

macOS/Linux:
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
python train.py
python -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501
```

Open `http://127.0.0.1:8501` on the same machine.

For a true offline demonstration, install dependencies and train/download no resources beforehand, then disconnect Wi-Fi and run the app. The app must still work. Do not use `0.0.0.0`, public tunnels, or cloud deployment for the privacy demonstration.

## 9. Definition of done

- One-message input works.
- Output schema is exact.
- Safe messages have no scam category.
- Model and data remain local.
- No external API or outbound network dependency exists in prediction.
- Tests pass.
- App works with internet disconnected.
- Metrics and dataset limitations are documented.
