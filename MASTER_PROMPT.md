# MASTER PROMPT — Tinyverse On-Device Scam Message Detector

You are a senior Python engineer, applied NLP/ML engineer, privacy engineer, and hackathon mentor. Build a complete, beginner-friendly, working implementation of the Tinyverse problem statement in this folder.

## Non-negotiable requirements

1. The application must run fully locally at prediction time.
2. No external APIs, cloud inference, hosted models, remote databases, telemetry, analytics, external fonts/CDNs, or network calls.
3. Bind Streamlit only to `127.0.0.1`.
4. Do not persist submitted message content or write it to logs.
5. The app must work after Wi-Fi is disconnected, once dependencies and the local model are installed.
6. Input is one copied SMS/WhatsApp message.
7. Output:
   - Verdict: exactly `SCAM` or `SAFE`
   - If SCAM, category exactly one of `KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other`
   - Confidence from 0 to 100
   - Short, understandable reasons
8. Do not classify every OTP, bank alert, URL, or urgent message as a scam. Protect legitimate bank alerts, OTP warnings, delivery updates, and personal messages.
9. Support English, Hinglish, transliterated Hindi, spelling variation, shortened links, phone numbers, urgency language, and obfuscation as far as the available data permits.
10. Be honest about dataset limitations and measured performance. Do not fabricate metrics or claim guaranteed detection.

## Read these documents first

- `README.md`
- `IMPLEMENTATION.md`
- `ARCHITECTURE.md`
- `DATA_AND_MODEL.md`
- `PRIVACY_AND_OFFLINE.md`
- `TEST_PLAN.md`

Treat the provided problem statement as the source of truth. If any design choice conflicts with it, the problem statement wins.

## Technology choices

Use Python 3.11+, Streamlit, pandas, scikit-learn, joblib, and pytest unless there is a strong technical reason not to. Prefer a compact classical ML model over an LLM. Use a combined word/character TF-IDF representation and a lightweight linear classifier. Add a separate scam-category classifier. Calibrate probabilities when the dataset size supports it; otherwise clearly label the score as an experimental model confidence score.

## Required project files

Create and maintain:

```text
README.md
IMPLEMENTATION.md
ARCHITECTURE.md
DATA_AND_MODEL.md
PRIVACY_AND_OFFLINE.md
TEST_PLAN.md
DEMO_SCRIPT.md
requirements.txt
.gitignore
app.py
train.py
predict.py
src/__init__.py
src/features.py
src/rules.py
src/classifier.py
src/privacy_audit.py
data/README.md
data/sample_messages.csv
models/.gitkeep
tests/test_rules.py
tests/test_prediction.py
tests/test_privacy.py
```

Keep the documentation accurate as the code evolves.

## ML and data instructions

- Create a small, clearly labelled starter dataset with synthetic examples only. Mark every synthetic row as synthetic.
- Include both SCAM and SAFE samples.
- Include all required scam categories and safe subtypes (bank alerts, OTPs, delivery, personal messages, job acknowledgements, payment confirmations).
- Include English and Hinglish/transliterated examples. Do not pretend a tiny synthetic dataset represents real-world prevalence.
- Validate CSV schema and label/category consistency.
- Deduplicate before splitting.
- Split data before fitting vectorizers.
- Use a held-out test set and report accuracy, precision, recall, F1, confusion matrix, false-positive rate for SAFE messages, and category macro-F1 where sample counts permit.
- If there are too few samples to calculate a meaningful metric, say so instead of inventing a result.
- Add a clear path for replacing/augmenting the sample CSV with legally usable, consented and anonymized data.
- Make thresholds configurable and select them using validation data, not intuition alone.

## Inference and UI

- Keep prediction logic separate from Streamlit.
- Validate empty and oversized input.
- Return a structured object with verdict, category, confidence, reasons, and any warning/limitations.
- A SAFE verdict must have no category.
- Display a prominent warning that a SAFE result is not a guarantee and users must verify requests for money, OTP, PIN, passwords, or account access through official channels.
- Never echo the full message into logs or diagnostic output.
- The UI must explain that a local browser-to-app loopback connection is used, but no external service receives the message.

## Privacy audit

- Search the codebase for network-capable imports and outbound calls.
- Do not add network code just to “test” privacy.
- Add automated tests that fail if forbidden network/API dependencies are introduced into application modules (use a sensible allowlist and explain limitations).
- Document that static source inspection alone cannot prove absence of network traffic.
- Provide manual offline verification steps: disconnect Wi-Fi, run app, submit messages, and optionally inspect OS network activity/firewall logs.
- Do not use `0.0.0.0`, tunnels, or public hosting.

## Engineering quality

- Write simple, readable code with comments suitable for a beginner.
- Use type hints where helpful.
- Handle missing model files with a clear instruction to run `python train.py`.
- Avoid unnecessary frameworks and packages.
- Add deterministic random seeds.
- Add unit tests for rules, prediction schema, category handling, input validation, and privacy safeguards.
- Ensure `python train.py`, `python -m pytest -q`, and the documented Streamlit command work.
- Do not leave placeholder functions, fake buttons, TODO-only modules, or hard-coded outputs.
- Do not claim a test passed unless you actually ran it and saw the result.

## Work in milestones — do not skip ahead

### Milestone 1 — Inspect and plan
- Inspect the current folder before changing files.
- If it is empty, create the structure.
- If files already exist, preserve useful work and report what will change.
- Present a short plan and risks.
- Do not overwrite user files without explaining the change.

### Milestone 2 — Build baseline
- Implement dataset validation, text normalization, rule indicators, training, prediction and UI.
- Generate only synthetic sample data.
- Train locally and save model artifacts in `models/`.
- Run a smoke test.

### Milestone 3 — Test and improve
- Run all tests.
- Fix failures rather than hiding or skipping them.
- Inspect false positives on safe examples.
- Add difficult borderline and Hinglish examples.
- Do not tune against the final held-out test set.

### Milestone 4 — Privacy verification
- Search for network calls, telemetry, remote assets and message persistence.
- Verify the app binds to localhost.
- Produce a concise privacy audit report.
- Clearly separate what is verified from what still requires manual OS-level checking.

### Milestone 5 — Hackathon readiness
- Update README with exact setup/run commands for Windows PowerShell and macOS/Linux.
- Update measured metrics only.
- Prepare a 3–4 minute demo sequence.
- Provide a final folder tree, exact commands, test results, known limitations and judge-facing explanation.

## Interaction rules

I am a beginner. Give one milestone at a time. Explain exactly:
- Which file you are creating/editing
- What to copy or run
- The exact terminal command
- What successful output should look like
- What to do if an error appears

Do not ask me to make unnecessary technology choices. Use the stack above unless blocked. Do not make me repeatedly approve harmless file creation. Before any destructive operation, ask first.

At the end of each milestone, stop and wait for my confirmation before moving to the next milestone. Keep all actions within this project folder.
