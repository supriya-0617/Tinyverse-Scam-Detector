# Architecture and Design

> **Authoritative Engineering Reference:** See [docs/04_System_Architecture.md](docs/04_System_Architecture.md) and [docs/05_Processing_Pipeline.md](docs/05_Processing_Pipeline.md) for full Mermaid architecture diagrams, training/inference sequence flows, and privacy boundary specifications.

## Design principle

**Local-first, explainable, lightweight.** The user's message is processed in memory by the local Python process. It is not sent to a server.

## Components

1. **UI:** Local Streamlit page bound to `127.0.0.1`.
2. **Normalizer:** Normalizes case and whitespace while retaining punctuation and character patterns useful for obfuscation detection.
3. **Rule engine:** Extracts explainable indicators. Examples: threat of account blocking, request to share OTP/PIN, advance fee, prize claim, suspicious shortened link.
4. **ML classifier:** Local word and character TF-IDF features with a compact linear classifier.
5. **Category classifier:** Predicts one of the required scam categories for scam messages.
6. **Result renderer:** Displays verdict, category, confidence and reasons.

## Why hybrid?

Rules are easy to explain but brittle against new wording. ML generalizes across patterns but may learn dataset shortcuts. Combining them can improve coverage, provided the combination is validated and does not create excessive false positives.

## Handling Hinglish and obfuscation

- Character n-grams can learn fragments across spelling variants.
- Include real transliterated examples in training and test data.
- Normalize repeated spaces and Unicode carefully.
- Do not translate messages using online services.
- Do not assume English-only keywords.
- Add examples such as `aapka KYC band ho jayega`, `inaam jeeta`, `naukri ke liye registration fee`, and obfuscated variants only when they are labelled and reviewed.

## Decision logic

The implementation should use a documented threshold chosen on validation data. A high-risk indicator may increase the scam score, but a single keyword should not automatically trigger a scam verdict. Safe-message evidence must be represented in training data.

## Resource expectations

A TF-IDF + linear model is suitable for CPU-only laptops. Measure cold-start time, prediction latency, and model size on the actual demo laptop rather than claiming unmeasured performance.
