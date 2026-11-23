# Test Plan and Acceptance Criteria

> **Authoritative Engineering Reference:** See [docs/02_SRD.md](docs/02_SRD.md), [docs/08_Evaluation_and_Test_Plan.md](docs/08_Evaluation_and_Test_Plan.md), and [docs/09_Deliverables_and_Acceptance.md](docs/09_Deliverables_and_Acceptance.md) for the Requirement Traceability Matrix and automated `pytest` verification plan.

## Required test groups

### A. Scam examples
- Fake KYC suspension / account-blocking message
- Fake bank refund or account verification link
- Lottery / prize claim with processing fee
- Instant loan with advance fee
- Fake job offer requesting registration fee
- Investment offer promising guaranteed high returns
- Impersonation and urgency
- Shortened or obfuscated URL
- Hinglish and transliterated examples

### B. Safe examples
- Bank debit/credit notification
- OTP message that says never to share the OTP
- UPI payment confirmation
- Courier delivery update
- Appointment reminder
- Personal conversation
- Job application acknowledgement
- Loan EMI receipt

### C. Borderline examples
- Message contains a URL but no request for credentials
- Message mentions KYC in an informational context
- Message says “urgent” but is a genuine delivery update
- Message contains “prize” in a personal conversation
- Message asks the user to call a known official number
- Message contains a bank name but no suspicious action

## Acceptance criteria

- Empty input is handled gracefully.
- Very long input is bounded safely.
- Output verdict is always exactly `SCAM` or `SAFE`.
- Category is one of the five required categories only when verdict is SCAM.
- Category is empty/null for SAFE.
- Confidence is between 0 and 100.
- Reasons are human-readable and do not expose private content in logs.
- Prediction works with Wi-Fi disconnected.
- No outbound network calls are made by app code.
- Unit tests pass.

## Example test cases

These are illustrative test fixtures, not guaranteed model outcomes. The team must label and test them against its trained model.

| Message pattern | Expected label | Expected category |
|---|---|---|
| “Your KYC will be blocked today. Share OTP at this link.” | SCAM | KYC/Bank |
| “Congratulations, you won a prize. Pay a release fee.” | SCAM | Lottery/Prize |
| “Instant loan approved. Pay processing fee first.” | SCAM | Loan/Credit |
| “Work from home job. Pay registration fee to start.” | SCAM | Job/Investment |
| “Your account was debited by Rs. 250.” | SAFE | — |
| “Your OTP is 123456. Do not share it with anyone.” | SAFE | — |
| “Your parcel is out for delivery.” | SAFE | — |

Do not hard-code these exact strings as the entire classifier. Include paraphrases and unseen test examples.

## Milestone 5 — Executed Test Summary

- **Automated Pytest Suite (`python -m pytest -vv --tb=short`):** `106` total automated tests across `tests/test_prediction.py` and `tests/test_rules.py` (`106 passed, 0 failed, 0 errors, 0 skipped`).
- **Diagnostic Scenario Coverage:**
  - `15 / 15` Scam scenarios (`SCAM` verdict + exact 5-class category match).
  - `15 / 15` Legitimate/Safe scenarios (`SAFE` verdict + `category = None`).
  - `1 / 1` Adversarial fake bank alert with OTP demand (`SCAM` verdict; not suppressed by safe-bank rules).
  - `10 / 10` Hinglish (`hi-Latn`) and Leetspeak obfuscation scenarios.
  - `7 / 7` Borderline & contradictory evidence scenarios (including `NEEDS_REVIEW` triggering).
  - `14 / 14` Input validation, length cap (`2,000` chars), Unicode, emoji, newline, malformed URL, and XSS/HTML security tests.
- *Methodological Note:* These scenario tests validate functional behavior, rule-engine interactions, and edge-case safety. Held-out statistical generalization is reported separately in `reports/evaluation_report.json` (`22` held-out synthetic test rows).
