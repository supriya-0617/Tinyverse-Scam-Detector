# Data and Model Plan

> **Authoritative Engineering Reference:** See [docs/08_Evaluation_and_Test_Plan.md](docs/08_Evaluation_and_Test_Plan.md) and [docs/11_Database_and_Data_Models.md](docs/11_Database_and_Data_Models.md) for the single canonical read-only dataset (`data/sample_messages.csv`), leakage-free train/validation/test split protocol, and measured evaluation reports in `reports/`.

## Dataset format

The canonical dataset is located at `data/sample_messages.csv` with columns:

```csv
text,label,category,source,language
"Your account will be blocked. Update KYC using this link.",SCAM,KYC/Bank,synthetic,en
"Rs 450 debited from your account. Available balance ...",SAFE,,synthetic,en
```

- `label`: exactly `SCAM` or `SAFE`
- `category`: required for SCAM; blank for SAFE
- `source`: `synthetic`, `public_dataset`, or `consented_anonymized`
- `language`: e.g. `en`, `hi-Latn`, `mixed`, `other`

Do not include real personal messages, phone numbers, account numbers, or private chat exports without explicit consent and careful anonymization.

## Data strategy

1. Start with carefully written synthetic examples for every scam category and legitimate-message type.
2. Add public datasets only after checking their licence, provenance, label quality, and suitability for Indian SMS/WhatsApp language.
3. Add consented, anonymized examples if available.
4. Include English, Hinglish, transliterated Hindi, mixed-language, misspelled and obfuscated messages.
5. Balance categories and safe-message subtypes.
6. Keep a separate, untouched test set containing unseen templates.

Synthetic data is useful for prototyping but is not proof of real-world accuracy. Clearly disclose its use.

## Avoid data leakage

- Deduplicate exact and near-duplicate messages.
- Split by source/template/campaign where feasible, not just random rows.
- Fit TF-IDF only on the training split.
- Keep the final test set untouched until the design is fixed.
- Report dataset size, class distribution, language distribution, and source.

## Evaluation

For binary classification report:
- Accuracy
- Scam precision and recall
- Scam F1
- Safe-message false-positive rate
- Confusion matrix

For category classification report:
- Per-category precision/recall/F1
- Macro-F1
- Confusion matrix

Also manually test borderline messages and unseen paraphrases.

## Confidence

Use held-out data for probability calibration where sample size permits. If the dataset is small or synthetic, explicitly state that the score is experimental and not a guarantee. A confidence score is not the same as the probability that the message is fraudulent in the real world.
