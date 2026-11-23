# Dataset folder

The single canonical labelled dataset is located at `data/sample_messages.csv` and is treated as read-only during model training (`train.py`). (`data/messages.csv` is retained only for starter-pack backward compatibility and is not modified by training.)

Required columns: `text,label,category,source,language`.

- `label`: `SCAM` or `SAFE`
- `category`: One of `KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other` when `label` is `SCAM`; empty when `label` is `SAFE`.
- `source`: `synthetic`, `public_dataset`, or `consented_anonymized`.
- `language`: `en`, `hi-Latn`, `mixed`, or `other`.

Use only legally usable public data or consented/anonymized messages. Never commit private chat exports, OTPs, phone numbers, account details, or personal identifiers. Synthetic examples are suitable for testing the pipeline, not for claiming real-world accuracy.
