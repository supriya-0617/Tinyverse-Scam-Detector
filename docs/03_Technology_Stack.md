# 03 — Technology Stack Specification

## 1. Overview & Selection Philosophy

The Tinyverse On-Device Scam Message Detector is engineered under three strict constraints:
1. **Zero Cloud Dependency:** Every library must execute 100% locally without calling remote APIs.
2. **CPU Efficiency on Ordinary Laptops:** Training must take seconds and inference must take milliseconds on standard student/consumer laptops without a dedicated GPU.
3. **Auditability & Explainability:** Hackathon judges and beginners must be able to inspect feature weights, decision thresholds, and rule triggers directly—avoiding opaque multi-gigabyte black-box models.

---

## 2. Verified Environment & Dependency Matrix

The following table lists every technology in our stack, the version constraints declared in `requirements.txt`, and the **exact installed versions verified** on the development machine (`Windows 11, 64-bit`):

| Component | Package / Tool | `requirements.txt` Constraint | Verified Installed Version | License |
|---|---|---|---|---|
| **Programming Language** | Python | `>=3.11` | `3.12.10` (64-bit AMD64) | PSF License |
| **Frontend UI** | `streamlit` | `>=1.36,<2` | `1.67.0` | Apache 2.0 |
| **Machine Learning** | `scikit-learn` | `>=1.4,<2` | `1.9.1` | BSD 3-Clause |
| **Data Processing** | `pandas` | `>=2.2,<4` | `3.1.1` | BSD 3-Clause |
| **Model Persistence** | `joblib` | `>=1.3,<2` | `1.6.0` | BSD 3-Clause |
| **Automated Testing** | `pytest` | `>=8,<9` | `8.4.2` | MIT License |
| **Charts & Plots** | `matplotlib` | `>=3.8,<4` | `3.11.2` | PSF-based |
| **Version Control** | `git` | N/A (System CLI) | `2.51.0.windows.1` | GPL v2 |

---

## 3. Detailed Technology Justification

### 3.1 Python (`3.12.10`)
- **Purpose:** Core programming language for dataset validation, text preprocessing, machine learning training, rule evaluation, privacy auditing, and UI rendering.
- **Why Selected:** Universal language for NLP and data science; built-in `re`, `unicodedata`, `ast`, `pathlib`, and `dataclasses` modules allow us to implement text normalization and static code privacy audits without risky third-party dependencies.
- **Where Used:** All `.py` files across root, `src/`, and `tests/`.
- **Alternatives Considered:**
  - *Node.js / TypeScript:* Weaker native classical ML and calibration libraries compared to `scikit-learn`.
  - *C++ / Rust:* High development complexity for a beginner-friendly hackathon project.
- **Limitations:** Interpreted runtime is slower than compiled C++ for raw loops, which we mitigate by delegating vectorized math to `scikit-learn`'s Cython/NumPy backends.

### 3.2 Streamlit (`1.67.0`)
- **Purpose:** Renders the local interactive cybersecurity web dashboard.
- **Why Selected:** Enables building a clean, responsive local UI purely in Python without requiring a separate React/Node build toolchain or external CSS/font CDNs. Can be bound strictly to loopback (`--server.address 127.0.0.1`).
- **Where Used:** `app.py` (Milestone 4).
- **Alternatives Considered:**
  - *Flask / FastAPI + HTML/JS:* Requires maintaining separate frontend/backend codebases and templates.
  - *Tkinter / PyQt:* Dated desktop styling and harder to render rich evaluation cards and charts cleanly.
- **Limitations:** Runs a local tornado web server over loopback HTTP (`127.0.0.1`), which must be clearly explained to judges so they understand loopback traffic never leaves the device. Also requires disabling Streamlit's usage statistics (`gatherUsageStats = false`).

### 3.3 Scikit-learn (`1.9.1`)
- **Purpose:** Provides the machine learning pipeline, TF-IDF vectorizers, linear classifiers, probability calibration, stratified splitting, and evaluation metrics.
- **Why Selected:** Industry-standard classical ML library with deterministic, fast CPU execution and built-in model inspection (`coef_`, `feature_names_out`).
- **Where Used:** `src/features.py`, `src/classifier.py`, `train.py`, `predict.py`.
- **Alternatives Considered:**
  - *PyTorch / HuggingFace Transformers (DistilBERT/RoBERTa):* Requires 250 MB–1.5 GB model downloads, slow CPU inference (100–500 ms), harder offline setup, and opaque token attributions.
  - *Cloud LLM APIs (OpenAI / Gemini / Groq):* Strictly prohibited by non-negotiable privacy and offline requirements.
- **Limitations:** Does not possess pre-trained world knowledge outside the training corpus; relies on representative training examples and hybrid rule support for novel scam templates.

### 3.4 TF-IDF Vectorization (Word + Character N-Grams)
- **Purpose:** Converts raw normalized message strings into sparse numerical feature vectors.
- **Why Selected:**
  - **Word TF-IDF (`ngram_range=(1, 2)`):** Captures high-signal words and two-word phrases (`"share otp"`, `"processing fee"`, `"account blocked"`, `"do not"`).
  - **Character TF-IDF (`analyzer="char_wb"`, `ngram_range=(3, 5)`):** Captures subword character sequences inside word boundaries. This is crucial for Indian SMS/WhatsApp scams because it connects morphological variations in Hinglish (`bhejo` / `bhejein`, `karo` / `karein`) and defeats leetspeak obfuscation (`fr33`, `l0an`, `K.Y.C`, `acc0unt`).
- **Where Used:** `src/features.py` and `src/classifier.py`.
- **Alternatives Considered:**
  - *Bag-of-Words (`CountVectorizer`):* Over-weights common words without inverse document frequency scaling.
  - *Word2Vec / FastText static embeddings:* Requires large external embedding files (100 MB+) and struggles with domain-specific Indian acronyms (`UPI`, `KYC`, `NEFT`, `CIBIL`).
- **Limitations:** Bag-of-n-grams loses long-range syntactic dependencies across distant clauses (e.g., negation far away from a keyword), which we mitigate using bigrams/trigrams and contextual rule dampeners.

### 3.5 Logistic Regression + Probability Calibration
- **Purpose:** Serves as the primary linear classifier for both Stage-1 Binary Classification (`SCAM` vs `SAFE`) and Stage-2 Category Classification (`KYC/Bank`, `Lottery/Prize`, `Loan/Credit`, `Job/Investment`, `Other`).
- **Why Selected:**
  - Naturally outputs well-behaved log-odds and probabilities via the sigmoid/multinomial softmax function.
  - Supports `class_weight="balanced"` to handle class/category imbalance without synthetic oversampling artifacts.
  - Every prediction can be explained by multiplying the input message's TF-IDF vector by the learned coefficient vector ($w_i \cdot x_i$) to extract the exact top words/subwords that pushed the score toward `SCAM` or `SAFE`.
  - Paired with `CalibratedClassifierCV` (sigmoid/Platt scaling on held-out folds) to prevent overconfident extreme probabilities.
- **Where Used:** `src/classifier.py`.
- **Alternatives Considered:**
  - *Naive Bayes (`MultinomialNB`):* Strong text baseline, but produces poorly calibrated, overly extreme probabilities (near 0 or 1) when correlated word + char n-grams are combined.
  - *Random Forest / Gradient Boosting:* Slower on high-dimensional sparse TF-IDF matrices and less interpretable per message.
- **Limitations:** Assumes a linear decision boundary in the word+character TF-IDF feature space.

### 3.6 Pandas (`3.1.1`)
- **Purpose:** Loads `data/sample_messages.csv`, validates schema columns, checks missing values and duplicates, and computes class/category/language distributions.
- **Where Used:** `train.py` and `src/classifier.py`.
- **Alternatives Considered:** Built-in `csv` module (used for zero-dependency helpers, while Pandas provides richer tabular reporting and groupby validation).
- **Limitations:** Higher memory overhead for multi-gigabyte datasets, though negligible for our local SMS dataset (`< 1 MB`).

### 3.7 Joblib (`1.6.0`)
- **Purpose:** Serializes and deserializes fitted Scikit-learn pipelines and model metadata to/from disk (`models/scam_detector.joblib`).
- **Why Selected:** Optimized for Scikit-learn estimators containing NumPy arrays; fast load times (`< 50 ms`).
- **Where Used:** `src/classifier.py`, `train.py`, `predict.py`.
- **Alternatives Considered:**
  - *Raw `pickle`:* Less efficient on NumPy arrays.
  - *ONNX:* Adds heavy runtime dependencies (`onnxruntime`) and complex string-vectorizer export constraints.
- **Limitations:** Like `pickle`, `.joblib` files can execute arbitrary code if loaded from untrusted internet sources. Therefore, our security specification (`docs/10_Privacy_and_Security_Specification.md`) mandates loading only locally generated artifacts from `models/` and verifying path containment.

### 3.8 Pytest (`8.4.2`)
- **Purpose:** Executes automated unit, functional, false-positive, borderline, performance, and privacy tests.
- **Where Used:** `tests/test_rules.py`, `tests/test_prediction.py`, `tests/test_privacy.py`.
- **Limitations:** Only tests scenarios represented in test fixtures; must be paired with held-out validation/test dataset evaluation.

### 3.9 Matplotlib (`3.11.2`)
- **Purpose:** Generates local visual evaluation artifacts (confusion matrix heatmaps, category metric bar charts) saved in `reports/` and displayed in the Streamlit dashboard.
- **Why Selected:** Renders static PNG/SVG figures completely offline without loading external JavaScript charting libraries from CDNs.
- **Where Used:** `train.py` and `app.py`.
- **Limitations:** Requires using the non-interactive `"Agg"` backend during headless CLI training so no GUI window blocks terminal execution.
