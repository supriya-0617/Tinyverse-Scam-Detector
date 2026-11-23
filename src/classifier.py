"""Local machine learning classifier, dataset validator, and calibration pipeline.

This module implements:
1. Dataset schema, label, category, missing-value, and duplicate validation.
2. Leakage-free stratified Train (70%) / Validation (15%) / Test (15%) splitting.
3. Stage-1 Binary Classifier (SCAM vs SAFE) using Word + Character TF-IDF and
   calibrated Logistic Regression.
4. Stage-2 Category Classifier (KYC/Bank, Lottery/Prize, Loan/Credit,
   Job/Investment, Other) trained exclusively on SCAM messages.
5. Per-message feature attribution so every ML prediction produces understandable
   explanations.
6. Local model artifact persistence via joblib.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, cross_val_score, train_test_split

from src.features import (
    MAX_MESSAGE_LENGTH,
    build_feature_vectorizer,
    extract_text_signals,
    normalize_text,
    validate_message_input,
)

# Valid binary labels and scam categories
VALID_LABELS: set[str] = {"SCAM", "SAFE"}
VALID_CATEGORIES: tuple[str, ...] = (
    "KYC/Bank",
    "Lottery/Prize",
    "Loan/Credit",
    "Job/Investment",
    "Other",
)
REQUIRED_COLUMNS: tuple[str, ...] = ("text", "label", "category", "source", "language")
RANDOM_SEED: int = 42
MODEL_VERSION: str = "1.0.0-m2-ml-baseline"

# Human-friendly descriptions for structural meta-tokens
_STRUCTURAL_TOKEN_EXPLANATIONS: dict[str, str] = {
    "__short_url__": "Contains a shortened URL link (frequently used to hide phishing domains)",
    "__suspicious_tld__": "Contains an unusual/high-risk domain extension (.xyz, .top, .club, .site, .online)",
    "__ip_url__": "Contains a raw IP-address web link instead of an official domain name",
    "__apk_file__": "Asks the user to download or install an Android .APK file",
    "__obfuscated_text__": "Contains deliberately obfuscated or leetspeak wording (e.g., K.Y.C, fr33, l0an, acc0unt)",
    "__harvest_demand__": "Requests sensitive credentials (OTP/PIN/CVV/password) or an upfront fee payment",
    "__protective_warning__": "Contains an explicit safety reminder never to share OTPs, PINs, or fees",
    "__has_url__": "Contains a web link/URL",
    "__currency_amount__": "Mentions a monetary amount in Rupees/currency",
}


@dataclass
class DatasetValidationReport:
    """Structured report summarizing dataset schema and quality checks."""

    total_rows: int
    scam_count: int
    safe_count: int
    duplicate_count: int
    missing_value_count: int
    category_counts: dict[str, int]
    language_counts: dict[str, int]
    source_counts: dict[str, int]
    warnings: list[str]
    is_valid: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "scam_count": self.scam_count,
            "safe_count": self.safe_count,
            "duplicate_count": self.duplicate_count,
            "missing_value_count": self.missing_value_count,
            "category_counts": self.category_counts,
            "language_counts": self.language_counts,
            "source_counts": self.source_counts,
            "warnings": self.warnings,
            "is_valid": self.is_valid,
        }


@dataclass
class PredictionResult:
    """Structured prediction output for a single analyzed message.

    Preserves both the raw ML model outputs (ml_verdict, ml_scam_probability,
    ml_category) and the hybrid rule-fusion outputs (verdict, category,
    confidence, review_status, rule_score, indicators).
    """

    verdict: Optional[str]
    category: Optional[str]
    confidence: float
    scam_probability: float
    reasons: list[str]
    warnings: list[str] = field(default_factory=list)
    is_valid: bool = True
    indicators: list[dict[str, Any]] = field(default_factory=list)
    model_version: str = MODEL_VERSION
    ml_verdict: Optional[str] = None
    ml_scam_probability: Optional[float] = None
    ml_category: Optional[str] = None
    rule_score: float = 0.0
    rule_risk_level: str = "NONE"
    review_status: str = "CLEAR"  # "CLEAR" or "NEEDS_REVIEW"
    confidence_type: str = "experimental_local_model_score"

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "verdict": self.verdict,
            "category": self.category,
            "confidence": round(float(self.confidence), 1),
            "confidence_ratio": round(float(self.confidence) / 100.0, 4),
            "scam_probability": round(float(self.scam_probability), 4),
            "ml_verdict": self.ml_verdict or self.verdict,
            "ml_scam_probability": round(
                float(
                    self.ml_scam_probability
                    if self.ml_scam_probability is not None
                    else self.scam_probability
                ),
                4,
            ),
            "ml_category": self.ml_category,
            "rule_score": round(float(self.rule_score), 4),
            "rule_risk_level": self.rule_risk_level,
            "review_status": self.review_status,
            "confidence_type": self.confidence_type,
            "reasons": list(self.reasons),
            "warnings": list(self.warnings),
            "indicators": list(self.indicators),
            "model_version": self.model_version,
        }


def load_and_validate_dataset(
    csv_path: str | Path,
    deduplicate: bool = True,
) -> tuple[pd.DataFrame, DatasetValidationReport]:
    """Load CSV dataset and validate schema, labels, categories, and duplicates.

    Args:
        csv_path: Path to the canonical dataset CSV (data/sample_messages.csv).
        deduplicate: Whether to drop duplicate texts if any are found.

    Returns:
        Tuple of (validated DataFrame, DatasetValidationReport).

    Raises:
        FileNotFoundError: If csv_path does not exist.
        ValueError: If schema columns, labels, or categories violate constraints.
    """
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset file not found at: {path}")

    df = pd.read_csv(path, keep_default_na=False)

    # 1. Verify required columns
    missing_cols = [col for col in REQUIRED_COLUMNS if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Dataset is missing required columns: {missing_cols}")

    # Strip whitespace around column values
    for col in REQUIRED_COLUMNS:
        df[col] = df[col].astype(str).str.strip()

    # 2. Check missing values in mandatory fields (text, label, source, language)
    missing_mask = (
        (df["text"] == "")
        | (df["label"] == "")
        | (df["source"] == "")
        | (df["language"] == "")
    )
    missing_value_count = int(missing_mask.sum())
    if missing_value_count > 0:
        raise ValueError(f"Dataset contains {missing_value_count} rows with empty mandatory fields.")

    # 3. Validate binary labels
    invalid_labels = set(df["label"].unique()) - VALID_LABELS
    if invalid_labels:
        raise ValueError(f"Dataset contains invalid label values: {invalid_labels}")

    # 4. Validate category consistency
    # Rule A: SAFE rows must have empty category ""
    safe_with_cat = df[(df["label"] == "SAFE") & (df["category"] != "")]
    if len(safe_with_cat) > 0:
        raise ValueError(
            f"Found {len(safe_with_cat)} SAFE rows with non-empty scam categories."
        )

    # Rule B: SCAM rows must have a category in VALID_CATEGORIES
    scam_rows = df[df["label"] == "SCAM"]
    invalid_cats = set(scam_rows["category"].unique()) - set(VALID_CATEGORIES)
    if invalid_cats:
        raise ValueError(
            f"Found SCAM rows with invalid or empty category values: {invalid_cats}"
        )

    # 5. Check duplicates (case-folded normalized whitespace text)
    canon_text = df["text"].str.lower().str.replace(r"\s+", " ", regex=True).str.strip()
    dup_mask = canon_text.duplicated(keep="first")
    duplicate_count = int(dup_mask.sum())

    warnings: list[str] = []
    if duplicate_count > 0:
        warnings.append(f"Found {duplicate_count} duplicate messages.")
        if deduplicate:
            df = df[~dup_mask].reset_index(drop=True)
            warnings.append(f"Removed {duplicate_count} duplicates; {len(df)} unique rows remain.")

    # Compute distributions
    scam_count = int((df["label"] == "SCAM").sum())
    safe_count = int((df["label"] == "SAFE").sum())
    cat_counts = {
        cat: int((df["category"] == cat).sum()) for cat in VALID_CATEGORIES
    }
    lang_counts = {str(k): int(v) for k, v in df["language"].value_counts().items()}
    src_counts = {str(k): int(v) for k, v in df["source"].value_counts().items()}

    if len(df) < 500:
        warnings.append(
            f"Dataset contains {len(df)} rows (all synthetic). High validation/test "
            "metrics demonstrate pipeline correctness but do not guarantee accuracy "
            "on all wild real-world traffic."
        )

    report = DatasetValidationReport(
        total_rows=len(df),
        scam_count=scam_count,
        safe_count=safe_count,
        duplicate_count=duplicate_count,
        missing_value_count=missing_value_count,
        category_counts=cat_counts,
        language_counts=lang_counts,
        source_counts=src_counts,
        warnings=warnings,
        is_valid=True,
    )
    return df, report


def split_dataset(
    df: pd.DataFrame,
    random_state: int = RANDOM_SEED,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Perform a leakage-free stratified 70% Train / 15% Val / 15% Test split.

    Stratifies on (label + '_' + category) so that SAFE messages and all 5
    SCAM categories are proportionally represented in Train, Val, and Test sets.
    """
    strat_key = df["label"] + "_" + df["category"].replace("", "NONE")

    # First split: 70% Train, 30% Temp (Val + Test)
    train_df, temp_df, _, temp_strat = train_test_split(
        df,
        strat_key,
        test_size=0.30,
        random_state=random_state,
        stratify=strat_key,
    )

    # Second split: divide the 30% Temp equally into 15% Val and 15% Test
    val_df, test_df = train_test_split(
        temp_df,
        test_size=0.50,
        random_state=random_state,
        stratify=temp_strat,
    )

    return (
        train_df.reset_index(drop=True),
        val_df.reset_index(drop=True),
        test_df.reset_index(drop=True),
    )


def train_scam_detector(
    train_df: pd.DataFrame,
    val_df: pd.DataFrame,
    random_state: int = RANDOM_SEED,
) -> dict[str, Any]:
    """Train the Stage-1 Binary and Stage-2 Category models without data leakage.

    Important:
        The TF-IDF FeatureUnion is fit strictly on train_df. Neither val_df nor
        test_df is ever passed to vectorizer.fit().
    """
    # 1. Normalize training and validation texts
    X_train_norm = [normalize_text(t) for t in train_df["text"]]
    y_train_bin = (train_df["label"] == "SCAM").astype(int).to_numpy()

    X_val_norm = [normalize_text(t) for t in val_df["text"]]
    y_val_bin = (val_df["label"] == "SCAM").astype(int).to_numpy()

    # 2. Fit combined Word + Char-WB TF-IDF strictly on training data
    vectorizer = build_feature_vectorizer()
    X_train_vec = vectorizer.fit_transform(X_train_norm)
    X_val_vec = vectorizer.transform(X_val_norm)

    # 3. Train base linear Binary Classifier (kept for exact feature weight attribution)
    binary_linear_model = LogisticRegression(
        C=2.0,
        class_weight="balanced",
        max_iter=1000,
        random_state=random_state,
    )
    binary_linear_model.fit(X_train_vec, y_train_bin)

    # 4. Train Calibrated Binary Classifier using 3-fold Stratified CV on training split
    base_for_cal = LogisticRegression(
        C=2.0,
        class_weight="balanced",
        max_iter=1000,
        random_state=random_state,
    )
    cv_splitter = StratifiedKFold(n_splits=3, shuffle=True, random_state=random_state)
    binary_calibrated = CalibratedClassifierCV(
        estimator=base_for_cal,
        method="sigmoid",
        cv=cv_splitter,
    )
    binary_calibrated.fit(X_train_vec, y_train_bin)

    # 5. Select decision threshold on validation split to protect SAFE messages (low FPR)
    val_probs = binary_calibrated.predict_proba(X_val_vec)[:, 1]
    best_threshold = 0.50
    best_score = -1.0
    for cand_thresh in (0.45, 0.50, 0.55, 0.60):
        preds = (val_probs >= cand_thresh).astype(int)
        f1 = f1_score(y_val_bin, preds, zero_division=0)
        tn, fp, fn, tp = confusion_matrix(y_val_bin, preds, labels=[0, 1]).ravel()
        fpr = fp / max(fp + tn, 1)
        # Reward F1 while strongly penalizing false positives on SAFE messages
        utility = f1 - (0.5 * fpr)
        if utility > best_score:
            best_score = utility
            best_threshold = float(cand_thresh)

    # 6. Train Stage-2 Category Classifier exclusively on SCAM rows in train_df
    scam_train_mask = (train_df["label"] == "SCAM").to_numpy()
    X_train_scam_vec = X_train_vec[scam_train_mask]
    y_train_cat = train_df.loc[scam_train_mask, "category"].to_numpy()

    category_classifier = LogisticRegression(
        C=2.5,
        class_weight="balanced",
        max_iter=1000,
        random_state=random_state,
    )
    category_classifier.fit(X_train_scam_vec, y_train_cat)

    # 7. Compute 5-fold cross-validation score on training split for stability reporting
    cv5 = StratifiedKFold(n_splits=5, shuffle=True, random_state=random_state)
    cv_f1_scores = cross_val_score(
        LogisticRegression(C=2.0, class_weight="balanced", random_state=random_state),
        X_train_vec,
        y_train_bin,
        cv=cv5,
        scoring="f1",
    )

    feature_names = vectorizer.get_feature_names_out()

    bundle: dict[str, Any] = {
        "model_version": MODEL_VERSION,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "random_seed": random_state,
        "vectorizer": vectorizer,
        "binary_classifier": binary_calibrated,
        "binary_linear_model": binary_linear_model,
        "category_classifier": category_classifier,
        "decision_threshold": best_threshold,
        "feature_count": int(len(feature_names)),
        "valid_categories": list(VALID_CATEGORIES),
        "cv5_train_f1_mean": round(float(np.mean(cv_f1_scores)), 4),
        "cv5_train_f1_std": round(float(np.std(cv_f1_scores)), 4),
        "calibration_info": {
            "is_calibrated": True,
            "method": "sigmoid_cv3",
            "train_rows": int(len(train_df)),
            "val_rows": int(len(val_df)),
            "disclosure": (
                "Confidence score is derived from a calibrated local classifier trained on "
                "synthetic examples. Treat it as an experimental model confidence score, "
                "not a guaranteed probability."
            ),
        },
    }
    return bundle


def evaluate_model_bundle(
    bundle: dict[str, Any],
    df_split: pd.DataFrame,
    split_name: str = "test",
) -> dict[str, Any]:
    """Evaluate binary and category classification metrics on a dataset split."""
    vectorizer = bundle["vectorizer"]
    binary_clf = bundle["binary_classifier"]
    category_clf = bundle["category_classifier"]
    threshold = float(bundle.get("decision_threshold", 0.50))

    norm_texts = [normalize_text(t) for t in df_split["text"]]
    X_vec = vectorizer.transform(norm_texts)

    y_true_bin = (df_split["label"] == "SCAM").astype(int).to_numpy()
    scam_probs = binary_clf.predict_proba(X_vec)[:, 1]
    y_pred_bin = (scam_probs >= threshold).astype(int)

    acc = float(accuracy_score(y_true_bin, y_pred_bin))
    prec = float(precision_score(y_true_bin, y_pred_bin, zero_division=0))
    rec = float(recall_score(y_true_bin, y_pred_bin, zero_division=0))
    f1 = float(f1_score(y_true_bin, y_pred_bin, zero_division=0))

    tn, fp, fn, tp = confusion_matrix(y_true_bin, y_pred_bin, labels=[0, 1]).ravel()
    safe_fpr = float(fp / max(fp + tn, 1))
    scam_fnr = float(fn / max(fn + tp, 1))

    # Evaluate Stage-2 Category Classifier on ground-truth SCAM rows in this split
    scam_mask = (df_split["label"] == "SCAM").to_numpy()
    X_scam_vec = X_vec[scam_mask]
    y_true_cat = df_split.loc[scam_mask, "category"].to_numpy()
    y_pred_cat = category_clf.predict(X_scam_vec)

    cat_acc = float(accuracy_score(y_true_cat, y_pred_cat))
    cat_macro_f1 = float(
        f1_score(
            y_true_cat,
            y_pred_cat,
            labels=list(VALID_CATEGORIES),
            average="macro",
            zero_division=0,
        )
    )
    cat_weighted_f1 = float(
        f1_score(
            y_true_cat,
            y_pred_cat,
            labels=list(VALID_CATEGORIES),
            average="weighted",
            zero_division=0,
        )
    )
    cat_report_dict = classification_report(
        y_true_cat,
        y_pred_cat,
        labels=list(VALID_CATEGORIES),
        output_dict=True,
        zero_division=0,
    )
    cat_cm = confusion_matrix(
        y_true_cat,
        y_pred_cat,
        labels=list(VALID_CATEGORIES),
    ).tolist()

    per_category_metrics: dict[str, dict[str, float | int]] = {}
    for cat in VALID_CATEGORIES:
        entry = cat_report_dict.get(cat, {})
        per_category_metrics[cat] = {
            "precision": round(float(entry.get("precision", 0.0)), 4),
            "recall": round(float(entry.get("recall", 0.0)), 4),
            "f1_score": round(float(entry.get("f1-score", 0.0)), 4),
            "support": int(entry.get("support", 0)),
        }

    return {
        "split_name": split_name,
        "row_count": int(len(df_split)),
        "scam_support": int(scam_mask.sum()),
        "safe_support": int((~scam_mask).sum()),
        "binary": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "safe_false_positive_rate": round(safe_fpr, 4),
            "scam_false_negative_rate": round(scam_fnr, 4),
            "confusion_matrix": {
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
            },
        },
        "category": {
            "accuracy": round(cat_acc, 4),
            "macro_f1": round(cat_macro_f1, 4),
            "weighted_f1": round(cat_weighted_f1, 4),
            "labels": list(VALID_CATEGORIES),
            "confusion_matrix": cat_cm,
            "per_category": per_category_metrics,
        },
    }


def explain_ml_prediction(
    bundle: dict[str, Any],
    raw_text: str,
    normalized_text: str,
    X_vec: Any,
    verdict: str,
    category: Optional[str],
    top_k: int = 4,
) -> list[str]:
    """Generate human-readable explanations from active TF-IDF features and signals."""
    if "_cached_feature_names" not in bundle:
        bundle["_cached_feature_names"] = bundle["vectorizer"].get_feature_names_out()
    feature_names = bundle["_cached_feature_names"]
    linear_model: LogisticRegression = bundle["binary_linear_model"]
    coefs = linear_model.coef_[0]

    # Element-wise contribution: x_i * w_i
    row_array = X_vec.toarray()[0]
    contributions = row_array * coefs
    nonzero_indices = np.where(row_array > 0)[0]

    reasons: list[str] = []
    signals = extract_text_signals(raw_text)

    if verdict == "SCAM":
        # Sort positive contributions (features pushing toward SCAM)
        pos_indices = [idx for idx in nonzero_indices if contributions[idx] > 0]
        pos_indices.sort(key=lambda idx: contributions[idx], reverse=True)

        top_words: list[str] = []
        structural_reasons: list[str] = []

        for idx in pos_indices:
            feat = str(feature_names[idx])
            if feat.startswith("word_tfidf__"):
                token = feat.replace("word_tfidf__", "")
                if token in _STRUCTURAL_TOKEN_EXPLANATIONS:
                    desc = _STRUCTURAL_TOKEN_EXPLANATIONS[token]
                    if desc not in structural_reasons:
                        structural_reasons.append(desc)
                elif not token.startswith("__") and len(top_words) < top_k:
                    top_words.append(f"'{token}'")

        reasons.extend(structural_reasons[:3])
        if top_words:
            reasons.append(
                f"Strongest statistical scam terms detected: {', '.join(top_words)}"
            )
        if category:
            reasons.append(
                f"Classified under '{category}' based on local category model patterns"
            )
        if not reasons:
            reasons.append(
                "Character and word n-gram profile matches known scam templates"
            )
    else:
        # Sort negative contributions (features pushing toward SAFE)
        neg_indices = [idx for idx in nonzero_indices if contributions[idx] < 0]
        neg_indices.sort(key=lambda idx: contributions[idx])

        safe_words: list[str] = []
        if signals["has_protective_warning"]:
            reasons.append(
                _STRUCTURAL_TOKEN_EXPLANATIONS["__protective_warning__"]
            )

        for idx in neg_indices:
            feat = str(feature_names[idx])
            if feat.startswith("word_tfidf__"):
                token = feat.replace("word_tfidf__", "")
                if not token.startswith("__") and len(safe_words) < top_k:
                    safe_words.append(f"'{token}'")

        if safe_words:
            reasons.append(
                f"Matches legitimate notification phrasing: {', '.join(safe_words)}"
            )
        reasons.append(
            "No high-risk credential harvesting, lottery fee, or account-suspension pattern dominated the message"
        )

    return reasons


def predict_with_bundle(
    bundle: dict[str, Any],
    text: object,
) -> PredictionResult:
    """Run local ML inference on a single message using a loaded model bundle."""
    validation = validate_message_input(text, max_length=MAX_MESSAGE_LENGTH)
    if not validation.is_valid:
        return PredictionResult(
            verdict=None,
            category=None,
            confidence=0.0,
            scam_probability=0.0,
            reasons=[validation.error_message or "Invalid message input."],
            warnings=validation.warnings,
            is_valid=False,
            model_version=str(bundle.get("model_version", MODEL_VERSION)),
        )

    cleaned_text = validation.cleaned_text
    normalized = normalize_text(cleaned_text, include_structural_tags=True)

    vectorizer = bundle["vectorizer"]
    binary_clf = bundle["binary_classifier"]
    category_clf = bundle["category_classifier"]
    threshold = float(bundle.get("decision_threshold", 0.50))

    X_vec = vectorizer.transform([normalized])
    scam_prob = float(binary_clf.predict_proba(X_vec)[0, 1])

    if scam_prob >= threshold:
        verdict = "SCAM"
        category = str(category_clf.predict(X_vec)[0])
        confidence = round(scam_prob * 100.0, 1)
    else:
        verdict = "SAFE"
        category = None
        confidence = round((1.0 - scam_prob) * 100.0, 1)

    ml_pred_cat = str(category_clf.predict(X_vec)[0])

    reasons = explain_ml_prediction(
        bundle=bundle,
        raw_text=cleaned_text,
        normalized_text=normalized,
        X_vec=X_vec,
        verdict=verdict,
        category=category,
    )

    warnings = list(validation.warnings)
    cal_disclosure = bundle.get("calibration_info", {}).get("disclosure")
    if cal_disclosure:
        warnings.append(str(cal_disclosure))

    return PredictionResult(
        verdict=verdict,
        category=category,
        confidence=confidence,
        scam_probability=scam_prob,
        reasons=reasons,
        warnings=warnings,
        is_valid=True,
        indicators=[],
        model_version=str(bundle.get("model_version", MODEL_VERSION)),
        ml_verdict=verdict,
        ml_scam_probability=scam_prob,
        ml_category=ml_pred_cat,
        rule_score=0.0,
        rule_risk_level="NONE",
        review_status="CLEAR",
        confidence_type="experimental_local_ml_score",
    )


def save_model_bundle(bundle: dict[str, Any], output_path: str | Path) -> Path:
    """Save the trained model bundle to a local .joblib file."""
    path = Path(output_path).resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(bundle, path, compress=3)
    return path


def load_model_bundle(model_path: str | Path) -> dict[str, Any]:
    """Load and validate a locally stored model bundle."""
    path = Path(model_path).resolve()
    if not path.exists():
        raise FileNotFoundError(
            f"Local model artifact not found at '{path}'. "
            "Please run 'python train.py' first to train and save the local model."
        )

    bundle = joblib.load(path)
    required_keys = {
        "vectorizer",
        "binary_classifier",
        "binary_linear_model",
        "category_classifier",
        "decision_threshold",
    }
    if not isinstance(bundle, dict) or not required_keys.issubset(bundle.keys()):
        raise ValueError(
            f"Model artifact at '{path}' is corrupted or missing required keys."
        )
    return bundle
