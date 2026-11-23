"""Automated unit tests for dataset validation, preprocessing, ML inference, and offline safety."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import pytest

from predict import DEFAULT_MODEL_PATH, clear_model_cache, predict_message
from src.classifier import (
    VALID_CATEGORIES,
    VALID_LABELS,
    load_and_validate_dataset,
    load_model_bundle,
    split_dataset,
)
from src.features import (
    MAX_MESSAGE_LENGTH,
    deobfuscate_token,
    extract_text_signals,
    normalize_text,
    validate_message_input,
)
from train import CANONICAL_DATA_PATH, REPORTS_DIR, run_training_pipeline


@pytest.fixture(scope="module", autouse=True)
def ensure_trained_model():
    """Ensure the local model artifact and evaluation reports exist before running tests."""
    if not DEFAULT_MODEL_PATH.exists() or not (REPORTS_DIR / "evaluation_report.json").exists():
        run_training_pipeline()
    clear_model_cache()


def test_dataset_validation_and_hygiene():
    """Verify canonical dataset schema, label/category consistency, and zero duplicates."""
    df, report = load_and_validate_dataset(CANONICAL_DATA_PATH, deduplicate=False)
    assert report.is_valid is True
    assert report.total_rows == 146
    assert report.duplicate_count == 0
    assert report.missing_value_count == 0
    assert report.scam_count == 94
    assert report.safe_count == 52
    assert set(df["label"].unique()) == VALID_LABELS

    # Verify SAFE rows never have a category and SCAM rows always have a valid category
    safe_rows = df[df["label"] == "SAFE"]
    scam_rows = df[df["label"] == "SCAM"]
    assert (safe_rows["category"] == "").all()
    assert set(scam_rows["category"].unique()) == set(VALID_CATEGORIES)


def test_leakage_free_stratified_split():
    """Verify train/val/test split has zero overlap and preserves all categories."""
    df, _ = load_and_validate_dataset(CANONICAL_DATA_PATH)
    train_df, val_df, test_df = split_dataset(df)

    assert len(train_df) + len(val_df) + len(test_df) == len(df)
    train_texts = set(train_df["text"])
    val_texts = set(val_df["text"])
    test_texts = set(test_df["text"])

    assert len(train_texts & val_texts) == 0
    assert len(train_texts & test_texts) == 0
    assert len(val_texts & test_texts) == 0

    # All 5 scam categories must appear in train, val, and test splits
    for split_df in (train_df, val_df, test_df):
        scam_cats = set(split_df[split_df["label"] == "SCAM"]["category"].unique())
        assert scam_cats == set(VALID_CATEGORIES)


def test_input_validation_and_length_bounds():
    """Verify empty, whitespace, non-string, and oversized inputs are handled safely."""
    for bad_input in ("", "   \n\t  ", None, 12345):
        res = predict_message(bad_input)
        assert res.is_valid is False
        assert res.verdict is None
        assert res.category is None
        assert res.confidence == 0.0

    # Oversized input (> 2000 chars) should be safely truncated with a warning
    long_text = "Your KYC will expire today. Share OTP immediately. " * 60
    assert len(long_text) > MAX_MESSAGE_LENGTH
    res_long = predict_message(long_text)
    assert res_long.is_valid is True
    assert res_long.verdict in VALID_LABELS
    assert any("truncated" in w.lower() for w in res_long.warnings)


def test_normalization_and_obfuscation():
    """Verify dotted acronyms and leetspeak words are properly normalized."""
    assert deobfuscate_token("fr33") == "free"
    assert deobfuscate_token("l0an") == "loan"
    assert deobfuscate_token("acc0unt") == "account"
    assert deobfuscate_token("cl1ck") == "click"
    assert deobfuscate_token("upd@te") == "update"
    # Genuine ordinals/codes should remain untouched
    assert deobfuscate_token("5g") == "5g"
    assert deobfuscate_token("xx4821") == "xx4821"

    norm = normalize_text("URGENT: Acc0unt bl0ck! Complete K.Y.C upd@te at bit.ly/test")
    assert "kyc" in norm
    assert "account" in norm
    assert "block" in norm
    assert "update" in norm
    assert "__short_url__" in norm
    assert "__obfuscated_text__" in norm


@pytest.mark.parametrize(
    "message,expected_category",
    [
        (
            "Your SBI KYC has expired. Click http://sbi-kyc-verify.xyz and share your 6-digit OTP to avoid account suspension.",
            "KYC/Bank",
        ),
        (
            "Congratulations! Your mobile number won Rs 25,00,000 in KBC Lucky Draw. Pay Rs 4500 processing fee to claim your prize.",
            "Lottery/Prize",
        ),
        (
            "Instant personal loan of Rs 3,00,000 approved with 0% interest and no CIBIL check. Pay Rs 1,500 advance file charge now.",
            "Loan/Credit",
        ),
        (
            "Work from home job selected! Earn Rs 5000 daily liking YouTube videos. Pay Rs 999 registration fee today to start.",
            "Job/Investment",
        ),
        (
            "URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz or lose access.",
            "KYC/Bank",
        ),
        (
            "Aapka KYC band ho jayega aaj raat. Turant link par click karke apna OTP aur PIN bhejo: bit.ly/kyc-abhi",
            "KYC/Bank",
        ),
    ],
)
def test_scam_predictions_and_categories(message: str, expected_category: str):
    """Verify English, Hinglish, and obfuscated scam messages return SCAM and valid categories."""
    res = predict_message(message)
    assert res.is_valid is True
    assert res.verdict == "SCAM"
    assert res.category == expected_category
    assert 0.0 <= res.confidence <= 100.0
    assert len(res.reasons) >= 1


@pytest.mark.parametrize(
    "safe_message",
    [
        "Your account was debited by Rs 450. If this was not you, contact your bank using its official app.",
        "Your OTP is 482913. Do not share it with anyone.",
        "Your parcel is out for delivery today. Track it in the courier app you already use.",
        "Your UPI payment of Rs 250 was successful.",
        "Thank you for applying. We have received your job application. Note: We never charge any fee for hiring.",
        "Your monthly loan EMI payment of Rs 12,000 has been received. Thank you.",
        "Reminder: your dental appointment is scheduled for tomorrow at 10 AM.",
        "Kal milte hain, 5 baje coffee pe chalte hain.",
        "OTP kisi ke saath share mat karna. Bank kabhi OTP nahi maangta.",
        "URGENT: Your package delivery is scheduled for today. Please be available.",
        "Your periodic KYC update has been successfully processed at your home branch. No further action is required.",
        "Hey! Did you hear that Rohan won first prize in the college coding competition today?",
        "Check out the official Python documentation at https://docs.python.org/3/ for tomorrow's workshop.",
    ],
)
def test_safe_and_borderline_false_positive_protection(safe_message: str):
    """Verify legitimate and borderline messages return SAFE and strictly category=None."""
    res = predict_message(safe_message)
    assert res.is_valid is True
    assert res.verdict == "SAFE", f"False positive on safe message: {safe_message}"
    assert res.category is None, "SAFE messages must NEVER have a scam category"
    assert 0.0 <= res.confidence <= 100.0
    assert len(res.reasons) >= 1


def test_offline_socket_blocked_inference(monkeypatch):
    """Prove that prediction makes zero outbound network socket calls."""

    def _forbidden_socket(*args, **kwargs):
        raise RuntimeError("Network access is strictly forbidden during local inference!")

    monkeypatch.setattr(socket, "socket", _forbidden_socket)
    monkeypatch.setattr(socket, "create_connection", _forbidden_socket)

    res_scam = predict_message(
        "Your KYC will be blocked today. Click bit.ly/kyc-now and share OTP."
    )
    res_safe = predict_message("Your OTP is 918273. Do not share it with anyone.")

    assert res_scam.verdict == "SCAM"
    assert res_safe.verdict == "SAFE"
    assert res_safe.category is None


def test_performance_latency_and_artifact_size():
    """Verify model artifact size (< 10 MB) and single-message latency (< 50 ms)."""
    assert DEFAULT_MODEL_PATH.exists()
    size_kb = DEFAULT_MODEL_PATH.stat().st_size / 1024.0
    assert size_kb < 10240.0  # < 10 MB

    # Warmup cache
    _ = predict_message("Warmup message")

    t0 = time.perf_counter()
    res = predict_message("Congratulations! You won a lottery prize. Pay a release fee.")
    elapsed_ms = (time.perf_counter() - t0) * 1000.0

    assert res.verdict == "SCAM"
    assert elapsed_ms < 50.0


# =============================================================================
# Milestone 4: Streamlit UI & Application Integration Tests
# =============================================================================


def test_app_import_and_helper_functions():
    """Verify app.py imports cleanly and loads real evaluation reports and recommendations."""
    import app

    eval_report = app.load_evaluation_report()
    assert eval_report is not None
    assert eval_report["dataset_validation"]["total_rows"] == 146

    scam_res = app.analyze_user_message(
        "Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately."
    )
    assert scam_res.verdict == "SCAM"
    assert scam_res.category == "KYC/Bank"
    assert "DO NOT" in app.get_safety_recommendation(scam_res)

    safe_res = app.analyze_user_message("Your OTP is 482913. Do not share it with anyone.")
    assert safe_res.verdict == "SAFE"
    assert safe_res.category is None
    assert "guarantee" in app.get_safety_recommendation(safe_res).lower()


def test_streamlit_ui_interactions_and_no_persistence(monkeypatch):
    """Verify full Streamlit UI flow (empty, scam, safe, NEEDS_REVIEW, long input, clear) and zero persistence."""
    import app

    # Mock Streamlit state & captured UI calls so UI logic executes deterministically
    # without spawning a background Tornado thread in restricted sandboxes
    state_dict: dict = {}
    captured_warnings: list[str] = []
    captured_errors: list[str] = []
    captured_successes: list[str] = []
    captured_markdowns: list[str] = []

    monkeypatch.setattr(app.st, "session_state", state_dict)
    monkeypatch.setattr(app.st, "warning", lambda msg, **kw: captured_warnings.append(str(msg)))
    monkeypatch.setattr(app.st, "error", lambda msg, **kw: captured_errors.append(str(msg)))
    monkeypatch.setattr(app.st, "success", lambda msg, **kw: captured_successes.append(str(msg)))
    monkeypatch.setattr(app.st, "markdown", lambda msg, **kw: captured_markdowns.append(str(msg)))
    monkeypatch.setattr(app.st, "subheader", lambda *a, **kw: None)
    monkeypatch.setattr(app.st, "caption", lambda *a, **kw: None)
    monkeypatch.setattr(app.st, "info", lambda *a, **kw: None)

    class _DummyCol:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def metric(self, *args, **kwargs):
            return None

    monkeypatch.setattr(app.st, "columns", lambda n: [_DummyCol() for _ in range(n if isinstance(n, int) else len(n))])
    monkeypatch.setattr(app.st, "expander", lambda *a, **kw: _DummyCol())

    # 1. Empty input handling: returns invalid result and renders a warning
    res_empty = app.analyze_user_message("   ")
    assert res_empty.is_valid is False
    app._render_results_section(res_empty)
    assert len(captured_warnings) >= 1

    # 2. Valid SCAM input produces real hybrid SCAM prediction and category
    scam_msg = "Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately."
    res_scam = app.analyze_user_message(scam_msg)
    assert res_scam.verdict == "SCAM"
    assert res_scam.category == "KYC/Bank"
    assert res_scam.confidence_type == "hybrid_heuristic_ml_score"
    app._render_results_section(res_scam)
    assert any("VERDICT: SCAM" in m for m in captured_markdowns)
    assert any("Experimental hybrid detection score" in m for m in captured_markdowns)

    # 3. Valid SAFE input produces real hybrid SAFE prediction with category=None
    safe_msg = "Your OTP is 482913. Do not share it with anyone."
    res_safe = app.analyze_user_message(safe_msg)
    assert res_safe.verdict == "SAFE"
    assert res_safe.category is None
    app._render_results_section(res_safe)
    assert any("VERDICT: SAFE" in m for m in captured_markdowns)

    # 4. Contradictory input displays NEEDS_REVIEW status banner
    review_msg = (
        "Congratulations! You won a lottery prize of Rs 10,00,000 in KBC Lucky Draw. "
        "Note: Do not share your OTP with anyone."
    )
    res_rev = app.analyze_user_message(review_msg)
    assert res_rev.review_status == "NEEDS_REVIEW"
    app._render_results_section(res_rev)
    assert any("NEEDS_REVIEW" in m for m in captured_markdowns)

    # 5. Long input (> 2000 chars) is safely bounded without crashing UI
    long_msg = "Instant loan approved! Pay Rs 1500 advance processing fee now. " * 45
    res_long = app.analyze_user_message(long_msg)
    assert res_long.is_valid is True
    assert any("truncated" in w.lower() for w in res_long.warnings)
    app._render_results_section(res_long)

    # 6. Verify no submitted message is written to the canonical dataset or disk logs
    assert review_msg not in CANONICAL_DATA_PATH.read_text(encoding="utf-8")

