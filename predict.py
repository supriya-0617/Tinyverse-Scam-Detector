"""Local inference and hybrid decision engine entrypoint for Tinyverse Scam Detector.

This module implements the Milestone 3 Hybrid Decision Engine combining:
1. Stage-1 & Stage-2 Local ML Classifier predictions (`src/classifier.py`).
2. Modular Explainable Rule Engine & Safe-Message Protections (`src/rules.py`).

Hybrid Decision & Confidence Specification:
- Preserves the raw ML prediction (`ml_verdict`, `ml_scam_probability`, `ml_category`).
- Evaluates positive suspicious rules and negative protective safe rules via `evaluate_rules()`.
- Uses bounded non-additive log-odds/probability fusion rather than blindly summing rule weights:
  * Case A (Strong Suspicious Rule Evidence, no safe contradiction):
    Combined scam score increases smoothly toward 1.0 using noisy-OR fusion:
    `hybrid_prob = 1.0 - (1.0 - ml_prob) * (1.0 - 0.65 * susp_score)`
  * Case B (Safe-Message Protection Dampener, zero suspicious rules fired):
    When a verified safe pattern (e.g., standard bank debit receipt with 'Avl Bal',
    'UPI Ref', OTP 'do not share' advisory, or delivery update) matches and zero
    suspicious rules fire, the ML false-positive probability is dampened:
    `hybrid_prob = ml_prob * (1.0 - 0.65 * safe_score)`
  * Case C (Contradictory / Ambiguous Evidence):
    When both suspicious and safe rules fire, or when `0.40 <= hybrid_prob <= 0.60`,
    `review_status` is set to `'NEEDS_REVIEW'` with an explicit caution warning.
- Decision threshold: `hybrid_prob >= 0.50` -> `'SCAM'`, else `'SAFE'`.
- Category rule: When verdict is `'SAFE'`, `category` is strictly `None`.
- Confidence reliability disclosure: Because hybrid scores combine statistical ML
  with heuristic rule evidence on a synthetic dataset, `confidence_type` is
  explicitly labeled `'hybrid_heuristic_ml_score'` (not a calibrated real-world probability).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

from src.classifier import (
    VALID_CATEGORIES,
    PredictionResult,
    load_model_bundle,
    predict_with_bundle,
)
from src.rules import RuleEvaluationResult, evaluate_rules

PROJECT_ROOT = Path(__file__).resolve().parent
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "scam_detector.joblib"

# Explicit hybrid decision thresholds
HYBRID_DECISION_THRESHOLD: float = 0.50
REVIEW_LOWER_BOUND: float = 0.40
REVIEW_UPPER_BOUND: float = 0.60

# In-memory cache so repeated calls do not re-read disk
_MODEL_CACHE: dict[str, dict[str, Any]] = {}


def get_cached_model_bundle(model_path: Optional[str | Path] = None) -> dict[str, Any]:
    """Load the local model bundle once and cache it in process memory."""
    resolved = str(Path(model_path or DEFAULT_MODEL_PATH).resolve())
    if resolved not in _MODEL_CACHE:
        _MODEL_CACHE[resolved] = load_model_bundle(resolved)
    return _MODEL_CACHE[resolved]


def clear_model_cache() -> None:
    """Clear the in-memory model bundle cache (useful in tests)."""
    _MODEL_CACHE.clear()


def combine_ml_and_rules(
    ml_result: PredictionResult,
    rule_result: RuleEvaluationResult,
    decision_threshold: float = HYBRID_DECISION_THRESHOLD,
) -> PredictionResult:
    """Combine local ML prediction with explainable rule-engine evidence.

    Preserves all raw ML fields on the returned PredictionResult while computing
    the final hybrid verdict, category, confidence score, review_status, and
    merged explanations.
    """
    if not ml_result.is_valid:
        return ml_result

    ml_prob = float(ml_result.scam_probability)
    susp_score = float(rule_result.suspicious_score)
    safe_score = float(rule_result.safe_protection_score)

    # 1. Bounded Hybrid Score Calculation (non-additive noisy-OR / dampening)
    if susp_score > 0.0 and safe_score == 0.0:
        # Suspicious rules fired with no safe dampeners -> boost scam score bounded in [0, 1]
        boost_factor = 0.75 if rule_result.risk_level == "CRITICAL" else 0.60
        hybrid_prob = 1.0 - (1.0 - ml_prob) * (1.0 - boost_factor * susp_score)
    elif safe_score > 0.0 and susp_score == 0.0:
        # Legitimate-message protection rule fired and zero suspicious indicators exist
        # Dampen false-positive ML spikes on genuine bank/OTP/UPI/delivery messages
        hybrid_prob = ml_prob * (1.0 - 0.70 * safe_score)
    elif susp_score > 0.0 and safe_score > 0.0:
        # Contradictory evidence: both suspicious and safe patterns matched
        # Weight slightly toward safety if explicit protective negation ("do not share") is present,
        # unless a critical upfront fee or lottery/impersonation rule also fired.
        net_shift = 0.45 * (susp_score - safe_score)
        hybrid_prob = min(0.99, max(0.01, ml_prob + net_shift))
    else:
        # Neither suspicious nor safe rules fired -> rely on local ML baseline probability
        hybrid_prob = ml_prob

    hybrid_prob = min(0.999, max(0.001, float(hybrid_prob)))

    # 2. Final Binary Verdict Determination
    if hybrid_prob >= decision_threshold:
        final_verdict = "SCAM"
        final_confidence = round(hybrid_prob * 100.0, 1)
    else:
        final_verdict = "SAFE"
        final_confidence = round((1.0 - hybrid_prob) * 100.0, 1)

    # 3. Category Determination (Strictly None when SAFE)
    if final_verdict == "SAFE":
        final_category = None
    else:
        # Prefer specific rule category hint when a high/critical domain rule fired,
        # otherwise use the trained Stage-2 Category Classifier prediction
        if (
            rule_result.suggested_category in VALID_CATEGORIES
            and susp_score >= 0.45
        ):
            final_category = rule_result.suggested_category
        elif ml_result.ml_category in VALID_CATEGORIES:
            final_category = ml_result.ml_category
        elif rule_result.suggested_category in VALID_CATEGORIES:
            final_category = rule_result.suggested_category
        else:
            final_category = "Other"

    # 4. Ambiguity / Contradiction Review Status
    ml_disagrees_with_final = ml_result.ml_verdict != final_verdict
    in_uncertain_band = REVIEW_LOWER_BOUND <= hybrid_prob <= REVIEW_UPPER_BOUND
    if (
        rule_result.has_contradictory_evidence
        or in_uncertain_band
        or (ml_disagrees_with_final and susp_score < 0.55 and safe_score < 0.45)
    ):
        review_status = "NEEDS_REVIEW"
    else:
        review_status = "CLEAR"

    # 5. Merge Human-Readable Explanations (Rule Evidence First, then ML Signals)
    merged_reasons: list[str] = []
    if final_verdict == "SCAM":
        for r in rule_result.suspicious_rules:
            merged_reasons.append(
                f"{r.description} (Indicator: '{r.matched_evidence}')"
            )
    else:
        for r in rule_result.safe_rules:
            merged_reasons.append(
                f"{r.description} (Verified pattern: '{r.matched_evidence}')"
            )

    for ml_reason in ml_result.reasons:
        if ml_reason not in merged_reasons:
            merged_reasons.append(ml_reason)

    if not merged_reasons:
        merged_reasons.append("Evaluated by local hybrid ML and rule engine.")

    # 6. Warnings & Honest Confidence Reliability Disclosure
    warnings = list(ml_result.warnings)
    if review_status == "NEEDS_REVIEW":
        warnings.append(
            "Ambiguous or mixed signals detected (review_status=NEEDS_REVIEW). "
            "Please verify the sender independently through official channels."
        )
    hybrid_disclosure = (
        "Hybrid confidence combines local ML probability with heuristic rule evidence "
        "(confidence_type=hybrid_heuristic_ml_score); it is a decision-support score, "
        "not a calibrated real-world probability."
    )
    if hybrid_disclosure not in warnings:
        warnings.append(hybrid_disclosure)

    indicators_list = [r.to_dict() for r in rule_result.all_matches]

    return PredictionResult(
        verdict=final_verdict,
        category=final_category,
        confidence=final_confidence,
        scam_probability=hybrid_prob,
        reasons=merged_reasons,
        warnings=warnings,
        is_valid=True,
        indicators=indicators_list,
        model_version="1.1.0-m3-hybrid",
        ml_verdict=ml_result.ml_verdict or ml_result.verdict,
        ml_scam_probability=ml_result.ml_scam_probability
        if ml_result.ml_scam_probability is not None
        else ml_result.scam_probability,
        ml_category=ml_result.ml_category,
        rule_score=rule_result.net_rule_score,
        rule_risk_level=rule_result.risk_level,
        review_status=review_status,
        confidence_type="hybrid_heuristic_ml_score",
    )


def predict_message(
    text: object,
    model_path: Optional[str | Path] = None,
    use_rules: bool = True,
) -> PredictionResult:
    """Classify a single SMS or WhatsApp message completely locally.

    Args:
        text: Raw message string to analyze.
        model_path: Optional custom path to local .joblib model artifact.
        use_rules: If True (default), combines local ML with the explainable
            rule engine. If False, returns the pure Milestone 2 ML baseline.

    Returns:
        PredictionResult containing verdict ('SCAM' or 'SAFE'), category (or None),
        confidence percentage (0-100), preserved ML score, rule indicators,
        review_status, human-readable reasons, and warnings.
    """
    bundle = get_cached_model_bundle(model_path)
    ml_res = predict_with_bundle(bundle, text)
    if not ml_res.is_valid or not use_rules:
        return ml_res

    rule_res = evaluate_rules(text)
    threshold = float(bundle.get("decision_threshold", HYBRID_DECISION_THRESHOLD))
    return combine_ml_and_rules(
        ml_result=ml_res,
        rule_result=rule_res,
        decision_threshold=threshold,
    )


def main() -> None:
    if len(sys.argv) > 1:
        raw_message = " ".join(sys.argv[1:])
        result = predict_message(raw_message)
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
        return

    # Demo showcase across Scam, Safe, Hinglish, Obfuscated, and Borderline messages
    demo_messages = [
        "Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately.",
        "Aapne lottery jeeti hai 25 lakh rupaye ki! Prize lene ke liye pehle Rs 5000 processing fee bhejo.",
        "URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz",
        "Your OTP is 482913. Do not share it with anyone.",
        "Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank (UPI Ref 632819402112). Avl Bal: Rs. 18,430.50.",
        "Kal milte hain, 5 baje coffee pe chalte hain.",
    ]

    print("=" * 72)
    print("TINYVERSE LOCAL HYBRID PREDICTION DEMO (100% OFFLINE INFERENCE)")
    print("=" * 72)
    for idx, msg in enumerate(demo_messages, start=1):
        res = predict_message(msg)
        print(f"\n[{idx}] Message:      {msg}")
        print(f"    Verdict:      {res.verdict} (Review Status: {res.review_status})")
        print(f"    Category:     {res.category}")
        print(f"    Confidence:   {res.confidence:.1f}% ({res.confidence_type})")
        print(f"    ML Prob:      {res.ml_scam_probability:.3f} | Hybrid Prob: {res.scam_probability:.3f} | Net Rule Score: {res.rule_score:+.3f}")
        print(f"    Rules Fired:  {[ind['rule_id'] for ind in res.indicators]}")
        print(f"    Top Reason:   {res.reasons[0] if res.reasons else 'N/A'}")


if __name__ == "__main__":
    main()
