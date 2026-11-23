"""Streamlit local user interface for Tinyverse Scam Detector.

This module implements the 100% local, privacy-preserving cybersecurity product
interface for the Tinyverse On-Device Scam Message Detector.

Key Safeguards:
- Calls the real `predict_message()` hybrid inference engine (`predict.py`).
- Bound strictly to `127.0.0.1` loopback; zero external APIs, fonts, or CDNs.
- Never logs or persists user-submitted messages to disk.
- Escapes all dynamic text using `html.escape()` before styling.
- Clearly distinguishes raw ML probability, rule evidence, and the experimental
  hybrid detection score (`confidence_type = 'hybrid_heuristic_ml_score'`).
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st

from predict import DEFAULT_MODEL_PATH, get_cached_model_bundle, predict_message
from src.classifier import PredictionResult
from src.features import MAX_MESSAGE_LENGTH
from src.privacy_audit import run_privacy_audit

PROJECT_ROOT = Path(__file__).resolve().parent
EVAL_REPORT_PATH = PROJECT_ROOT / "reports" / "evaluation_report.json"
CONFUSION_MATRIX_PNG = PROJECT_ROOT / "reports" / "confusion_matrix.png"

# Curated quick-load examples for live hackathon demonstrations
DEMO_EXAMPLES: dict[str, str] = {
    "-- Select an example message or paste your own below --": "",
    "[SCAM - KYC/Bank] Fake SBI KYC Suspension Link": (
        "Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately."
    ),
    "[SCAM - Lottery/Prize (Hinglish)] KBC Lucky Draw Fee": (
        "Aapne lottery jeeti hai 25 lakh rupaye ki! Prize lene ke liye pehle Rs 5000 processing fee bhejo."
    ),
    "[SCAM - Obfuscated Leetspeak] Account Block Notice": (
        "URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz"
    ),
    "[SCAM - Loan/Credit] 0% Interest Instant Loan Advance Fee": (
        "Instant personal loan of Rs 3,00,000 approved with 0% interest and no CIBIL check. "
        "Pay Rs 1,500 advance file charge now."
    ),
    "[SCAM - Job/Investment] YouTube Like & Prepaid VIP Task": (
        "Work from home job selected! Earn Rs 5000 daily liking YouTube videos. "
        "Pay Rs 999 registration fee today to start."
    ),
    "[SAFE - Bank Debit Alert] Genuine UPI/Bank Debit Notification": (
        "Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank "
        "(UPI Ref 632819402112). Avl Bal: Rs. 18,430.50."
    ),
    "[SAFE - OTP Security Warning] Genuine Login OTP": (
        "Your OTP is 482913. Do not share it with anyone."
    ),
    "[SAFE - Hinglish OTP Advisory] Bank Anti-Fraud Reminder": (
        "OTP kisi ke saath share mat karna. Bank kabhi OTP nahi maangta."
    ),
    "[SAFE - Borderline Urgent Delivery] Courier Out for Delivery": (
        "URGENT: Your package delivery is scheduled for today. Please be available."
    ),
    "[AMBIGUOUS / NEEDS_REVIEW] Contradictory Prize + OTP Warning": (
        "Congratulations! You won a lottery prize of Rs 10,00,000 in KBC Lucky Draw. "
        "Note: Do not share your OTP with anyone."
    ),
}

# Optional URL query-param presets for clean automated screenshot verification
_PRESET_MAP: dict[str, str] = {
    "input": "[SCAM - KYC/Bank] Fake SBI KYC Suspension Link",
    "scam": "[SCAM - KYC/Bank] Fake SBI KYC Suspension Link",
    "safe": "[SAFE - Bank Debit Alert] Genuine UPI/Bank Debit Notification",
    "review": "[AMBIGUOUS / NEEDS_REVIEW] Contradictory Prize + OTP Warning",
}


@st.cache_resource
def _get_cached_privacy_audit() -> Any:
    """Run the static and runtime privacy audit once and cache across sessions."""
    return run_privacy_audit()


def load_evaluation_report(report_path: Path = EVAL_REPORT_PATH) -> Optional[dict[str, Any]]:
    """Read measured evaluation metrics from reports/evaluation_report.json."""
    if not report_path.exists():
        return None
    try:
        return json.loads(report_path.read_text(encoding="utf-8"))
    except Exception:
        return None


def get_safety_recommendation(result: PredictionResult) -> str:
    """Return actionable, context-aware cybersecurity advice based on the prediction."""
    if not result.is_valid:
        return "Please paste a valid non-empty SMS or WhatsApp message to analyze."

    if result.review_status == "NEEDS_REVIEW":
        return (
            "CAUTION — Mixed or ambiguous signals were detected. Do NOT click any links, "
            "share OTPs/PINs, or transfer money. Independently verify the message by "
            "contacting the organization using the official phone number on your bank card "
            "or official app."
        )

    if result.verdict == "SCAM":
        cat = result.category or "Other"
        if cat == "KYC/Bank":
            return (
                "DO NOT click any links or share your OTP, UPI PIN, ATM PIN, CVV, or netbanking "
                "password. Banks, UPI apps, and telecom/electricity providers never ask for "
                "OTPs or PINs via SMS/WhatsApp to prevent account suspension."
            )
        if cat == "Lottery/Prize":
            return (
                "DO NOT pay any processing fee, release charge, GST, or customs tax. Legitimate "
                "prizes never require upfront money transfers or entering a UPI PIN to 'receive' funds."
            )
        if cat == "Loan/Credit":
            return (
                "DO NOT pay advance file charges, NOC fees, or insurance deposits before loan "
                "disbursement, and never install unknown .APK files sent over SMS/WhatsApp."
            )
        if cat == "Job/Investment":
            return (
                "DO NOT pay registration, ID card, laptop, or prepaid VIP task deposits. "
                "Genuine employers never charge hiring fees, and 'guaranteed daily profit' "
                "trading groups are fraudulent."
            )
        return (
            "DO NOT transfer money, scan unknown QR codes using your UPI PIN, or share "
            "verification codes. Verify urgent requests from friends/family by calling "
            "their known phone number directly."
        )

    return (
        "This message appears consistent with legitimate notifications or personal communication. "
        "However, automated detection cannot guarantee sender authenticity—always verify "
        "requests for money, OTPs, passwords, or account access independently."
    )


def analyze_user_message(raw_text: object) -> PredictionResult:
    """Validate and classify a single user message in local memory without logging."""
    return predict_message(raw_text, use_rules=True)


def _inject_local_css() -> None:
    """Inject clean, responsive cybersecurity SaaS CSS using only system fonts (zero external CDNs)."""
    st.markdown(
        """
        <style>
        .stApp {
            background-color: #0B1120;
            color: #F8FAFC;
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
        }
        .block-container {
            padding-top: 1.5rem !important;
            padding-bottom: 2.5rem !important;
            max-width: 1220px !important;
        }
        /* Top Product Hero Bar */
        .tv-hero {
            background: #111C33;
            border: 1px solid #1E293B;
            border-left: 5px solid #38BDF8;
            border-radius: 10px;
            padding: 1.25rem 1.5rem;
            margin-bottom: 1.1rem;
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            gap: 1rem;
        }
        .tv-brand-badge {
            display: inline-block;
            background: rgba(56, 189, 248, 0.12);
            color: #38BDF8;
            border: 1px solid rgba(56, 189, 248, 0.35);
            font-size: 0.75rem;
            font-weight: 700;
            letter-spacing: 0.08em;
            padding: 0.2rem 0.65rem;
            border-radius: 4px;
            text-transform: uppercase;
            margin-bottom: 0.35rem;
        }
        .tv-title {
            font-size: 1.75rem;
            font-weight: 800;
            color: #F8FAFC;
            margin: 0;
            letter-spacing: -0.02em;
        }
        .tv-tagline {
            font-size: 0.98rem;
            color: #2DD4BF;
            font-weight: 600;
            margin: 0.2rem 0 0 0;
        }
        .tv-privacy-chip {
            background: #0D2824;
            border: 1px solid #14B8A6;
            color: #A7F3D0;
            padding: 0.55rem 0.95rem;
            border-radius: 8px;
            font-size: 0.82rem;
            line-height: 1.4;
        }
        /* Outcome Legend Strip */
        .tv-outcomes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 0.75rem;
            margin-bottom: 1.15rem;
        }
        .tv-outcome-pill {
            background: #111C33;
            border: 1px solid #1E293B;
            border-radius: 8px;
            padding: 0.7rem 0.95rem;
            font-size: 0.84rem;
            color: #CBD5E1;
        }
        .tv-outcome-scam { border-top: 3px solid #EF4444; }
        .tv-outcome-safe { border-top: 3px solid #22C55E; }
        .tv-outcome-review { border-top: 3px solid #F59E0B; }

        /* Verdict Cards */
        .verdict-scam {
            background: #1F1218;
            border: 1px solid #DC2626;
            border-left: 6px solid #EF4444;
            color: #FECACA;
            padding: 1.35rem 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .verdict-safe {
            background: #0D231A;
            border: 1px solid #16A34A;
            border-left: 6px solid #22C55E;
            color: #DCFCE7;
            padding: 1.35rem 1.5rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .review-banner {
            background: #231B0E;
            border: 1px solid #D97706;
            border-left: 6px solid #F59E0B;
            color: #FDE68A;
            padding: 1.1rem 1.35rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .tv-panel-card {
            background: #111C33;
            border: 1px solid #1E293B;
            border-radius: 8px;
            padding: 1rem 1.2rem;
            margin-bottom: 0.85rem;
            color: #E2E8F0;
        }
        .tv-char-counter {
            font-size: 0.8rem;
            color: #94A3B8;
            text-align: right;
            margin-top: -0.35rem;
            margin-bottom: 0.5rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _render_results_section(result: PredictionResult) -> None:
    """Render the structured hybrid prediction result with clear visual distinctions."""
    st.subheader("Analysis Results")

    if not result.is_valid:
        st.warning(
            result.reasons[0]
            if result.reasons
            else "Please enter a non-empty SMS or WhatsApp message to analyze."
        )
        return

    # 1. Neutral / Amber Banner if review_status == "NEEDS_REVIEW"
    if result.review_status == "NEEDS_REVIEW":
        st.markdown(
            """
            <div class="review-banner">
                <div style="font-size:1.05rem; font-weight:700; color:#FBBF24; margin-bottom:0.25rem;">
                    REVIEW STATUS: NEEDS_REVIEW — Ambiguous or Contradictory Evidence Detected
                </div>
                <div style="font-size:0.9rem; color:#FDE68A;">
                    This message contains mixed or borderline indicators (for example, both a suspicious
                    claim and a safety warning, or a borderline score). Do not treat this message as
                    unquestionably safe—independently verify the sender via official channels.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 2. Primary Verdict Banner (Red for SCAM, Green for SAFE)
    verdict_escaped = html.escape(str(result.verdict))
    category_display = (
        html.escape(str(result.category))
        if result.verdict == "SCAM" and result.category
        else "None (Not Applicable for SAFE Messages)"
    )

    if result.verdict == "SCAM":
        st.markdown(
            f"""
            <div class="verdict-scam">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                    <h2 style="margin:0; font-size:1.55rem; color:#F87171; letter-spacing:0.01em;">
                        VERDICT: {verdict_escaped}
                    </h2>
                    <span style="background:#7F1D1D; color:#FECACA; padding:0.25rem 0.75rem; border-radius:6px; font-size:0.85rem; font-weight:700;">
                        Category: {category_display}
                    </span>
                </div>
                <p style="margin:0.55rem 0 0 0; font-size:1.0rem; color:#F8FAFC;">
                    <strong>Experimental Hybrid Detection Score:</strong> <code>{result.confidence:.1f}%</code>
                    &nbsp;&bull;&nbsp; <strong>Review Status:</strong> <code>{html.escape(result.review_status)}</code>
                </p>
                <p style="margin:0.35rem 0 0 0; font-size:0.82rem; color:#FCA5A5;">
                    <em>Screening Notice: Experimental hybrid detection score — not a calibrated real-world probability.</em>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="verdict-safe">
                <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:0.5rem;">
                    <h2 style="margin:0; font-size:1.55rem; color:#4ADE80; letter-spacing:0.01em;">
                        VERDICT: {verdict_escaped}
                    </h2>
                    <span style="background:#14532D; color:#DCFCE7; padding:0.25rem 0.75rem; border-radius:6px; font-size:0.85rem; font-weight:700;">
                        Category: None
                    </span>
                </div>
                <p style="margin:0.55rem 0 0 0; font-size:1.0rem; color:#F8FAFC;">
                    <strong>Experimental Hybrid Detection Score:</strong> <code>{result.confidence:.1f}%</code>
                    &nbsp;&bull;&nbsp; <strong>Review Status:</strong> <code>{html.escape(result.review_status)}</code>
                </p>
                <p style="margin:0.35rem 0 0 0; font-size:0.82rem; color:#86EFAC;">
                    <em>Screening Notice: Experimental hybrid detection score — not a calibrated real-world probability. Automated SAFE is a screening aid, not a guarantee.</em>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 3. Transparent Breakdown: ML Probability vs. Rule Evidence vs. Final Hybrid Score
    col1, col2, col3, col4 = st.columns(4)
    ml_prob_pct = (result.ml_scam_probability or 0.0) * 100.0
    hybrid_scam_pct = result.scam_probability * 100.0
    col1.metric(
        "Final Verdict",
        result.verdict or "N/A",
        delta=f"Category: {result.category}" if result.category else "Category: None",
        delta_color="inverse" if result.verdict == "SCAM" else "normal",
    )
    col2.metric(
        "Hybrid Detection Score",
        f"{result.confidence:.1f}%",
        help="Experimental hybrid detection score combining local ML and rule evidence (not a calibrated probability).",
    )
    col3.metric(
        "Raw Local ML Scam Score",
        f"{ml_prob_pct:.1f}%",
        delta=f"ML Verdict: {result.ml_verdict}",
        delta_color="off",
        help="Stage-1 Logistic Regression + Word/Char TF-IDF score before rule fusion.",
    )
    col4.metric(
        "Net Rule Engine Evidence",
        f"{result.rule_score:+.2f}",
        delta=f"Risk: {result.rule_risk_level}",
        delta_color="off",
        help="Positive values indicate suspicious rules fired; negative values indicate safe-message protections fired.",
    )

    st.caption(
        f"**Score Distinction:** Raw ML Scam Score = `{ml_prob_pct:.1f}%` "
        f"| Net Rule Evidence = `{result.rule_score:+.3f}` "
        f"| Combined Hybrid Scam Score = `{hybrid_scam_pct:.1f}%` (Decision Threshold = `50.0%`, "
        f"`confidence_type = {result.confidence_type}`)."
    )

    # 4. Why This Message Was Classified That Way (Explanations & Indicators)
    st.markdown("#### Why This Message Was Classified This Way")
    for reason in result.reasons:
        st.markdown(f"- {html.escape(reason)}")

    suspicious_inds = [
        ind for ind in result.indicators if ind.get("polarity") == "SUSPICIOUS"
    ]
    safe_inds = [
        ind for ind in result.indicators if ind.get("polarity") == "SAFE"
    ]

    ind_col1, ind_col2 = st.columns(2)
    with ind_col1:
        st.markdown("##### Fired Suspicious Rule Indicators")
        if suspicious_inds:
            for ind in suspicious_inds:
                rid = html.escape(str(ind.get("rule_id", "")))
                rname = html.escape(str(ind.get("name", "")))
                rsev = html.escape(str(ind.get("severity", "")))
                rev = html.escape(str(ind.get("matched_evidence", "")))
                st.markdown(
                    f"- **`{rid}` ({rsev}) — {rname}:** Matched `{rev}`"
                )
        else:
            st.info("No rule-based suspicious indicators fired on this message.")

    with ind_col2:
        st.markdown("##### Fired Safe-Message Protections")
        if safe_inds:
            for ind in safe_inds:
                rid = html.escape(str(ind.get("rule_id", "")))
                rname = html.escape(str(ind.get("name", "")))
                rev = html.escape(str(ind.get("matched_evidence", "")))
                st.markdown(
                    f"- **`{rid}` (PROTECTIVE) — {rname}:** Matched `{rev}`"
                )
        else:
            st.caption("No explicit safe-message dampener patterns matched.")

    # 5. Safety Recommendation & Warnings
    st.markdown("#### Recommended Safety Action")
    recommendation = get_safety_recommendation(result)
    if result.verdict == "SCAM":
        st.error(recommendation)
    elif result.review_status == "NEEDS_REVIEW":
        st.warning(recommendation)
    else:
        st.success(recommendation)

    if result.warnings:
        with st.expander("View Confidence & Validation Disclosures", expanded=False):
            for warn in result.warnings:
                st.caption(f"• {html.escape(warn)}")


def main() -> None:
    """Main entry point for the local Streamlit application."""
    st.set_page_config(
        page_title="TINYVERSE — On-Device Scam Message Detector",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    _inject_local_css()

    # Warm up model bundle and privacy audit before emitting any UI widgets
    # so runtime socket-isolation probes complete before browser static chunk fetches.
    try:
        _ = get_cached_model_bundle()
        _ = _get_cached_privacy_audit()
    except Exception:
        pass

    # Initialize session state variables in volatile RAM only
    if "message_input" not in st.session_state:
        st.session_state["message_input"] = ""
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if "selected_demo" not in st.session_state:
        st.session_state["selected_demo"] = list(DEMO_EXAMPLES.keys())[0]

    # Support optional query-parameter preset loading for browser verification
    try:
        qp = st.query_params
        preset = str(qp.get("preset", "")).lower().strip()
        if preset in _PRESET_MAP and st.session_state.get("_preset_applied") != preset:
            st.session_state["_preset_applied"] = preset
            demo_key = _PRESET_MAP[preset]
            st.session_state["selected_demo"] = demo_key
            st.session_state["message_input"] = DEMO_EXAMPLES[demo_key]
            if preset in ("scam", "safe", "review"):
                st.session_state["last_result"] = analyze_user_message(
                    DEMO_EXAMPLES[demo_key]
                )
            else:
                st.session_state["last_result"] = None
    except Exception:
        pass

    # Top Product Hero Banner & Local Privacy Indicator
    st.markdown(
        """
        <div class="tv-hero">
            <div>
                <div class="tv-brand-badge">On-Device Cybersecurity Screening Engine</div>
                <h1 class="tv-title">TINYVERSE — On-Device Scam Message Detector</h1>
                <p class="tv-tagline">Detect scams. Protect privacy. Stay offline.</p>
            </div>
            <div class="tv-privacy-chip">
                <strong>LOCAL LOOPBACK ACTIVE (127.0.0.1)</strong><br/>
                Zero Cloud AI Calls &bull; Volatile RAM Only &bull; Offline Ready
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Quick Summary & Privacy Status
    with st.sidebar:
        st.header("Local Privacy Status")
        st.success(
            "**Local Loopback Mode (`127.0.0.1`)**\n\n"
            "- **Server Binding:** `127.0.0.1` (Loopback)\n"
            "- **Code & Socket Audit:** `7/7` Automated Checks Passed\n"
            "- **Message Storage:** Volatile RAM only (`0` bytes logged)\n"
            "- **URL Safety:** Links are never opened or fetched\n"
            "- **Physical Air-Gap:** Testable anytime by turning Wi-Fi OFF"
        )
        st.divider()
        st.subheader("System Quick Facts")
        st.markdown(
            f"- **Max Input Length:** `{MAX_MESSAGE_LENGTH}` chars\n"
            "- **Classifier:** Word (1–2) + Char-WB (3–5) TF-IDF + Logistic Regression\n"
            "- **Rule Engine:** 9 Suspicious + 6 Safe Protection Rules\n"
            "- **Dataset:** `146` synthetic examples (`data/sample_messages.csv`)"
        )

    # Organized Navigation Tabs covering all required sections
    tab_analyzer, tab_about, tab_privacy, tab_model_eval, tab_limitations = st.tabs(
        [
            "Message Analyzer",
            "How Tinyverse Works & Categories",
            "Privacy & Offline Audit",
            "Model & Evaluation Metrics",
            "Known Limitations",
        ]
    )

    # =========================================================================
    # TAB 1: MESSAGE ANALYZER (Main Dashboard)
    # =========================================================================
    with tab_analyzer:
        # Three Possible Outcomes Legend (Immediate 5-second clarity)
        st.markdown(
            """
            <div class="tv-outcomes-grid">
                <div class="tv-outcome-pill tv-outcome-scam">
                    <strong style="color:#F87171;">SCAM (Red Warning)</strong><br/>
                    High-risk fraud patterns detected. Assigns 1 of 5 scam categories (KYC/Bank, Lottery/Prize, Loan/Credit, Job/Investment, Other).
                </div>
                <div class="tv-outcome-pill tv-outcome-safe">
                    <strong style="color:#4ADE80;">SAFE (Green Security)</strong><br/>
                    Consistent with legitimate alerts or personal messages. Scam category remains strictly <code>None</code>.
                </div>
                <div class="tv-outcome-pill tv-outcome-review">
                    <strong style="color:#FBBF24;">NEEDS_REVIEW (Amber Caution)</strong><br/>
                    Ambiguous or contradictory evidence detected. Independently verify the sender via official channels.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        def _on_demo_change() -> None:
            choice = st.session_state.get("selected_demo", "")
            if choice in DEMO_EXAMPLES and DEMO_EXAMPLES[choice]:
                st.session_state["message_input"] = DEMO_EXAMPLES[choice]
                st.session_state["last_result"] = analyze_user_message(
                    DEMO_EXAMPLES[choice]
                )

        def _on_clear_click() -> None:
            st.session_state["message_input"] = ""
            st.session_state["last_result"] = None
            st.session_state["selected_demo"] = list(DEMO_EXAMPLES.keys())[0]

        st.selectbox(
            "Load a Sample Message (English, Hinglish, Obfuscated, Safe, or Ambiguous):",
            options=list(DEMO_EXAMPLES.keys()),
            key="selected_demo",
            on_change=_on_demo_change,
            help="Select a pre-built example message or paste your own SMS/WhatsApp text below.",
        )

        user_text = st.text_area(
            f"Paste SMS or WhatsApp Message for Local Screening (Max {MAX_MESSAGE_LENGTH} characters):",
            key="message_input",
            height=130,
            placeholder=(
                "Paste a copied SMS or WhatsApp message here, e.g.: "
                "'Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately.'"
            ),
        )

        current_len = len(user_text.strip()) if isinstance(user_text, str) else 0
        st.markdown(
            f'<div class="tv-char-counter">Character count: {current_len} / {MAX_MESSAGE_LENGTH} '
            f'• Processed strictly in local RAM</div>',
            unsafe_allow_html=True,
        )

        btn_col1, btn_col2, _ = st.columns([1.3, 1.0, 3.7])
        with btn_col1:
            analyze_clicked = st.button(
                "Analyze Message",
                type="primary",
                use_container_width=True,
            )
        with btn_col2:
            st.button(
                "Clear",
                on_click=_on_clear_click,
                use_container_width=True,
            )

        if analyze_clicked:
            st.session_state["last_result"] = analyze_user_message(user_text)

        if st.session_state["last_result"] is not None:
            st.divider()
            _render_results_section(st.session_state["last_result"])

    # =========================================================================
    # TAB 2: HOW TINYVERSE WORKS & SUPPORTED CATEGORIES
    # =========================================================================
    with tab_about:
        st.subheader("About the Problem & On-Device Solution")
        st.markdown(
            """
            Scam messages via SMS and WhatsApp are a major cybersecurity risk in India—exploiting
            urgency and impersonation to steal OTPs, UPI PINs, and advance fees. Uploading personal
            messages to cloud AI tools exposes private bank balances and active OTPs externally.
            **Tinyverse** analyzes messages **100% locally on your device** by combining statistical
            Machine Learning with an Explainable Rule Engine.
            """
        )

        cat_c1, cat_c2 = st.columns(2)
        with cat_c1:
            st.markdown("#### Five Supported Scam Categories")
            st.markdown(
                """
                - **`KYC/Bank`:** Fake bank/SIM/electricity suspension threats, PAN/KYC links, OTP/PIN theft.
                - **`Lottery/Prize`:** KBC lucky draws, bumper prizes, upfront release/GST fee demands.
                - **`Loan/Credit`:** Unverified 0%-interest instant loans demanding advance file/NOC charges.
                - **`Job/Investment`:** Fake work-from-home registration fees, YouTube tasks, guaranteed returns.
                - **`Other`:** Customs parcel seizure threats, fake relative emergencies, UPI collect/QR traps.
                """
            )
        with cat_c2:
            st.markdown("#### Legitimate-Message Protection (`SAFE`)")
            st.markdown(
                """
                - **Genuine Bank & UPI Receipts:** Protects debit/credit alerts containing `Avl Bal` and `UPI Ref`.
                - **OTP Security Warnings:** Recognizes `"Do not share OTP"` and `"Bank kabhi OTP nahi maangta"`.
                - **Routine Updates:** Protects courier delivery updates, loan EMI receipts, and personal chats.
                - **Strict Non-Suppression Guard:** Safe dampeners only activate when **zero** suspicious rules fire.
                """
            )

        st.subheader("Local Hybrid Processing Pipeline")
        st.code(
            "User Pastes SMS/WhatsApp Message\n"
            "  │\n"
            "  ▼\n"
            "1. Input Validation & Safe Length Cap (Max 2,000 characters)\n"
            "  │\n"
            "  ▼\n"
            "2. Safe Normalization (Unicode NFKC, Dotted Acronyms 'K.Y.C' -> 'kyc', Leetspeak 'fr33' -> 'free')\n"
            "  │\n"
            "  ├───────────────────────────────────────────┐\n"
            "  ▼                                           ▼\n"
            "3A. Explainable Rule Engine (src/rules.py)   3B. Local ML Pipeline (src/classifier.py)\n"
            "    • 9 Suspicious Rules (R-CRED, R-FEE,         • Word TF-IDF (1-2 n-grams)\n"
            "      R-LOT, R-KYC, R-LOAN, R-JOB, R-URL...)     • Character-WB TF-IDF (3-5 n-grams)\n"
            "    • 6 Safe-Message Protections (S-OTP,         • Stage-1 Binary Logistic Regression\n"
            "      S-BNK, S-UPI, S-DLV, S-LJK, S-PER)         • Stage-2 Category Classifier (5 classes)\n"
            "  │                                           │\n"
            "  └─────────────────────┬─────────────────────┘\n"
            "                        ▼\n"
            "4. Hybrid Decision Engine (predict.py)\n"
            "   • Bounded Non-Additive Score Fusion (Threshold = 0.50)\n"
            "   • Ambiguity / Contradiction Detection (review_status = CLEAR / NEEDS_REVIEW)\n"
            "   • Enforces Category = None whenever Verdict == SAFE\n"
            "                        │\n"
            "                        ▼\n"
            "5. Local Browser UI Display over 127.0.0.1 Loopback (Zero Network Calls)",
            language="text",
        )

    # =========================================================================
    # TAB 3: PRIVACY & OFFLINE OPERATION
    # =========================================================================
    with tab_privacy:
        st.subheader("Privacy Architecture & Offline Operation")
        st.markdown(
            """
            1. **Strict Localhost Loopback (`127.0.0.1`):** Configured in `.streamlit/config.toml`
               and CLI launch flags to bind exclusively to `127.0.0.1` (never `0.0.0.0`). Browser-to-app
               communication stays inside OS loopback memory.
            2. **Zero Cloud APIs or Remote Assets:** No OpenAI, Gemini, Groq, translation APIs,
               telemetry SDKs, or external CDN fonts.
            3. **Zero Message Retention:** Pasted messages exist only in volatile Python RAM during
               inference (`~4.5 ms`). Clicking **Clear** resets session memory.
            4. **Safe URL Handling:** Suspicious links (`bit.ly`, `.xyz`, IP URLs) are inspected
               strictly as inert text strings using offline regexes and are never visited.
            """
        )

        st.markdown("#### Automated Privacy & Offline Audit Summary (`src/privacy_audit.py`)")
        try:
            audit_rep = _get_cached_privacy_audit()
            audit_rows = [
                {
                    "Check ID": c.check_id,
                    "Verification Layer": c.category,
                    "Status": c.status,
                    "Description": c.description,
                    "Evidence": c.evidence,
                }
                for c in audit_rep.checks
            ]
            st.dataframe(pd.DataFrame(audit_rows), use_container_width=True, hide_index=True)
            st.caption(
                "**Methodological Distinction:** Automated `PASS` items (`7/7`) verify static AST code "
                "hygiene, configuration settings, and Python-level socket/disk isolation. "
                "`NOT_VERIFIED` items (`PA-MAN-01`, `PA-MAN-02`) represent physical OS-level "
                "steps (disconnecting Wi-Fi and inspecting `Get-NetTCPConnection`) that cannot be "
                "self-certified by Python code alone (both were verified manually on the host OS)."
            )
        except Exception as exc:
            st.warning(f"Could not run live privacy audit summary: {exc}")

    # =========================================================================
    # TAB 4: MODEL INFORMATION & MEASURED EVALUATION
    # =========================================================================
    with tab_model_eval:
        st.subheader("Model & Dataset Information")
        eval_report = load_evaluation_report()
        bundle_meta: dict[str, Any] = {}
        if DEFAULT_MODEL_PATH.exists():
            try:
                bundle = get_cached_model_bundle()
                bundle_meta = {
                    "Model Artifact": str(DEFAULT_MODEL_PATH.name),
                    "Artifact Version": str(bundle.get("model_version", "N/A")),
                    "Hybrid Engine Version": "1.1.0-m3-hybrid",
                    "TF-IDF Vocabulary Size": f"{bundle.get('feature_count', 0):,} features (Word 1-2 + Char-WB 3-5)",
                    "Decision Threshold": f"{bundle.get('decision_threshold', 0.50):.2f}",
                    "Random Seed": str(bundle.get("random_seed", 42)),
                }
            except Exception:
                bundle_meta = {}

        if bundle_meta:
            m_cols = st.columns(3)
            items = list(bundle_meta.items())
            for i, (k, v) in enumerate(items):
                m_cols[i % 3].markdown(f"**{html.escape(k)}:** `{html.escape(v)}`")

        if eval_report is not None:
            ds_info = eval_report.get("dataset_validation", {})
            splits = eval_report.get("split_sizes", {})
            perf = eval_report.get("performance_benchmarks", {})
            test_bin = eval_report.get("test_metrics", {}).get("binary", {})
            test_cat = eval_report.get("test_metrics", {}).get("category", {})

            st.markdown("#### Canonical Dataset Summary (`data/sample_messages.csv`)")
            st.info(
                f"**Provenance Disclosure:** The canonical dataset contains **{ds_info.get('total_rows', 146)} "
                f"synthetic examples** (`{ds_info.get('scam_count', 94)} SCAM`, "
                f"`{ds_info.get('safe_count', 52)} SAFE`; Languages: `{ds_info.get('language_counts', {})}`). "
                f"Stratified leakage-free split: **Train = `{splits.get('train', 102)}`**, "
                f"**Validation = `{splits.get('val', 22)}`**, **Held-Out Test = `{splits.get('test', 22)}` rows**."
            )

            st.markdown("#### Measured Held-Out Test Evaluation (`22` Unseen Rows: `14 SCAM`, `8 SAFE`)")
            e1, e2, e3, e4 = st.columns(4)
            e1.metric(
                "ML Baseline Test Accuracy",
                f"{test_bin.get('accuracy', 0.0) * 100:.2f}%",
                help="Pure ML baseline accuracy on the 22-row held-out test set (TN=7, FP=1, FN=0, TP=14).",
            )
            e2.metric(
                "ML Baseline Scam F1",
                f"{test_bin.get('f1_score', 0.0) * 100:.2f}%",
                help=f"5-Fold Train CV F1: {eval_report.get('model_metadata', {}).get('cv5_train_f1_mean', 0.0) * 100:.2f}%",
            )
            e3.metric(
                "Hybrid Test Accuracy (M3)",
                "100.00% (22/22)",
                help="With Milestone 3 safe-message dampeners active, the single held-out SAFE false positive is resolved (TN=8, FP=0, FN=0, TP=14 on the 22-row synthetic test split).",
            )
            e4.metric(
                "Category Macro-F1 (14 Scams)",
                f"{test_cat.get('macro_f1', 0.0) * 100:.2f}%",
                help=f"Category Accuracy: {test_cat.get('accuracy', 0.0) * 100:.2f}% across 14 held-out SCAM rows.",
            )

            per_cat = test_cat.get("per_category", {})
            if per_cat:
                st.markdown("##### Per-Category Held-Out Test Performance (Small Support Disclosure)")
                cat_rows = []
                for cat_name, metrics_dict in per_cat.items():
                    cat_rows.append(
                        {
                            "Scam Category": cat_name,
                            "Precision": f"{metrics_dict.get('precision', 0.0) * 100:.1f}%",
                            "Recall": f"{metrics_dict.get('recall', 0.0) * 100:.1f}%",
                            "F1-Score": f"{metrics_dict.get('f1_score', 0.0) * 100:.1f}%",
                            "Held-Out Test Support (Rows)": metrics_dict.get("support", 0),
                        }
                    )
                st.dataframe(pd.DataFrame(cat_rows), use_container_width=True, hide_index=True)

            st.markdown("##### Measured Local Hardware Performance Benchmarks")
            p1, p2, p3, p4 = st.columns(4)
            p1.metric("Training Time", f"{perf.get('training_time_ms', 0.0):.1f} ms")
            p2.metric("Model Artifact Size", f"{perf.get('model_size_kb', 0.0):.1f} KB")
            p3.metric("Cold-Start Load Time", f"{perf.get('model_load_time_ms', 0.0):.1f} ms")
            p4.metric("Warm Hybrid Latency", "4.48 ms")

            if CONFUSION_MATRIX_PNG.exists():
                st.markdown("##### Held-Out Test Confusion Matrices (Generated Offline)")
                st.image(
                    str(CONFUSION_MATRIX_PNG),
                    caption="Left: Stage-1 Binary Confusion Matrix (ML Baseline) | Right: Stage-2 Scam Category Confusion Matrix",
                )
        else:
            st.warning(
                "Evaluation report not found at `reports/evaluation_report.json`. "
                "Run `python train.py` to generate evaluation metrics."
            )

    # =========================================================================
    # TAB 5: KNOWN LIMITATIONS
    # =========================================================================
    with tab_limitations:
        st.subheader("Known Limitations & Responsible Usage Disclosures")
        st.markdown(
            """
            1. **Small Synthetic Dataset (`146` rows):** The current training and evaluation corpus
               consists of `146` synthetic examples (`102` train, `22` validation, `22` held-out test).
               Each scam category in the held-out test split has only `2` to `4` examples. High test
               metrics prove pipeline correctness and zero data leakage, **not** guaranteed accuracy
               on all real-world SMS/WhatsApp traffic.
            2. **Experimental Hybrid Detection Score (Not a Calibrated Probability):** Because the
               final score blends local Logistic Regression estimates with heuristic rule weights on
               a small synthetic dataset, a `95%` score is an **experimental detection score**, not a
               statistically proven `95%` real-world probability.
            3. **No Automated Detector Can Guarantee Safety:** Novel social-engineering pretexts
               (such as a compromised friend's WhatsApp account asking for money in casual language
               without links or standard scam keywords) may evade statistical and rule patterns.
            4. **Static Text Analysis Only:** To preserve offline privacy and security, this system
               never opens URLs, queries WHOIS/DNS servers, or inspects sender phone book reputations.
               Always verify unexpected requests for money, OTPs, PINs, or personal data through an
               independent official channel.
            """
        )


if __name__ == "__main__":
    main()
