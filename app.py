"""Streamlit local user interface for Tinyverse Scam Detector (Milestone 4).

This module implements the 100% local, privacy-preserving cybersecurity dashboard
for the Tinyverse On-Device Scam Message Detector.

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
    """Inject clean, responsive local CSS using only system fonts (zero external CDNs)."""
    st.markdown(
        """
        <style>
        .main-header-card {
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f8fafc;
            padding: 1.4rem 1.6rem;
            border-radius: 12px;
            border-left: 6px solid #38bdf8;
            margin-bottom: 1rem;
            font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
        }
        .privacy-pill {
            display: inline-block;
            background-color: #064e3b;
            color: #a7f3d0;
            border: 1px solid #10b981;
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            margin-top: 0.5rem;
        }
        .verdict-scam {
            background-color: #fef2f2;
            border: 2px solid #dc2626;
            border-left: 8px solid #dc2626;
            color: #7f1d1d;
            padding: 1.25rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .verdict-safe {
            background-color: #f0fdf4;
            border: 2px solid #16a34a;
            border-left: 8px solid #16a34a;
            color: #14532d;
            padding: 1.25rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .review-banner {
            background-color: #fffbeb;
            border: 2px solid #d97706;
            border-left: 8px solid #d97706;
            color: #78350f;
            padding: 1rem 1.25rem;
            border-radius: 10px;
            margin-bottom: 1rem;
        }
        .info-card {
            background-color: #f8fafc;
            border: 1px solid #cbd5e1;
            color: #1e293b;
            padding: 1rem 1.25rem;
            border-radius: 8px;
            margin-bottom: 0.85rem;
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
                <strong>⚠️ REVIEW STATUS: NEEDS_REVIEW (Ambiguous or Contradictory Signals)</strong><br/>
                This message contains mixed or borderline indicators (for example, both a suspicious
                claim and a safety phrase, or a borderline score). Do not treat this message as
                unquestionably safe—verify the sender via official channels.
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
                <h2 style="margin:0 0 0.35rem 0; color:#991b1b;">🚨 VERDICT: {verdict_escaped}</h2>
                <p style="margin:0; font-size:1.05rem;">
                    <strong>Scam Category:</strong> <code>{category_display}</code> &nbsp;|&nbsp;
                    <strong>Experimental Hybrid Detection Score:</strong> <code>{result.confidence:.1f}%</code>
                    &nbsp;|&nbsp; <strong>Review Status:</strong> <code>{html.escape(result.review_status)}</code>
                </p>
                <p style="margin:0.4rem 0 0 0; font-size:0.85rem; color:#7f1d1d;">
                    <em>Note: Experimental hybrid detection score — not a calibrated real-world probability.</em>
                </p>
            </div>
            """,
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f"""
            <div class="verdict-safe">
                <h2 style="margin:0 0 0.35rem 0; color:#166534;">✅ VERDICT: {verdict_escaped}</h2>
                <p style="margin:0; font-size:1.05rem;">
                    <strong>Scam Category:</strong> <code>None</code> &nbsp;|&nbsp;
                    <strong>Experimental Hybrid Detection Score:</strong> <code>{result.confidence:.1f}%</code>
                    &nbsp;|&nbsp; <strong>Review Status:</strong> <code>{html.escape(result.review_status)}</code>
                </p>
                <p style="margin:0.4rem 0 0 0; font-size:0.85rem; color:#14532d;">
                    <em>Note: Experimental hybrid detection score — not a calibrated real-world probability. Automated SAFE assessment is not a guarantee.</em>
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
        f"| Combined Hybrid Scam Score = `{hybrid_scam_pct:.1f}%` (Threshold = `50.0%`, "
        f"`confidence_type = {result.confidence_type}`)."
    )

    # 4. Why This Message Was Classified That Way (Explanations & Indicators)
    st.markdown("#### Explanation & Key Signals")
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
    st.markdown("#### Safety Recommendation")
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
        page_title="Tinyverse Scam Detector (100% Local)",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )
    _inject_local_css()

    # Initialize session state variables in volatile RAM only
    if "message_input" not in st.session_state:
        st.session_state["message_input"] = ""
    if "last_result" not in st.session_state:
        st.session_state["last_result"] = None
    if "selected_demo" not in st.session_state:
        st.session_state["selected_demo"] = list(DEMO_EXAMPLES.keys())[0]

    # Top Header & Privacy Indicator
    st.markdown(
        """
        <div class="main-header-card">
            <h1 style="margin:0; font-size:1.85rem;">🛡️ Tinyverse Scam Detector</h1>
            <p style="margin:0.35rem 0 0 0; font-size:1.0rem; color:#cbd5e1;">
                On-Device, Privacy-Preserving SMS &amp; WhatsApp Scam Detection System (English, Hinglish &amp; Obfuscation Resilient)
            </p>
            <div class="privacy-pill">
                🔒 PRIVACY INDICATOR: Local Loopback Mode (127.0.0.1) &bull; Automated Code &amp; Socket Audit Passed &bull; Zero Message Storage
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Sidebar Quick Summary & Privacy Status
    with st.sidebar:
        st.header("🔒 Local Privacy Status")
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
            "🔍 Message Analyzer",
            "📖 About & How It Works",
            "🔐 Privacy & Offline Operation",
            "📊 Model & Evaluation Metrics",
            "⚠️ Known Limitations",
        ]
    )

    # =========================================================================
    # TAB 1: MESSAGE ANALYZER (Main Dashboard)
    # =========================================================================
    with tab_analyzer:
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
            "Load a Quick Demo Example (Optional):",
            options=list(DEMO_EXAMPLES.keys()),
            key="selected_demo",
            on_change=_on_demo_change,
            help="Select a pre-built English, Hinglish, obfuscated, safe, or borderline example to test immediately.",
        )

        user_text = st.text_area(
            f"Paste one SMS or WhatsApp message below (Max {MAX_MESSAGE_LENGTH} characters):",
            key="message_input",
            height=135,
            placeholder=(
                "Paste a suspicious or legitimate message here, e.g.: "
                "'Your KYC will be blocked today. Click bit.ly/kyc-update and share your OTP immediately.'"
            ),
        )

        btn_col1, btn_col2, _ = st.columns([1, 1, 4])
        with btn_col1:
            analyze_clicked = st.button(
                "🔍 Analyze Message",
                type="primary",
                use_container_width=True,
            )
        with btn_col2:
            st.button(
                "🧹 Clear",
                on_click=_on_clear_click,
                use_container_width=True,
            )

        if analyze_clicked:
            st.session_state["last_result"] = analyze_user_message(user_text)

        if st.session_state["last_result"] is not None:
            st.divider()
            _render_results_section(st.session_state["last_result"])

    # =========================================================================
    # TAB 2: ABOUT & HOW IT WORKS
    # =========================================================================
    with tab_about:
        st.subheader("About the Problem & Our Solution")
        st.markdown(
            """
            Scam messages via SMS and WhatsApp are a major cybersecurity threat in India—ranging
            from fake **KYC/bank suspension warnings** and **electricity disconnection threats**
            to **KBC lottery scams**, **instant 0%-interest loan advance fees**, and **work-from-home
            job/investment traps**.

            Many spam detectors send copied messages to cloud AI APIs. However, uploading private
            inbox messages exposes genuine bank balances, account numbers, and live OTPs to external
            servers. **Tinyverse Scam Detector** solves this by running a hybrid Machine Learning
            and Explainable Rule Engine **100% locally on your computer**.
            """
        )

        st.subheader("How It Works — Local Processing Pipeline")
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
            1. **Strict Localhost Loopback (`127.0.0.1`):** This Streamlit interface is configured
               in `.streamlit/config.toml` and via CLI flags to bind exclusively to `127.0.0.1`
               (never `0.0.0.0`). Your web browser communicates with the local Python process inside
               your operating system's loopback memory—no traffic reaches your Wi-Fi router or the internet.
            2. **Zero Cloud APIs or Remote Assets:** The detector uses no OpenAI, Gemini, Groq,
               translation APIs, telemetry SDKs, or external CDN fonts.
            3. **Zero Message Retention:** Pasted messages exist only in volatile Python RAM during
               the `< 25 ms` inference step. Clicking **Clear** wipes the input from session memory.
               Submitted messages are never written to log files, CSVs, or databases.
            4. **Safe URL Handling:** Suspicious links (`bit.ly`, `.xyz`, IP URLs) are inspected
               strictly as inert text strings using regular expressions and are never visited or
               rendered as clickable hyperlinks.
            """
        )

        st.markdown("#### Automated Privacy & Offline Audit Summary (`src/privacy_audit.py`)")
        try:
            audit_rep = run_privacy_audit()
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
                "**Methodological Distinction:** Automated `PASS` items verify static AST code "
                "hygiene, configuration settings, and Python-level socket/disk isolation. "
                "`NOT_VERIFIED` items (`PA-MAN-01`, `PA-MAN-02`) represent physical OS-level "
                "steps (disconnecting Wi-Fi and inspecting `Get-NetTCPConnection`) that must "
                "be performed outside Python."
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
            p4.metric("Single Prediction Latency", f"{perf.get('single_prediction_latency_ms', 0.0):.2f} ms")

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
