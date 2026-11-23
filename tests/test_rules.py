"""Comprehensive unit tests for the Milestone 3 Explainable Rule Engine and Hybrid Detector."""

from __future__ import annotations

import pytest

from predict import combine_ml_and_rules, predict_message
from src.classifier import VALID_CATEGORIES
from src.rules import RuleEvaluationResult, evaluate_rules


# =============================================================================
# 1. Individual Suspicious Rule Behaviour Tests
# =============================================================================


def test_rule_credential_harvesting_english_and_hinglish():
    """Verify R-CRED-01 fires on OTP, PIN, CVV, and password requests in English and Hinglish."""
    r1 = evaluate_rules("Your debit card is blocked. Share your 6-digit OTP and CVV immediately.")
    rule_ids_1 = {r.rule_id for r in r1.suspicious_rules}
    assert "R-CRED-01" in rule_ids_1
    assert r1.risk_level == "CRITICAL"

    r2 = evaluate_rules("Aapka khata chalu rakhne ke liye turant is link par OTP bhejo aur UPI PIN dalein.")
    rule_ids_2 = {r.rule_id for r in r2.suspicious_rules}
    assert "R-CRED-01" in rule_ids_2


def test_rule_upfront_and_processing_fees():
    """Verify R-FEE-01 fires on advance fee, processing charge, release tax, and registration fee demands."""
    r1 = evaluate_rules("Pay Rs 4500 processing fee to claim your prize money now.")
    assert any(r.rule_id == "R-FEE-01" for r in r1.suspicious_rules)

    r2 = evaluate_rules("Loan pass ho gaya hai, pehle Rs 1500 file charge abhi UPI karein.")
    assert any(r.rule_id == "R-FEE-01" for r in r2.suspicious_rules)


def test_rule_lottery_and_prize_scams():
    """Verify R-LOT-01 fires on lottery, KBC lucky draw, and unexpected prize messages."""
    r = evaluate_rules(
        "CONGRATULATIONS! Your mobile number has won Rs 25,00,000 in the KBC Mega Lucky Draw."
    )
    assert any(m.rule_id == "R-LOT-01" for m in r.suspicious_rules)
    assert r.suggested_category == "Lottery/Prize"


def test_rule_kyc_and_account_suspension_threats():
    """Verify R-KYC-01 fires on KYC expiry, account blocking, and electricity disconnect threats."""
    r1 = evaluate_rules("Dear customer, your SBI bank account has been suspended due to incomplete KYC.")
    assert any(m.rule_id == "R-KYC-01" for m in r1.suspicious_rules)
    assert r1.suggested_category == "KYC/Bank"

    r2 = evaluate_rules("Aapka KYC band ho jayega aaj raat 12 baje.")
    assert any(m.rule_id == "R-KYC-01" for m in r2.suspicious_rules)


def test_rule_instant_loan_and_credit_scams():
    """Verify R-LOAN-01 fires on 0% interest, no-CIBIL, and paperless instant loan offers."""
    r = evaluate_rules(
        "Pre-approved personal loan of Rs 5,00,000 at 0% interest with no CIBIL check."
    )
    assert any(m.rule_id == "R-LOAN-01" for m in r.suspicious_rules)
    assert r.suggested_category == "Loan/Credit"


def test_rule_job_and_investment_scams():
    """Verify R-JOB-01 fires on work-from-home task scams and guaranteed high-return schemes."""
    r1 = evaluate_rules(
        "Earn Rs 5,000 daily from home just by liking YouTube videos! Prepaid VIP task available."
    )
    assert any(m.rule_id == "R-JOB-01" for m in r1.suspicious_rules)
    assert r1.suggested_category == "Job/Investment"

    r2 = evaluate_rules("10 din mein paisa double karne wali guaranteed trading scheme!")
    assert any(m.rule_id == "R-JOB-01" for m in r2.suspicious_rules)


def test_rule_suspicious_links_and_obfuscation():
    """Verify R-URL-01 and R-OBF-01 fire on shortened links, .xyz/.top TLDs, IP URLs, APKs, and leetspeak."""
    r = evaluate_rules(
        "URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at http://192.168.10.45/kyc or bit.ly/kyc-now"
    )
    fired = {m.rule_id for m in r.suspicious_rules}
    assert "R-URL-01" in fired
    assert "R-OBF-01" in fired
    assert "R-KYC-01" in fired


def test_rule_impersonation_and_customs_threats():
    """Verify R-OTH-01 fires on customs seizure, fake relative hospital emergencies, and QR PIN scams."""
    r = evaluate_rules(
        "Army Officer here buying your OLX sofa. Scan this QR code and enter your UPI PIN to receive advance payment."
    )
    fired = {m.rule_id for m in r.suspicious_rules}
    assert "R-OTH-01" in fired
    assert "R-CRED-01" in fired


# =============================================================================
# 2. Safe-Message Protections & Non-Triggering Keyword Tests
# =============================================================================


@pytest.mark.parametrize(
    "safe_msg,expected_safe_rule",
    [
        (
            "Your OTP is 482913. Do not share it with anyone.",
            "S-OTP-01",
        ),
        (
            "OTP kisi ke saath share mat karna. Bank kabhi OTP nahi maangta.",
            "S-OTP-01",
        ),
        (
            "Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank (UPI Ref 632819402112). Avl Bal: Rs. 18,430.50.",
            "S-BNK-01",
        ),
        (
            "ICICI Bank: Rs 3,000 withdrawn from ATM +S1AC02 on 22-Nov-26 using Card XX1122. Avl Bal: Rs 14,200.",
            "S-BNK-01",
        ),
        (
            "Paid Rs 180.00 to Metro Dairy via UPI Ref 419283746510. Thank you for using Google Pay.",
            "S-UPI-01",
        ),
        (
            "BlueDart Update: Your shipment AWB 7788991122 is out for delivery with executive Rajesh. No payment is required.",
            "S-DLV-01",
        ),
        (
            "We have received your home loan EMI of Rs 24,500 for November 2026 towards Loan Account LN998822.",
            "S-LJK-01",
        ),
        (
            "Your periodic KYC update has been successfully processed at your home branch. No further action is required.",
            "S-LJK-01",
        ),
        (
            "Dear Candidate, thank you for attending the technical interview at Infosys. Note: We never charge any fee for hiring.",
            "S-OTP-01",
        ),
        (
            "Hey! Did you hear that Rohan won first prize in the inter-college coding competition today?",
            "S-PER-01",
        ),
        (
            "Check out the official Python documentation at https://docs.python.org/3/ for tomorrow's coding workshop.",
            "S-PER-01",
        ),
    ],
)
def test_safe_message_protection_rules_and_hybrid_verdict(safe_msg: str, expected_safe_rule: str):
    """Verify safe rules fire on legitimate messages and hybrid prediction returns SAFE with category=None."""
    rule_res = evaluate_rules(safe_msg)
    assert len(rule_res.suspicious_rules) == 0, f"Unexpected suspicious rule on: {safe_msg}"
    safe_ids = {r.rule_id for r in rule_res.safe_rules}
    assert expected_safe_rule in safe_ids
    assert rule_res.net_rule_score < 0.0

    pred = predict_message(safe_msg)
    assert pred.verdict == "SAFE"
    assert pred.category is None
    assert pred.ml_verdict in ("SAFE", "SCAM")
    assert pred.ml_scam_probability is not None


# =============================================================================
# 3. Rule Combinations, Non-Additive Bounds & Contradictory Evidence Tests
# =============================================================================


def test_non_additive_score_bounding():
    """Verify multiple firing rules do not blindly sum above 1.0."""
    msg = (
        "FINAL WARNING within 1 hour: Acc0unt bl0ck due to K.Y.C! "
        "You won Rs 25,00,000 lottery prize & 0% interest instant l0an. "
        "Click bit.ly/scam-all.xyz, share your OTP and PIN, and pay Rs 5000 processing fee!"
    )
    res = evaluate_rules(msg)
    assert len(res.suspicious_rules) >= 5
    # Even when 6+ rules fire, suspicious_score is strictly bounded <= 0.95
    assert 0.70 <= res.suspicious_score <= 0.95

    pred = predict_message(msg)
    assert pred.verdict == "SCAM"
    assert pred.category in VALID_CATEGORIES
    assert 0.0 <= pred.confidence <= 100.0
    assert 0.0 < pred.scam_probability < 1.0


def test_contradictory_evidence_triggers_needs_review():
    """Verify contradictory messages (both suspicious and safe signals) flag review_status='NEEDS_REVIEW'."""
    contradictory_msg = (
        "Congratulations! You won a lottery prize of Rs 10,00,000 in KBC Lucky Draw. "
        "Note: Do not share your OTP with anyone."
    )
    rule_res = evaluate_rules(contradictory_msg)
    assert rule_res.has_contradictory_evidence is True
    assert len(rule_res.suspicious_rules) >= 1
    assert len(rule_res.safe_rules) >= 1

    pred = predict_message(contradictory_msg)
    assert pred.review_status == "NEEDS_REVIEW"
    assert any("NEEDS_REVIEW" in w for w in pred.warnings)


def test_hybrid_preserves_ml_fields_and_confidence_type():
    """Verify hybrid prediction preserves original ML fields and distinguishes confidence_type."""
    # 1. Borderline ATM withdrawal alert where pure ML had a false positive (0.600)
    #    and the Hybrid S-BNK-01 safe-protection rule dampens it to SAFE (0.369)
    atm_msg = (
        "ICICI Bank: Rs 3,000 withdrawn from ATM +S1AC02 on 22-Nov-26 using Card XX1122. "
        "Avl Bal: Rs 14,200. Call 18001080 from official card back if unauthorized."
    )
    pure_ml_atm = predict_message(atm_msg, use_rules=False)
    hybrid_atm = predict_message(atm_msg, use_rules=True)

    assert pure_ml_atm.verdict == "SCAM"
    assert pure_ml_atm.confidence_type == "experimental_local_ml_score"
    assert hybrid_atm.verdict == "SAFE"
    assert hybrid_atm.category is None
    assert hybrid_atm.ml_verdict == "SCAM"
    assert abs(hybrid_atm.ml_scam_probability - pure_ml_atm.scam_probability) < 1e-6
    assert hybrid_atm.scam_probability < pure_ml_atm.scam_probability
    assert hybrid_atm.confidence_type == "hybrid_heuristic_ml_score"

    # 2. Standard UPI bank debit alert where both pure ML and Hybrid agree on SAFE,
    #    and Hybrid further strengthens SAFE confidence via S-BNK-01
    upi_msg = "Rs. 1,250.00 debited from A/c XX4821 on 23-Nov-26 to VPA swiggy@axisbank (UPI Ref 632819402112). Avl Bal: Rs. 18,430.50."
    pure_ml_upi = predict_message(upi_msg, use_rules=False)
    hybrid_upi = predict_message(upi_msg, use_rules=True)
    assert pure_ml_upi.verdict == "SAFE"
    assert hybrid_upi.verdict == "SAFE"
    assert hybrid_upi.category is None
    assert abs(hybrid_upi.ml_scam_probability - pure_ml_upi.scam_probability) < 1e-6
    assert hybrid_upi.scam_probability < pure_ml_upi.scam_probability


def test_empty_and_invalid_inputs_in_rule_engine():
    """Verify evaluate_rules handles empty, whitespace, and non-string inputs safely."""
    for invalid in ("", "   ", None, 42):
        r = evaluate_rules(invalid)
        assert isinstance(r, RuleEvaluationResult)
        assert len(r.suspicious_rules) == 0
        assert len(r.safe_rules) == 0
        assert r.suspicious_score == 0.0
        assert r.risk_level == "NONE"


# =============================================================================
# 4. Milestone 5 Comprehensive Scam, Safe, Hinglish, Obfuscation & Security Suite
# =============================================================================


@pytest.mark.parametrize(
    "case_name,expected_cat,msg",
    [
        ("Fake KYC update", "KYC/Bank", "Dear Customer, your bank KYC has expired today. Update your KYC immediately at bit.ly/kyc-online-update to avoid account block."),
        ("Bank account suspension threat", "KYC/Bank", "URGENT: Your SBI savings account has been suspended due to non-verification. Click http://sbi-reactivate.xyz to restore access."),
        ("Fake lottery winnings", "Lottery/Prize", "CONGRATULATIONS! Your mobile number won Rs 25,00,000 in the KBC Mega Lucky Draw. Contact our WhatsApp officer to claim."),
        ("Prize processing fee", "Lottery/Prize", "You won an iPhone 15 Pro and Rs 5 Lakh bumper prize! Pay Rs 2,500 processing fee and release charge via UPI to dispatch your gift."),
        ("Fake instant loan", "Loan/Credit", "Pre-approved personal loan of Rs 5,00,000 sanctioned at 0% interest with no CIBIL check! Click bit.ly/fast-cash-loan"),
        ("Loan advance fee", "Loan/Credit", "Your instant cash loan of Rs 2,00,000 is approved. Pay Rs 1,499 advance processing charge and NOC fee to disburse to your bank."),
        ("Fake job registration fee", "Job/Investment", "Work from home job confirmed! Earn Rs 35,000 monthly in data entry. Pay Rs 999 registration fee today to receive your offer letter."),
        ("Investment fraud", "Job/Investment", "Join our VIP Stock & Crypto trading group for 100% guaranteed daily profit! Double your money in 7 days: http://vip-profit.top"),
        ("Suspicious shortened URL", "KYC/Bank", "Alert: Unusual activity on your credit card. Verify your PIN and OTP immediately at tinyurl.com/card-verify-now"),
        ("OTP/PIN request", "KYC/Bank", "Your electricity connection will be disconnected tonight. Call officer and share your 6-digit OTP and UPI PIN to update bill."),
        ("Hinglish scam", "KYC/Bank", "Aapka KYC band ho jayega aaj raat 12 baje. Turant link par click karke apna OTP aur PIN bhejo: bit.ly/kyc-abhi"),
        ("Obfuscated scam", "KYC/Bank", "URGENT: Acc0unt bl0ck notice! Complete your K.Y.C upd@te now at cl1ck-h3re.xyz or lose access to your b@nk."),
        ("Fake electricity disconnection", "KYC/Bank", "Bijli vibhag alert: Your electricity bill is unpaid and power will be disconnected tonight at 9:30 PM. Share OTP with officer."),
        ("Fake UPI payment confirmation / collect trap", "Other", "I accidentally sent Rs 15,000 to your UPI ID by mistake. Please approve the collect request and enter your UPI PIN to refund."),
        ("Suspicious APK download", "Loan/Credit", "Your instant credit line of Rs 1,00,000 is ready. Download our official APK file from http://instant-loan-app.xyz and pay Rs 499 activation fee."),
    ],
)
def test_m5_comprehensive_15_scam_scenarios(case_name: str, expected_cat: str, msg: str):
    """Verify all 15 Milestone 5 scam scenarios are classified as SCAM with accurate categories."""
    res = predict_message(msg)
    assert res.is_valid is True, f"Failed validation on {case_name}"
    assert res.verdict == "SCAM", f"Missed scam on {case_name}: {msg}"
    assert res.category == expected_cat, f"Wrong category on {case_name}: got {res.category}, expected {expected_cat}"
    assert len(res.indicators) >= 1


@pytest.mark.parametrize(
    "case_name,msg",
    [
        ("Bank debit notification", "Rs. 650.00 debited from A/c XX4821 on 23-Nov-26. Available balance is Rs. 15,200.00."),
        ("Bank credit notification", "Dear Customer, your A/c XX9012 is credited with INR 48,500.00 on 01-Nov-26 via NEFT (Monthly Salary). Avl Bal: INR 64,100.00."),
        ("ATM withdrawal", "ICICI Bank: Rs 4,000 withdrawn from ATM +S1AC02 on 23-Nov-26 using Card XX1122. Avl Bal: Rs 11,200. Call official number on card back if unauthorized."),
        ("UPI payment confirmation", "Paid Rs 240.00 to Fresh Mart via UPI Ref 632819402199. Thank you for using Google Pay."),
        ("OTP delivery message", "748291 is your OTP for netbanking transaction at HDFC Bank. Valid for 10 minutes. Do not share this OTP with anyone."),
        ("OTP safety warning", "Security Advisory from SBI: Bank never asks for your OTP, PIN, CVV, or password over phone, SMS, or email."),
        ("Courier delivery notification", "BlueDart Update: Your parcel AWB 8899112233 is out for delivery today with executive Amit. No payment is required."),
        ("Loan EMI receipt", "We have received your monthly home loan EMI payment of Rs 18,500 towards Loan Account LN445566. Thank you."),
        ("Genuine KYC completion", "Your periodic KYC update has been successfully processed at your home branch. No further action is required from your side."),
        ("Job application acknowledgement", "Thank you for applying to TCS. We have received your job application and our HR team will review your profile. Note: We never charge any fee for hiring."),
        ("Personal conversation mentioning a bank", "I went to the bank branch this morning and applied for a new cheque book, it will arrive by post next week."),
        ("Personal conversation mentioning a prize", "Hey! Did you hear that Neha won first prize in the inter-college debate competition today? Let's celebrate this evening!"),
        ("Informational message containing a URL", "Check out the official Python documentation at https://docs.python.org/3/ before tomorrow's lab session."),
        ("Urgent delivery notification", "URGENT: Your package delivery is scheduled for today before 2 PM. Please be available at your doorstep."),
        ("Genuine message containing an amount of money", "Mom asked me to remind you to pay the milkman Rs 600 and buy vegetables on your way home from office."),
    ],
)
def test_m5_comprehensive_15_safe_scenarios(case_name: str, msg: str):
    """Verify all 15 Milestone 5 legitimate scenarios return SAFE and category=None."""
    res = predict_message(msg)
    assert res.is_valid is True
    assert res.verdict == "SAFE", f"False positive on {case_name}: {msg}"
    assert res.category is None


def test_m5_adversarial_fake_bank_with_otp_request_is_not_suppressed():
    """Verify a genuine-looking bank debit alert that also asks to share OTP or pay a fee is flagged as SCAM."""
    msg = (
        "Rs. 500 debited from A/c XX4821. Avl Bal: Rs 12,000. "
        "To cancel this transaction, click bit.ly/sbi-cancel and share your 6-digit OTP and ATM PIN immediately."
    )
    res = predict_message(msg)
    assert res.verdict == "SCAM"
    assert res.category == "KYC/Bank"
    # Safe rule S-BNK-01 must NOT suppress the suspicious credential & link rules
    fired_ids = {ind["rule_id"] for ind in res.indicators}
    assert "R-CRED-01" in fired_ids
    assert "S-BNK-01" not in fired_ids


def test_m5_contradictory_otp_warning_plus_credential_demand():
    """Verify message containing both 'Do not share OTP' AND a later credential demand triggers R-CRED-01 and NEEDS_REVIEW."""
    msg = (
        "Your OTP is 482913. Do not share it with anyone. "
        "However, to unblock your suspended KYC account, share your 6-digit OTP and ATM PIN at bit.ly/kyc-unblock"
    )
    res = predict_message(msg)
    fired_ids = {ind["rule_id"] for ind in res.indicators}
    assert "R-CRED-01" in fired_ids
    assert "S-OTP-01" in fired_ids
    assert res.verdict == "SCAM"
    assert res.review_status == "NEEDS_REVIEW"


@pytest.mark.parametrize(
    "case_name,expected_verdict,msg",
    [
        ("H1. Aapka KYC band ho jayega", "SCAM", "Aapka KYC band ho jayega. Turant link par click karke update karein."),
        ("H2. Turant account verify karein", "SCAM", "Turant account verify karein warna aapka ATM card block kar diya jayega: http://atm-verify.xyz"),
        ("H3. Pehle registration fee bhejein", "SCAM", "Pehle registration fee bhejein, ghar baithe data entry job mein pakki naukri milegi."),
        ("H4. Aapka parcel delivery ke liye ready hai", "SAFE", "Aapka parcel aaj delivery ke liye out for delivery hai, courier boy sham tak ghar pahunch jayega."),
        ("H5. Bank kabhi OTP nahi maangta", "SAFE", "Savdhan! OTP kisi ke saath share mat karna. Bank kabhi OTP nahi maangta."),
        ("H6. Kal milte hain, coffee pe chalte hain", "SAFE", "Kal milte hain, 5 baje coffee pe chalte hain."),
        ("O1. Fr33 pr1ze", "SCAM", "Claim your Fr33 pr1ze of Rs 1,00,000 now! Pay Rs 999 processing fee at bit.ly/win-free"),
        ("O2. Acc0unt bl0ck", "SCAM", "URGENT: Acc0unt bl0ck warning! Verify your PIN and O.T.P immediately."),
        ("O3. K.Y.C upd@te", "SCAM", "Dear customer, complete your K.Y.C upd@te today at http://kyc-portal.top or lose account access."),
        ("O4. Cl1ck h3re", "SCAM", "L0an appr0ved for Rs 2 Lakh! Cl1ck h3re http://fast-l0an.xyz and pay Rs 1200 file charge."),
    ],
)
def test_m5_hinglish_and_obfuscation_suite(case_name: str, expected_verdict: str, msg: str):
    """Verify Hinglish (scam & safe) and leetspeak obfuscation test suite."""
    res = predict_message(msg)
    assert res.verdict == expected_verdict, f"Failed on {case_name}: got {res.verdict}, expected {expected_verdict}"
    if expected_verdict == "SAFE":
        assert res.category is None
    else:
        assert res.category in VALID_CATEGORIES


@pytest.mark.parametrize(
    "input_label,payload,expect_valid",
    [
        ("Empty string", "", False),
        ("Whitespace only", "   \t\n  ", False),
        ("Very short input", "Hi", True),
        ("Exact max length (2000 chars)", "A" * 2000, True),
        ("Exceeding max length (2500 chars)", "Your KYC will expire today. " * 100, True),
        ("Unicode & Devanagari Hindi", "नमस्ते, आपका बैंक स्टेटमेंट तैयार है। OTP किसी को न बताएं।", True),
        ("Emojis", "🎉 Congratulations! You won Rs 25 Lakh lottery prize 💰! Pay Rs 5000 processing fee 🔥", True),
        ("Multi-line with newlines", "Line 1: Urgent Notice\nLine 2: Your KYC is suspended\nLine 3: Share OTP now", True),
        ("Special symbols", "@#$%^&*()_+-=[]{}|;':\",./<>?~`", True),
        ("HTML-like input", "<b>URGENT</b>: <a href='http://scam.xyz'>Click here</a> to update KYC", True),
        ("Script-like XSS payload", "<script>alert('xss')</script> Your OTP is 123456. Do not share it with anyone.", True),
        ("Malformed URL", "Visit http:// or https://...///bad-url/kyc to check status", True),
        ("Repeated characters", "UUUUURRRRGGGGEEEENNNTTTTT!!!!!!", True),
        ("Very long unbroken token (3000 chars)", "x" * 3000, True),
    ],
)
def test_m5_input_validation_and_security_payloads(input_label: str, payload: str, expect_valid: bool):
    """Verify boundary, Unicode, emoji, newline, HTML/XSS, malformed URL, and unbroken token inputs."""
    res = predict_message(payload)
    assert res.is_valid is expect_valid, f"Unexpected validity on {input_label}"
    if expect_valid:
        assert res.verdict in ("SCAM", "SAFE")
        if res.verdict == "SAFE":
            assert res.category is None
        if len(payload.strip()) > 2000:
            assert any("truncated" in w.lower() for w in res.warnings)

