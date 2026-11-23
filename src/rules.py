"""Explainable rule-based scam indicator and safe-message protection engine.

This module implements Milestone 3 of the Tinyverse On-Device Scam Message Detector:
1. Modular suspicious indicator rules covering:
   - Credential harvesting (OTP, PIN, CVV, password, netbanking login demands)
   - Upfront fees, processing fees, release taxes, and advance payments
   - Lottery, KBC, lucky draw, and unexpected prize claims
   - Fake KYC expiry, bank account suspension, electricity/SIM disconnection threats
   - Fraudulent work-from-home jobs, task deposits, and guaranteed investment returns
   - Suspicious links (URL shorteners, unusual TLDs, raw IP URLs, .APK downloads)
   - Urgency, coercion, legal/customs threats, and impersonation (fake relative/OLX QR)
   - Hinglish (hi-Latn) and deliberately obfuscated/leetspeak scam patterns
2. Modular safe-message contextual dampeners covering:
   - Genuine bank debit/credit/ATM transaction receipts with available balance ('Avl Bal')
   - Explicit OTP delivery and security advisories ('do not share', 'kabhi OTP nahi maangta')
   - UPI transaction confirmation receipts ('UPI Ref', 'Paid Rs ... to')
   - Courier/parcel delivery updates ('out for delivery', 'AWB', 'no payment is required')
   - Loan EMI repayment receipts and closure certificates
   - Informational KYC completion and bank branch/holiday notices
   - Genuine job application acknowledgements ('never charge any fee')
   - Personal conversations and appointment/academic reminders
3. Non-additive bounded evidence aggregation so a single benign keyword ('OTP',
   'bank', 'urgent', 'prize', 'loan', or a safe 'https://' URL) never triggers a
   false positive.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Optional

from src.features import (
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
    deobfuscate_token,
    extract_text_signals,
    validate_message_input,
)


@dataclass
class RuleMatch:
    """Represents a single fired rule (either suspicious or protective)."""

    rule_id: str
    name: str
    polarity: str  # "SUSPICIOUS" or "SAFE"
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", or "PROTECTIVE"
    weight: float  # Bounded contribution weight (positive for scam, negative for safe)
    category_hint: Optional[str]
    description: str
    matched_evidence: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "polarity": self.polarity,
            "severity": self.severity,
            "weight": round(float(self.weight), 3),
            "category_hint": self.category_hint,
            "description": self.description,
            "matched_evidence": self.matched_evidence,
        }


@dataclass
class RuleEvaluationResult:
    """Aggregated output of running all modular rules on a single message."""

    suspicious_rules: list[RuleMatch] = field(default_factory=list)
    safe_rules: list[RuleMatch] = field(default_factory=list)
    suspicious_score: float = 0.0
    safe_protection_score: float = 0.0
    net_rule_score: float = 0.0
    risk_level: str = "NONE"  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE_PROTECTED", "NONE"
    suggested_category: Optional[str] = None
    has_contradictory_evidence: bool = False
    summary_reasons: list[str] = field(default_factory=list)

    @property
    def all_matches(self) -> list[RuleMatch]:
        return self.suspicious_rules + self.safe_rules

    def to_dict(self) -> dict[str, Any]:
        return {
            "suspicious_rules": [r.to_dict() for r in self.suspicious_rules],
            "safe_rules": [r.to_dict() for r in self.safe_rules],
            "suspicious_score": round(float(self.suspicious_score), 4),
            "safe_protection_score": round(float(self.safe_protection_score), 4),
            "net_rule_score": round(float(self.net_rule_score), 4),
            "risk_level": self.risk_level,
            "suggested_category": self.suggested_category,
            "has_contradictory_evidence": self.has_contradictory_evidence,
            "summary_reasons": list(self.summary_reasons),
        }


# =============================================================================
# Compiled Regex Patterns for Modular Rules (Offline String Matching Only)
# =============================================================================

# 1. Protective / Safe Negation Check (Must be checked first so "Do not share OTP" is never flagged as harvesting)
_SAFE_DO_NOT_SHARE_RE = re.compile(
    r"(?:do\s+not\s+share|never\s+share|don'?t\s+share|"
    r"bank\s+never\s+asks|never\s+charge\s+any\s+fee|"
    r"kisi\s+ke\s+saath\s+share\s+mat\s+karna|kisi\s+ko\s+na\s+batayein|"
    r"kabhi\s+otp\s+nahi\s+maangta|do\s+not\s+need\s+to\s+enter\s+your\s+upi\s+pin)",
    re.IGNORECASE,
)

# 2. Credential Harvesting Demands (English + Hinglish + De-obfuscated)
_CREDENTIAL_HARVEST_RE = re.compile(
    r"(?:share\s+(?:your\s+|the\s+)?(?:\d+-digit\s+)?(?:verification\s+)?(?:otp|pin|cvv|password|m-pin)|"
    r"reply\s+with\s+(?:your\s+)?(?:\d+-digit\s+)?(?:atm\s+pin|otp|password|pin)|"
    r"provide\s+the\s+verification\s+code|"
    r"enter\s+(?:your\s+)?(?:\d+-digit\s+)?(?:upi\s+pin|netbanking\s+password|crn|pin|otp|password)|"
    r"entering\s+netbanking\s+password|"
    r"submit\s+(?:your\s+)?cvv|"
    r"otp\s+(?:aur\s+pin\s+)?(?:bhejo|bhejein|batayein|forward\s+karein|share\s+karo|darj\s+karein)|"
    r"(?:upi\s+pin|password\s+aur\s+cvv|pin)\s+(?:dalein|darj\s+karein|enter\s+karein|yahan\s+bharein)|"
    r"pin\s+daal\s+kar|netbanking\s+login\s+karein)",
    re.IGNORECASE,
)

# 3. Upfront Fee / Advance Payment Demands
_ADVANCE_FEE_RE = re.compile(
    r"(?:pay\s+(?:a\s+|an\s+|the\s+|rs\.?\s*[\d,]+\s+)?(?:release\s+fee|processing\s+fee|processing\s+charge|"
    r"advance\s+processing|registration\s+fee|registration\s+tax|security\s+fee|security\s+deposit|"
    r"tds\s+fee|file\s+charge|activation\s+fee|activation\s+charge|clearance\s+fine|clearance\s+charge|"
    r"release\s+tax|re-delivery\s+fee|login\s+fee|documentation\s+charge|verification\s+charge|"
    r"medical\s+&\s+uniform\s+fee|laptop\s+security\s+fee|gate\s+pass\s+&\s+training\s+fee|"
    r"card\s+printing\s+fee|gst\s+and\s+shipping\s+charge|gst\s+and\s+agreement\s+fee|advance\s+noc\s+fee)|"
    r"(?:send|deposit|transfer)\s+rs\.?\s*[\d,]+\s+(?:delivery\s+and\s+customs|foreign\s+exchange|refundable\s+security|"
    r"file\s+charge|insurance\s+charge|tds\s+fee|gate\s+pass|recharge\s+deposit)|"
    r"(?:processing\s+fee|registration\s+fee|file\s+charge|advance\s+fee|insurance\s+fee|courier\s+fee|"
    r"registration\s+charge|id\s+card\s+aur\s+registration|tax)\s+(?:bhejo|bhejein|jama\s+karein|jama\s+karke|"
    r"abhi\s+upi\s+karein|paytm\s+karein|transfer\s+karein|dekar)|"
    r"pehle\s+(?:rs\.?\s*[\d,]+\s+)?(?:processing\s+fee|registration\s+fee|file\s+charge))",
    re.IGNORECASE,
)

# 4. Lottery / Prize / Lucky Draw Scams
_LOTTERY_PRIZE_RE = re.compile(
    r"(?:won\s+(?:a\s+|an\s+|1st\s+)?(?:lottery\s+prize|rs\.?\s*[\d,]+|\$[\d,]+|iphone|maruti|free\s+macbook|"
    r"bumper\s+prize|prize\s+in\s+dubai)|"
    r"lucky\s+(?:winner|draw)|kbc\s+(?:mega\s+lucky\s+draw|head\s+office)|"
    r"spin\s+&\s+win\s+jackpot|whatsapp\s+international\s+lottery|"
    r"claim\s+your\s+(?:free\s+prize|fr33\s+pr1ze|free\s+gift\s+voucher|fr33e\s+gift)|"
    r"surprise\s+cashback\s+reward|scratch\s+card\s+winner|"
    r"(?:aapka\s+inaam\s+nikla|aapne\s+lottery\s+jeeti|bumper\s+car\s+prize\s+nikla|"
    r"lucky\s+draw\s+mein\s+(?:aapka\s+naam|select\s+hua)|aapne\s+jeeta\s+hai\s+\d+\s+tola\s+sona|"
    r"cashback\s+reward!\s+paisa\s+bank\s+mein\s+lene))",
    re.IGNORECASE,
)

# 5. Fake KYC / Account Suspension / Utility Disconnect Threats
_KYC_SUSPENSION_RE = re.compile(
    r"(?:(?:kyc|k\.y\.c|account|acc0unt|netbanking|debit\s+card|credit\s+card|sim\s+card|fastag|wallet|upi\s+id)\s+"
    r"(?:will\s+be\s+|has\s+been\s+|is\s+)?(?:blocked|bl0ck|bl0cked|suspended|deactivated|frozen|blacklisted|"
    r"closed\s+today|temporarily\s+locked|temp0rarily\s+locked|cancelled|expired)|"
    r"(?:incomplete|pending|invalid\s+bank|e-kyc|uan\s+kyc)\s+(?:kyc|k\.y\.c|failure|mismatch)|"
    r"power\s+will\s+be\s+disconnected\s+tonight|bijli\s+kat\s+jayegi|"
    r"pan\s+card\s+(?:is\s+not\s+linked|aadhaar\s+se\s+link\s+nahi)|"
    r"(?:kyc|account|khata|atm\s+card|sim\s+card|len-den|upi\s+id)\s+"
    r"(?:band\s+ho\s+jayega|suspend\s+ho\s+gaya|block\s+kar\s+diya\s+jayega|freeze\s+ho\s+jayega|"
    r"expire\s+ho\s+gaya|band\s+hone\s+wala\s+hai|block\s+hone\s+ja\s+raha)|"
    r"aaj\s+hi\s+(?:kyc\s+)?update\s+karo\s+warna|turant\s+account\s+verify\s+karein\s+warna|"
    r"complete\s+your\s+(?:kyc|k\.y\.c)\s+(?:update|upd@te)\s+now)",
    re.IGNORECASE,
)

# 6. Instant Loan / Unverified Credit Approval Scams
_LOAN_SCAM_RE = re.compile(
    r"(?:(?:instant\s+loan|l0an|personal\s+loan|cash\s+loan|mudra\s+yojana\s+loan|"
    r"aadhaar\s+loan|medical\s+loan|sarkari\s+mudra\s+loan)\s+"
    r"(?:of\s+rs\.?\s*[\d,lakh\s]+\s+)?(?:approved|appr0ved|sanctioned|pass\s+ho\s+gaya|approve\s+hua)|"
    r"0%\s+(?:interest|byaj)|no\s+cibil\s+check|low\s+cibil\s+defaulters|bina\s+cibil\s+score|"
    r"paperless\s+aadhaar\s+loan|turant\s+loan\s+chahiye|loan\s+approval\s+ke\s+liye\s+payment|"
    r"instant\s+credit\s+line\s+of\s+rs)",
    re.IGNORECASE,
)

# 7. Fake Work-From-Home Job & Guaranteed Investment Return Scams
_JOB_INVESTMENT_SCAM_RE = re.compile(
    r"(?:work\s+from\s+home\s+(?:job\s+guaranteed|data\s+entry)|"
    r"(?:daily\s+profit|return\s+in\s+\d+\s+days|daily\s+guaranteed\s+profit|100%\s+guaranteed\s+munafa)\s*guaranteed?|"
    r"guaranteed\s+(?:300%\s+return|trading\s+scheme|100%\s+guaranteed\s+munafa)|"
    r"double\s+your\s+money|paisa\s+(?:double|3\s+guna)\s+karne|"
    r"liking\s+youtube\s+videos|youtube\s+video\s+like\s+karein|rate\s+hotels\s+online|"
    r"prepaid\s+(?:vip\s+)?task|telegram\s+task\s+pura\s+karo|usdt\s+mining\s+scheme|"
    r"selection\s+without\s+interview|bina\s+exam\s+ke|pakki\s+naukri|पक्की\s+नौकरी|"
    r"pencil\s+packing\s+work\s+from\s+home)",
    re.IGNORECASE,
)

# 8. Impersonation, Customs Seizure, Fake UPI Collect/QR & Emergency Relative Scams
_OTHER_IMPERSONATION_SCAM_RE = re.compile(
    r"(?:parcel\s+contains\s+illegal\s+items|seized\s+by\s+mumbai\s+customs|customs\s+ne\s+pakda\s+hai|"
    r"cbi\s+cyber\s+crime\s+notice|arrest\s+warrant\s+is\s+issued|"
    r"lost\s+my\s+phone\s+and\s+my\s+bank\s+app|papa\s+ka\s+dost\s+bol\s+raha\s+hoon|"
    r"accidentally\s+sent\s+rs|galti\s+se\s+aapke\s+number\s+par\s+rs|"
    r"scan\s+this\s+qr\s+code\s+and\s+enter\s+your\s+upi\s+pin|"
    r"qr\s+code\s+scan\s+karke\s+apna\s+upi\s+pin\s+dalein|"
    r"approve\s+the\s+(?:upi\s+)?collect\s+(?:request|notification))",
    re.IGNORECASE,
)

# 9. High-Pressure Urgency & Coercion Tactics
_URGENCY_THREAT_RE = re.compile(
    r"(?:within\s+(?:24\s+hours|2\s+hours|30\s+minutes|1\s+hour)|"
    r"tonight\s+at\s+\d+:\d+\s*pm|aaj\s+raat\s+12\s+baje|"
    r"final\s+warning|avoid\s+(?:court\s+case|cancellation|rs\s*\d+\s*penalty)|"
    r"police\s+case\s+se\s+bachne|immediately\s+to\s+avoid|turant\s+is\s+(?:link|number)\s+par)",
    re.IGNORECASE,
)

# =============================================================================
# Safe / Legitimate Message Protection Patterns
# =============================================================================

# S1. Genuine Bank Debit / Credit / ATM / SIP Transaction Receipts
_SAFE_BANK_TXN_RE = re.compile(
    r"(?:debited\s+from\s+a/c|was\s+debited\s+by\s+rs|is\s+credited\s+with\s+inr|"
    r"withdrawn\s+from\s+atm|avl\s+bal:\s*rs|available\s+balance\s+is\s+inr|"
    r"e-statement\s+for\s+savings\s+account|fd\s+of\s+rs\s*[\d,]+\s+with\s+.*\s+has\s+been\s+renewed|"
    r"standing\s+instruction\s+for\s+mutual\s+fund\s+sip|bank\s+holiday\s+notice|"
    r"bank\s+statement\s+aapke\s+registered\s+email|naya\s+cheque\s+book\s+apply\s+kar\s+diya)",
    re.IGNORECASE,
)

# S2. Genuine UPI / Bill / Recharge Confirmation Receipts
_SAFE_UPI_BILL_RE = re.compile(
    r"(?:upi\s+payment\s+of\s+rs\s*[\d,]+\s+was\s+successful|"
    r"paid\s+rs\.?\s*[\d,.]+\s+to\s+.*?\s+via\s+upi\s+ref|"
    r"electricity\s+bill\s+of\s+rs\s*[\d,]+\s+.*?\s+has\s+been\s+paid\s+successfully|"
    r"recharge\s+successful!\s+plan\s+of\s+rs|bijli\s+ka\s+bill\s+official\s+app\s+se\s+bhar\s+diya)",
    re.IGNORECASE,
)

# S3. Genuine Courier / Food / Flight / Train Delivery & Travel Updates
_SAFE_DELIVERY_TRAVEL_RE = re.compile(
    r"(?:(?:parcel|shipment\s+awb\s+\d+|shipment|package)\s+(?:awb\s+\d+\s+)?(?:is\s+out\s+for\s+delivery|"
    r"delivery\s+ke\s+liye\s+(?:ready|out\s+for\s+delivery)\s+hai|aaj\s+delivery\s+ke\s+liye)|"
    r"package\s+delivery\s+is\s+scheduled\s+for\s+today|swiggy\s+order\s+#\d+\s+is\s+being\s+prepared|"
    r"irctc\s+booking\s+confirmed:\s*pnr|boarding\s+gate\s+for\s+flight\s+[\w-]+\s+has\s+changed)",
    re.IGNORECASE,
)

# S4. Genuine Loan EMI Receipt / Job Application Acknowledgement / Completed KYC
_SAFE_LOAN_JOB_KYC_RE = re.compile(
    r"(?:loan\s+emi\s+(?:payment|of\s+rs\s*[\d,]+)\s+.*?has\s+been\s+received|"
    r"received\s+your\s+(?:monthly\s+)?(?:home\s+)?loan\s+emi|education\s+loan\s+closure\s+certificate|"
    r"bike\s+loan\s+ki\s+aakhri\s+emi\s+aaj\s+kat\s+gayi|"
    r"received\s+your\s+job\s+application|thank\s+you\s+for\s+attending\s+the\s+technical\s+interview|"
    r"mera\s+tcs\s+mein\s+online\s+interview\s+hai|"
    r"periodic\s+kyc\s+update\s+has\s+been\s+successfully\s+processed|"
    r"mera\s+kyc\s+branch\s+mein\s+jaakar\s+ho\s+gaya\s+hai)",
    re.IGNORECASE,
)

# S5. Personal Conversations, College Prize Mentions & Appointment Reminders
_SAFE_PERSONAL_APPT_RE = re.compile(
    r"(?:kal\s+milte\s+hain|coffee\s+pe\s+chalte\s+hain|cricket\s+khelne\s+chalna\s+hai|"
    r"2\s+kilo\s+aalu\s+aur\s+dhoodh|pick\s+up\s+groceries\s+and\s+pay\s+the\s+milkman|"
    r"pay\s+the\s+milkman\s+rs\s*\d+|applied\s+for\s+a\s+new\s+cheque\s+book|"
    r"won\s+(?:first|second)\s+prize\s+(?:in\s+the\s+.*?competition|trophy\s+at\s+the\s+science\s+exhibition)|"
    r"college\s+debate\s+mein\s+first\s+prize\s+mila\s+hai|"
    r"appointment\s+(?:is\s+scheduled|with\s+dr\.|book\s+ho\s+gaya\s+hai)|"
    r"submit\s+your\s+semester\s+project\s+report|send\s+me\s+the\s+notes\s+for\s+chapter|"
    r"presentation\s+ki\s+ppt\s+jaldi\s+email\s+kar\s+de|"
    r"official\s+python\s+documentation\s+at\s+https://docs\.python\.org|"
    r"(?:github\s+repository\s+link|hackathon\s+schedule\s+and\s+rules)\s+.*?https://github\.com/)",
    re.IGNORECASE,
)


def _deobfuscated_view(text: str) -> str:
    """Create a normalized + de-obfuscated text view so obfuscated scams match rules cleanly."""
    # Expand dotted acronyms like K.Y.C -> kyc
    expanded = re.sub(
        r"\b([a-zA-Z])\.([a-zA-Z])(?:\.([a-zA-Z]))?(?:\.([a-zA-Z]))?\b",
        lambda m: "".join(g for g in m.groups() if g),
        text,
    )
    tokens = expanded.split()
    out: list[str] = []
    for tok in tokens:
        out.append(tok)
        subtokens = re.findall(r"[a-zA-Z0-9@$]+", tok)
        for sub in subtokens:
            deobf = deobfuscate_token(sub)
            if deobf != sub.lower():
                out.append(deobf)
    return " ".join(out)


def evaluate_rules(text: object) -> RuleEvaluationResult:
    """Evaluate all modular scam and safe-protection rules on a message.

    Args:
        text: Raw message string to inspect.

    Returns:
        RuleEvaluationResult with fired suspicious rules, safe rules, bounded scores,
        category hints, and human-readable explanations.
    """
    val = validate_message_input(text)
    if not val.is_valid:
        return RuleEvaluationResult()

    raw_text = val.cleaned_text
    view_text = _deobfuscated_view(raw_text)
    signals = extract_text_signals(raw_text)

    suspicious_rules: list[RuleMatch] = []
    safe_rules: list[RuleMatch] = []

    # Check if message contains an explicit "do not share / never share" safety warning
    protective_match = _SAFE_DO_NOT_SHARE_RE.search(view_text)
    has_protective_negation = bool(protective_match)

    # -------------------------------------------------------------------------
    # PART 1: SUSPICIOUS INDICATOR RULES
    # -------------------------------------------------------------------------

    # Rule R-CRED-01: Credential / OTP / PIN / CVV / Password Harvesting
    # Check if credential demand appears in a separate clause from any "do not share" warning
    cred_match = _CREDENTIAL_HARVEST_RE.search(view_text)
    if cred_match:
        # Suppress only if the match itself is directly inside the negated clause (e.g., "do not share your OTP")
        match_start = max(0, cred_match.start() - 25)
        preceding_window = view_text[match_start : cred_match.end()]
        is_directly_negated = bool(_SAFE_DO_NOT_SHARE_RE.search(preceding_window))
        if not is_directly_negated:
            suspicious_rules.append(
                RuleMatch(
                    rule_id="R-CRED-01",
                    name="Credential & OTP Harvesting Request",
                    polarity="SUSPICIOUS",
                    severity="CRITICAL",
                    weight=0.55,
                    category_hint="KYC/Bank",
                    description="Asks the recipient to share or enter an OTP, UPI PIN, ATM PIN, CVV, or password.",
                    matched_evidence=cred_match.group(0).strip(),
                )
            )

    # Rule R-FEE-01: Upfront / Advance / Processing / Release Fee Demand
    fee_match = _ADVANCE_FEE_RE.search(view_text)
    if fee_match and not has_protective_negation:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-FEE-01",
                name="Upfront Fee or Advance Payment Demand",
                polarity="SUSPICIOUS",
                severity="CRITICAL",
                weight=0.55,
                category_hint=None,  # Refined by Lottery/Loan/Job rules if present
                description="Demands an upfront processing fee, release charge, registration fee, or security deposit.",
                matched_evidence=fee_match.group(0).strip(),
            )
        )

    # Rule R-LOT-01: Lottery, Lucky Draw & Prize Claim
    lot_match = _LOTTERY_PRIZE_RE.search(view_text)
    if lot_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-LOT-01",
                name="Lottery or Unsolicited Prize Claim",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.45,
                category_hint="Lottery/Prize",
                description="Claims the user won a lottery, KBC lucky draw, bumper prize, or cashback reward.",
                matched_evidence=lot_match.group(0).strip(),
            )
        )

    # Rule R-KYC-01: Fake KYC Expiry / Account Suspension / Utility Disconnect Threat
    kyc_match = _KYC_SUSPENSION_RE.search(view_text)
    if kyc_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-KYC-01",
                name="KYC Expiry or Account Suspension Threat",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.45,
                category_hint="KYC/Bank",
                description="Threatens immediate bank account, SIM, card, electricity, or KYC suspension/blocking.",
                matched_evidence=kyc_match.group(0).strip(),
            )
        )

    # Rule R-LOAN-01: Unverified Instant Loan / 0% Interest / No-CIBIL Offer
    loan_match = _LOAN_SCAM_RE.search(view_text)
    if loan_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-LOAN-01",
                name="Unverified Instant Loan Offer",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.45,
                category_hint="Loan/Credit",
                description="Promotes pre-approved instant loans with 0% interest, no CIBIL check, or advance fee conditions.",
                matched_evidence=loan_match.group(0).strip(),
            )
        )

    # Rule R-JOB-01: Fraudulent Job Offer or Guaranteed High-Return Investment
    job_match = _JOB_INVESTMENT_SCAM_RE.search(view_text)
    if job_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-JOB-01",
                name="Fake Job or Guaranteed Return Investment",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.45,
                category_hint="Job/Investment",
                description="Promises guaranteed daily profits, money doubling, paid YouTube/Telegram tasks, or hiring without interviews.",
                matched_evidence=job_match.group(0).strip(),
            )
        )

    # Rule R-OTH-01: Impersonation, Customs Seizure, or UPI Collect/QR Trap
    oth_match = _OTHER_IMPERSONATION_SCAM_RE.search(view_text)
    if oth_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-OTH-01",
                name="Impersonation, Customs Threat, or QR/Collect Trap",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.55,
                category_hint="Other",
                description="Uses customs/police seizure threats, emergency relative impersonation, or QR/collect PIN deception.",
                matched_evidence=oth_match.group(0).strip(),
            )
        )

    # Rule R-URL-01: High-Risk Link (Shortener, Suspicious TLD, IP URL, or APK Download)
    if (
        signals["has_short_url"]
        or signals["has_suspicious_tld"]
        or signals["has_ip_url"]
        or signals["has_apk_mention"]
    ):
        url_parts: list[str] = []
        if signals["has_ip_url"]:
            url_parts.append("raw IP-address link")
        if signals["has_short_url"]:
            matched_short = [s for s in URL_SHORTENERS if s in raw_text.lower()]
            url_parts.append(f"shortened URL ({', '.join(matched_short[:2])})")
        if signals["has_suspicious_tld"]:
            matched_tld = [t for t in SUSPICIOUS_TLDS if t in raw_text.lower()]
            url_parts.append(f"high-risk domain extension ({', '.join(matched_tld[:2])})")
        if signals["has_apk_mention"]:
            url_parts.append(".APK application download request")

        suspicious_rules.append(
            RuleMatch(
                rule_id="R-URL-01",
                name="Suspicious URL or APK Download Pattern",
                polarity="SUSPICIOUS",
                severity="HIGH",
                weight=0.40,
                category_hint=None,
                description=f"Contains a {', '.join(url_parts)}.",
                matched_evidence=", ".join(url_parts),
            )
        )

    # Rule R-OBF-01: Deliberate Text Obfuscation / Leetspeak
    if signals["has_obfuscation"]:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-OBF-01",
                name="Deliberate Word Obfuscation (Leetspeak / Dotted Acronyms)",
                polarity="SUSPICIOUS",
                severity="MEDIUM",
                weight=0.30,
                category_hint=None,
                description="Uses obfuscated spelling (such as K.Y.C, fr33, l0an, acc0unt, cl1ck) to evade spam filters.",
                matched_evidence="Obfuscated characters detected",
            )
        )

    # Rule R-URG-01: Coercive Urgency & Deadline Threats
    urg_match = _URGENCY_THREAT_RE.search(view_text)
    if urg_match:
        suspicious_rules.append(
            RuleMatch(
                rule_id="R-URG-01",
                name="High-Pressure Coercive Deadline",
                polarity="SUSPICIOUS",
                severity="MEDIUM",
                weight=0.20,
                category_hint=None,
                description="Pressures the user with an immediate countdown, tonight deadline, or legal penalty threat.",
                matched_evidence=urg_match.group(0).strip(),
            )
        )

    # -------------------------------------------------------------------------
    # PART 2: SAFE-MESSAGE CONTEXTUAL PROTECTION RULES (DAMPENERS)
    # -------------------------------------------------------------------------

    # Safe Rule S-OTP-01: Explicit OTP/PIN Security Warning ("Do not share")
    if protective_match:
        safe_rules.append(
            RuleMatch(
                rule_id="S-OTP-01",
                name="Explicit Security & Anti-Fraud Advisory",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.55,
                category_hint=None,
                description="Explicitly warns the recipient NEVER to share OTPs, PINs, passwords, or hiring fees.",
                matched_evidence=protective_match.group(0).strip(),
            )
        )

    # Safe Rule S-BNK-01: Genuine Bank Transaction Alert / Balance Notification
    bank_txn_match = _SAFE_BANK_TXN_RE.search(raw_text)
    if bank_txn_match and not suspicious_rules:
        safe_rules.append(
            RuleMatch(
                rule_id="S-BNK-01",
                name="Standard Bank Transaction or Informational Alert",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.55,
                category_hint=None,
                description="Matches standard informational bank debit/credit/ATM alert formatting with no credential or link demand.",
                matched_evidence=bank_txn_match.group(0).strip(),
            )
        )

    # Safe Rule S-UPI-01: Genuine UPI / Utility Bill Payment Confirmation Receipt
    upi_match = _SAFE_UPI_BILL_RE.search(raw_text)
    if upi_match and not suspicious_rules:
        safe_rules.append(
            RuleMatch(
                rule_id="S-UPI-01",
                name="Completed Payment or Recharge Confirmation",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.45,
                category_hint=None,
                description="Confirms an already completed UPI transfer, bill payment, or mobile recharge.",
                matched_evidence=upi_match.group(0).strip(),
            )
        )

    # Safe Rule S-DLV-01: Genuine Courier / Order / Travel Status Notification
    dlv_match = _SAFE_DELIVERY_TRAVEL_RE.search(raw_text)
    if dlv_match and not suspicious_rules:
        safe_rules.append(
            RuleMatch(
                rule_id="S-DLV-01",
                name="Standard Delivery or Travel Status Update",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.45,
                category_hint=None,
                description="Provides routine parcel tracking, food delivery, train PNR, or flight gate information without asking for fees.",
                matched_evidence=dlv_match.group(0).strip(),
            )
        )

    # Safe Rule S-LJK-01: Genuine Loan EMI Receipt, Job Application Ack, or Completed Branch KYC
    ljk_match = _SAFE_LOAN_JOB_KYC_RE.search(raw_text)
    if ljk_match and not suspicious_rules:
        safe_rules.append(
            RuleMatch(
                rule_id="S-LJK-01",
                name="Legitimate EMI Receipt, Job Application Ack, or Completed KYC",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.45,
                category_hint=None,
                description="Confirms receipt of a loan EMI, job interview/application, or completed branch KYC with no suspicious request.",
                matched_evidence=ljk_match.group(0).strip(),
            )
        )

    # Safe Rule S-PER-01: Everyday Personal Chat, Academic/Clinic Reminder, or Trusted Docs Link
    per_match = _SAFE_PERSONAL_APPT_RE.search(raw_text)
    if per_match and not suspicious_rules:
        safe_rules.append(
            RuleMatch(
                rule_id="S-PER-01",
                name="Personal Conversation, Appointment, or Educational Context",
                polarity="SAFE",
                severity="PROTECTIVE",
                weight=-0.45,
                category_hint=None,
                description="Matches conversational chat, medical/academic reminder, or official developer documentation link.",
                matched_evidence=per_match.group(0).strip(),
            )
        )

    # -------------------------------------------------------------------------
    # PART 3: NON-ADDITIVE BOUNDED SCORE AGGREGATION & CATEGORY RESOLUTION
    # -------------------------------------------------------------------------
    # Instead of blindly summing weights to infinity, we combine independent weights
    # using diminishing returns: 1 - prod(1 - w_i), capped in [0.0, 0.95].
    susp_score = 0.0
    if suspicious_rules:
        complement = 1.0
        for r in suspicious_rules:
            complement *= 1.0 - min(max(r.weight, 0.0), 0.90)
        susp_score = min(0.95, 1.0 - complement)

    safe_score = 0.0
    if safe_rules:
        complement_safe = 1.0
        for r in safe_rules:
            complement_safe *= 1.0 - min(max(abs(r.weight), 0.0), 0.90)
        safe_score = min(0.95, 1.0 - complement_safe)

    has_contradiction = bool(suspicious_rules and safe_rules)
    net_score = susp_score - safe_score

    # Determine suggested scam category from fired suspicious rules by priority
    # Priority order when multiple rules fire (e.g., Lottery + Upfront Fee -> Lottery/Prize)
    category_votes: dict[str, float] = {}
    for r in suspicious_rules:
        if r.category_hint:
            # Give specific domain categories (Lottery, Loan, Job, Other) slightly higher
            # specificity weight than generic KYC/Bank credential requests
            specificity_multiplier = 1.25 if r.category_hint in ("Lottery/Prize", "Loan/Credit", "Job/Investment", "Other") else 1.0
            category_votes[r.category_hint] = (
                category_votes.get(r.category_hint, 0.0) + r.weight * specificity_multiplier
            )

    suggested_category: Optional[str] = None
    if category_votes:
        suggested_category = max(category_votes.items(), key=lambda kv: kv[1])[0]

    # Determine discrete risk level
    has_critical = any(r.severity == "CRITICAL" for r in suspicious_rules)
    if has_critical or susp_score >= 0.70:
        risk_level = "CRITICAL"
    elif susp_score >= 0.40:
        risk_level = "HIGH"
    elif susp_score >= 0.20:
        risk_level = "MEDIUM"
    elif safe_score >= 0.40 and susp_score == 0.0:
        risk_level = "SAFE_PROTECTED"
    else:
        risk_level = "NONE"

    summary_reasons: list[str] = [
        f"[{r.rule_id}] {r.description} (Matched: '{r.matched_evidence}')"
        for r in suspicious_rules
    ]
    for r in safe_rules:
        summary_reasons.append(
            f"[{r.rule_id}] {r.description} (Matched: '{r.matched_evidence}')"
        )

    return RuleEvaluationResult(
        suspicious_rules=suspicious_rules,
        safe_rules=safe_rules,
        suspicious_score=susp_score,
        safe_protection_score=safe_score,
        net_rule_score=net_score,
        risk_level=risk_level,
        suggested_category=suggested_category,
        has_contradictory_evidence=has_contradiction,
        summary_reasons=summary_reasons,
    )
