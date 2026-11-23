"""Feature extraction, input validation, and safe text normalization module.

This module implements:
1. Input validation and safe length bounding (MAX_MESSAGE_LENGTH = 2000).
2. Unicode NFKC normalization and zero-width obfuscation stripping.
3. Dotted acronym compaction (e.g., 'K.Y.C' -> 'kyc', 'O.T.P' -> 'otp').
4. Targeted leetspeak de-obfuscation (e.g., 'fr33' -> 'free', 'l0an' -> 'loan',
   'acc0unt' -> 'account', 'cl1ck' -> 'click', 'upd@te' -> 'update').
5. Structural token tagging for URLs, shorteners, suspicious TLDs, and
   legitimate protective warnings ('do not share', 'kisi ke saath share mat karna').
6. Combined Word + Character-WB TF-IDF FeatureUnion builder.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import FeatureUnion

# Maximum characters allowed per message to prevent algorithmic/memory abuse
MAX_MESSAGE_LENGTH: int = 2000

# Suspicious top-level domains frequently abused in Indian SMS/WhatsApp phishing
SUSPICIOUS_TLDS: tuple[str, ...] = (
    ".xyz",
    ".top",
    ".club",
    ".site",
    ".online",
    ".click",
    ".loan",
    ".work",
    ".vip",
    ".buzz",
)

# Common URL shorteners and redirectors used in SMS/WhatsApp campaigns
URL_SHORTENERS: tuple[str, ...] = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "rb.gy",
    "cutt.ly",
    "t.me",
    "shorturl.at",
    "tiny.cc",
)

# Zero-width and invisible formatting characters used to evade keyword filters
_ZERO_WIDTH_RE = re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")

# Dotted acronym pattern such as K.Y.C, O.T.P, U.P.I, P.I.N
_DOTTED_ACRONYM_RE = re.compile(r"\b([a-zA-Z])\.([a-zA-Z])(?:\.([a-zA-Z]))?(?:\.([a-zA-Z]))?\b")

# General URL or domain-with-path pattern (offline regex only; never visited)
_URL_RE = re.compile(
    r"(?:https?://[^\s]+|\b(?:bit\.ly|tinyurl\.com|t\.me|is\.gd|rb\.gy|cutt\.ly)/[^\s]+|"
    r"\b[a-zA-Z0-9-]+\.(?:xyz|top|club|site|online|click|loan|work|vip)\b[^\s]*)",
    re.IGNORECASE,
)

# IPv4 URL pattern such as http://192.168.10.45/axis-pan
_IP_URL_RE = re.compile(r"https?://\d{1,3}(?:\.\d{1,3}){3}[^\s]*", re.IGNORECASE)

# APK download mention pattern
_APK_RE = re.compile(r"\bapk\b|\.apk\b", re.IGNORECASE)

# Currency / money mention pattern (Rs, INR, Lakh, $, ₹)
_CURRENCY_RE = re.compile(
    r"(?:\brs\.?\s*\d+|\binr\s*\d+|₹\s*\d+|\$\s*\d+|\b\d+\s*(?:lakh|lakhs|crore)\b)",
    re.IGNORECASE,
)

# Explicit protective warning phrases found in genuine bank/OTP notifications
_PROTECTIVE_WARNING_RE = re.compile(
    r"(?:do\s+not\s+share|never\s+share|don'?t\s+share|"
    r"bank\s+never\s+asks|never\s+charge\s+any\s+fee|"
    r"kisi\s+ke\s+saath\s+share\s+mat\s+karna|kisi\s+ko\s+na\s+batayein|"
    r"kabhi\s+otp\s+nahi\s+maangta|no\s+further\s+action\s+is\s+required|"
    r"no\s+payment\s+is\s+required)",
    re.IGNORECASE,
)

# Direct credential or advance fee harvesting phrases
_HARVEST_DEMAND_RE = re.compile(
    r"(?:share\s+(?:your\s+)?(?:\d+-digit\s+)?(?:otp|pin|cvv|password)|"
    r"enter\s+(?:your\s+)?(?:\d+-digit\s+)?(?:upi\s+pin|netbanking\s+password|pin|otp)|"
    r"submit\s+cvv|otp\s+bhejo|otp\s+bhejein|otp\s+batayein|otp\s+forward\s+karein|"
    r"pin\s+dalein|pin\s+darj\s+karein|pin\s+enter\s+karein|"
    r"pay\s+(?:a\s+|an\s+)?(?:release\s+fee|processing\s+fee|advance\s+processing|registration\s+fee|security\s+fee|tds\s+fee|file\s+charge|activation\s+fee|clearance\s+fine)|"
    r"processing\s+fee\s+bhejo|registration\s+fee\s+bhejo|registration\s+fee\s+bhejein|"
    r"file\s+charge\s+abhi|advance\s+fee)",
    re.IGNORECASE,
)

# Known explicit leetspeak / obfuscated dictionary for exact canonical recovery
_KNOWN_OBFUSCATIONS: dict[str, str] = {
    "fr33": "free",
    "fr33e": "free",
    "pr1ze": "prize",
    "l0an": "loan",
    "appr0ved": "approved",
    "acc0unt": "account",
    "bl0ck": "block",
    "bl0cked": "blocked",
    "cl1ck": "click",
    "h3re": "here",
    "upd@te": "update",
    "b@nk": "bank",
    "c0ngratulati0ns": "congratulations",
    "temp0rarily": "temporarily",
    "upgrde": "upgrade",
    "k.y.c": "kyc",
    "o.t.p": "otp",
}

# Character translation table for mixed alphanumeric leetspeak tokens
_LEET_MAP = str.maketrans(
    {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "@": "a",
        "$": "s",
    }
)


@dataclass
class InputValidationResult:
    """Result of validating and bounding raw message input."""

    is_valid: bool
    cleaned_text: str
    warnings: list[str] = field(default_factory=list)
    error_message: Optional[str] = None


def validate_message_input(
    text: object,
    max_length: int = MAX_MESSAGE_LENGTH,
) -> InputValidationResult:
    """Validate that input is a non-empty string and bound its maximum length.

    Args:
        text: Raw input object supplied by caller or UI.
        max_length: Maximum character length allowed before safe truncation.

    Returns:
        InputValidationResult indicating validity, cleaned text, and any warnings.
    """
    if text is None or not isinstance(text, str):
        return InputValidationResult(
            is_valid=False,
            cleaned_text="",
            warnings=["Input must be a valid text string."],
            error_message="Invalid input type: expected a text string.",
        )

    # Strip invisible zero-width chars and surrounding whitespace
    cleaned = _ZERO_WIDTH_RE.sub("", text).strip()
    if not cleaned:
        return InputValidationResult(
            is_valid=False,
            cleaned_text="",
            warnings=["Message input is empty. Please paste an SMS or WhatsApp message."],
            error_message="Message input cannot be empty or whitespace only.",
        )

    warnings: list[str] = []
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length]
        warnings.append(
            f"Message exceeded the maximum safe length of {max_length} characters "
            f"and was truncated for local processing."
        )

    return InputValidationResult(
        is_valid=True,
        cleaned_text=cleaned,
        warnings=warnings,
        error_message=None,
    )


def deobfuscate_token(token: str) -> str:
    """Recover standard English words from leetspeak/obfuscated tokens.

    Preserves legitimate alphanumeric tokens like flight numbers ('6e-204'),
    masked accounts ('xx4821'), and ordinals ('1st', '4g', '5g').

    Args:
        token: A single whitespace-delimited token (lowercased).

    Returns:
        De-obfuscated alphabetic word if obfuscation was detected, else original token.
    """
    clean_tok = token.strip(".,!?:;()[]{}\"'")
    lower_tok = clean_tok.lower()

    if lower_tok in _KNOWN_OBFUSCATIONS:
        return _KNOWN_OBFUSCATIONS[lower_tok]

    # Do not alter short ordinals/generations like 1st, 2nd, 3rd, 4g, 5g, xx4821
    if re.fullmatch(r"(?:\d+(?:st|nd|rd|th|g|gb|am|pm)|xx\d+|s1ac\d+|ln\d+)", lower_tok):
        return lower_tok

    # Check if token mixes letters with leet digits/symbols inside a word stem
    # Ignore UPI handles / emails containing '@' between two alphabetic names (e.g., swiggy@axisbank)
    if "@" in lower_tok and re.fullmatch(r"[a-z0-9._-]+@[a-z0-9._-]+", lower_tok):
        left, right = lower_tok.split("@", 1)
        if len(left) >= 2 and len(right) >= 3:
            return lower_tok

    has_alpha = any(ch.isalpha() for ch in lower_tok)
    has_leet_char = any(ch in "01345@$" for ch in lower_tok)
    if has_alpha and has_leet_char and len(lower_tok) >= 4:
        # Ensure at least half the characters are alphabetic so codes like a1b234 are ignored
        alpha_count = sum(1 for ch in lower_tok if ch.isalpha())
        if alpha_count >= len(lower_tok) / 2:
            candidate = lower_tok.translate(_LEET_MAP)
            if candidate in _KNOWN_OBFUSCATIONS.values():
                return candidate

    return lower_tok


def extract_text_signals(text: str) -> dict[str, bool]:
    """Extract structural boolean signals from raw or normalized message text.

    Never opens or visits URLs; strictly inspects string patterns locally.
    """
    if not isinstance(text, str) or not text.strip():
        return {
            "has_url": False,
            "has_short_url": False,
            "has_suspicious_tld": False,
            "has_ip_url": False,
            "has_apk_mention": False,
            "has_obfuscation": False,
            "has_currency": False,
            "has_protective_warning": False,
            "has_harvest_demand": False,
        }

    lower_text = text.lower()
    has_url = bool(_URL_RE.search(lower_text))
    has_short_url = any(short in lower_text for short in URL_SHORTENERS)
    has_suspicious_tld = any(tld in lower_text for tld in SUSPICIOUS_TLDS)
    has_ip_url = bool(_IP_URL_RE.search(lower_text))
    has_apk_mention = bool(_APK_RE.search(lower_text))
    has_currency = bool(_CURRENCY_RE.search(lower_text))
    has_protective_warning = bool(_PROTECTIVE_WARNING_RE.search(lower_text))
    has_harvest_demand = bool(_HARVEST_DEMAND_RE.search(lower_text))

    # Check for dotted acronyms (K.Y.C) or leetspeak tokens
    has_dotted = bool(_DOTTED_ACRONYM_RE.search(text))
    words = re.findall(r"[a-zA-Z0-9@$]+", lower_text)
    has_leet = any(deobfuscate_token(w) != w.lower() for w in words)

    return {
        "has_url": has_url,
        "has_short_url": has_short_url,
        "has_suspicious_tld": has_suspicious_tld,
        "has_ip_url": has_ip_url,
        "has_apk_mention": has_apk_mention,
        "has_obfuscation": has_dotted or has_leet,
        "has_currency": has_currency,
        "has_protective_warning": has_protective_warning,
        "has_harvest_demand": has_harvest_demand,
    }


def normalize_text(text: str, include_structural_tags: bool = True) -> str:
    """Normalize raw message text while preserving fraud and obfuscation signals.

    Steps:
    1. Apply Unicode NFKC normalization and remove invisible zero-width characters.
    2. Compact dotted acronyms (e.g., 'K.Y.C' -> 'K.Y.C kyc') so both raw character
       patterns and clean words are available to TF-IDF.
    3. Append de-obfuscated companion words for leetspeak tokens (e.g., 'fr33' -> 'fr33 free').
    4. Lowercase and collapse repeated whitespace.
    5. Optionally append structural tags (__short_url__, __protective_warning__, etc.).
    """
    if not isinstance(text, str):
        return ""

    # 1. Unicode NFKC + strip invisible characters
    norm = unicodedata.normalize("NFKC", text)
    norm = _ZERO_WIDTH_RE.sub("", norm)

    # Extract structural signals before modifying punctuation
    signals = extract_text_signals(norm)

    # 2. Expand dotted acronyms: "K.Y.C" -> "K.Y.C kyc"
    def _expand_dotted(match: re.Match[str]) -> str:
        letters = [g for g in match.groups() if g is not None]
        compacted = "".join(letters).lower()
        return f"{match.group(0)} {compacted}"

    norm = _DOTTED_ACRONYM_RE.sub(_expand_dotted, norm)

    # 3. Lowercase and append de-obfuscated companion tokens
    norm = norm.lower()
    raw_tokens = norm.split()
    enriched_tokens: list[str] = []
    for tok in raw_tokens:
        enriched_tokens.append(tok)
        clean_subtokens = re.findall(r"[a-z0-9@$]+", tok)
        for sub in clean_subtokens:
            deobf = deobfuscate_token(sub)
            if deobf != sub and deobf not in enriched_tokens:
                enriched_tokens.append(deobf)

    # 4. Append structural meta-tokens if enabled
    if include_structural_tags:
        if signals["has_url"]:
            enriched_tokens.append("__has_url__")
        if signals["has_short_url"]:
            enriched_tokens.append("__short_url__")
        if signals["has_suspicious_tld"]:
            enriched_tokens.append("__suspicious_tld__")
        if signals["has_ip_url"]:
            enriched_tokens.append("__ip_url__")
        if signals["has_apk_mention"]:
            enriched_tokens.append("__apk_file__")
        if signals["has_obfuscation"]:
            enriched_tokens.append("__obfuscated_text__")
        if signals["has_currency"]:
            enriched_tokens.append("__currency_amount__")
        if signals["has_protective_warning"]:
            # Repeat protective tag to ensure negative/safe weight is well-represented
            enriched_tokens.extend(["__protective_warning__", "__protective_warning__"])
        if signals["has_harvest_demand"]:
            enriched_tokens.extend(["__harvest_demand__", "__harvest_demand__"])

    normalized = " ".join(enriched_tokens)
    normalized = re.sub(r"\s+", " ", normalized).strip()
    return normalized


def build_feature_vectorizer(
    word_max_features: int = 3000,
    char_max_features: int = 4000,
) -> FeatureUnion:
    """Create the combined Word TF-IDF + Character-WB TF-IDF FeatureUnion.

    Word TF-IDF (1-2 n-grams) captures semantic words and two-word phrases
    ('share otp', 'processing fee', 'do not').
    Character TF-IDF (char_wb, 3-5 n-grams) captures subword stems across
    Hinglish spelling variations and obfuscated strings.
    """
    word_vectorizer = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        min_df=1,
        max_features=word_max_features,
        sublinear_tf=True,
        token_pattern=r"(?u)\b\w[\w.@$-]+\b|__[a-z_]+__",
    )

    char_vectorizer = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        min_df=2,
        max_features=char_max_features,
        sublinear_tf=True,
    )

    return FeatureUnion(
        transformer_list=[
            ("word_tfidf", word_vectorizer),
            ("char_tfidf", char_vectorizer),
        ]
    )
