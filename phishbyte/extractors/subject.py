"""
phishbyte/extractors/subject.py
Layer 1 — Subject-line scorer.
NEW module added after CEAS-2008 evaluation showed subject was unused.

Phishing subjects have measurable patterns that distinguish them from legit
emails: urgency words, currency mentions, fake reply prefixes, all-caps shouting,
account/security/verification themes, fake transaction IDs.
"""

import re
import email
from typing import Dict, Any


_SUBJECT_URGENCY = [
    "urgent", "immediate", "immediately", "action required", "action needed",
    "asap", "now", "today", "expire", "expiring", "expired", "deadline",
    "final notice", "last warning", "limited time", "act fast", "hurry",
    "alert", "important", "critical", "warning", "attention",
]

_SUBJECT_SECURITY_THEME = [
    "verify", "verification", "confirm", "validate", "authenticate",
    "suspended", "locked", "blocked", "disabled", "restricted",
    "security", "compromised", "unauthorized", "suspicious activity",
    "unusual sign-in", "login attempt", "password",
    "account", "billing", "payment", "invoice", "refund",
    "update required", "re-activate", "reactivate", "restore access",
]

_SUBJECT_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "bank", "chase", "wells fargo", "citi", "hsbc", "barclays",
    "facebook", "instagram", "linkedin", "twitter", "whatsapp",
    "fedex", "ups", "dhl", "usps", "ebay", "walmart",
    "office365", "outlook", "gmail", "icloud", "dropbox",
    "irs", "hmrc", "tax", "social security",
]

_FAKE_TRANSACTION_PATTERNS = [
    r'\b(?:transaction|order|invoice|reference|case|ticket|claim)\s*(?:id|#|no\.?|number)\s*[:#]?\s*[a-z0-9\-]{4,}',
    r'\#\d{5,}',
    r'\b\d{10,}\b',
]

_CURRENCY_PATTERN = re.compile(r'[\$£€¥₹]|\busd\b|\beur\b|\bgbp\b', re.IGNORECASE)
_RE_FWD_PATTERN  = re.compile(r'^\s*(?:re|fw|fwd|aw)\s*:', re.IGNORECASE)
_ALL_CAPS_WORD   = re.compile(r'\b[A-Z]{4,}\b')


def score_subject(raw_email: str) -> Dict[str, Any]:
    """
    Score the subject line for phishing signals.

    Returns
    -------
    {
        "score":           float 0.0–1.0
        "subject":         str       (cleaned subject text)
        "subject_length":  int
        "features": {
            "subject_urgency":      float
            "subject_security":     float
            "subject_brand_name":   float
            "subject_currency":     float
            "subject_all_caps":     float
            "subject_fake_re":      float
            "subject_fake_txn_id":  float
        }
    }
    """
    msg = email.message_from_string(raw_email)
    subject = (msg.get("Subject") or "").strip()
    subject_lower = subject.lower()
    n_chars = len(subject)

    if n_chars == 0:
        return _empty_result(subject)

    urgency_hits = sum(1 for w in _SUBJECT_URGENCY if w in subject_lower)
    urgency_score = min(1.0, urgency_hits / 3)

    security_hits = sum(1 for w in _SUBJECT_SECURITY_THEME if w in subject_lower)
    security_score = min(1.0, security_hits / 3)

    brand_hit = any(b in subject_lower for b in _SUBJECT_BRANDS)
    brand_score = 1.0 if brand_hit else 0.0

    currency_score = 1.0 if _CURRENCY_PATTERN.search(subject) else 0.0

    caps_words = _ALL_CAPS_WORD.findall(subject)
    caps_score = min(1.0, len(caps_words) / 3)

    fake_re_score = 0.0
    if _RE_FWD_PATTERN.match(subject):
        rest = _RE_FWD_PATTERN.sub("", subject).strip().lower()
        if any(w in rest for w in _SUBJECT_SECURITY_THEME[:10]):
            fake_re_score = 1.0

    txn_score = 0.0
    for pat in _FAKE_TRANSACTION_PATTERNS:
        if re.search(pat, subject_lower):
            txn_score = 1.0
            break

    score = min(1.0,
        urgency_score   * 0.25 +
        security_score  * 0.25 +
        brand_score     * 0.15 +
        currency_score  * 0.10 +
        caps_score      * 0.10 +
        fake_re_score   * 0.10 +
        txn_score       * 0.05
    )

    return {
        "score":           round(score, 4),
        "subject":         subject,
        "subject_length":  n_chars,
        "features": {
            "subject_urgency":     round(urgency_score,  4),
            "subject_security":    round(security_score, 4),
            "subject_brand_name":  round(brand_score,    4),
            "subject_currency":    round(currency_score, 4),
            "subject_all_caps":    round(caps_score,     4),
            "subject_fake_re":     round(fake_re_score,  4),
            "subject_fake_txn_id": round(txn_score,      4),
        }
    }


def _empty_result(subject: str) -> Dict[str, Any]:
    return {
        "score":           0.1,
        "subject":         subject,
        "subject_length":  0,
        "features": {
            "subject_urgency":     0.0, "subject_security":   0.0,
            "subject_brand_name":  0.0, "subject_currency":   0.0,
            "subject_all_caps":    0.0, "subject_fake_re":    0.0,
            "subject_fake_txn_id": 0.0,
        }
    }