"""
phishbyte/extractors/domain.py
Layer 1 — Domain consistency scorer.
Refactored from original Phish_Byte Domain() function.
Returns a numeric score + full feature dict instead of printing.
"""

import email
import email.utils
from typing import Dict, Any


# Suspicious free-mail domains commonly spoofed in phishing
_FREEMAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "aol.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com"
}


def _extract_domain(header_value: str) -> str | None:
    """Parse a header value and return the domain portion."""
    if not header_value:
        return None
    _, addr = email.utils.parseaddr(header_value)
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None


def score_domain(raw_email: str) -> Dict[str, Any]:
    """
    Analyse domain consistency across From / Reply-To / Return-Path headers.

    Returns
    -------
    {
        "score":            float 0.0–1.0   (higher = more suspicious)
        "from_domain":      str | None
        "replyto_domain":   str | None
        "returnpath_domain":str | None
        "domains_match":    bool
        "from_is_freemail": bool
        "mismatch_count":   int             (number of unique domains found)
        "features": {                       (sub-scores for MLP feature vector)
            "domain_mismatch":  float
            "replyto_differs":  float
            "returnpath_differs": float
            "from_is_freemail": float
        }
    }
    """
    msg = email.message_from_string(raw_email)

    from_domain       = _extract_domain(msg.get("From"))
    replyto_domain    = _extract_domain(msg.get("Reply-To"))
    returnpath_domain = _extract_domain(msg.get("Return-Path"))

    domains = [d for d in [from_domain, replyto_domain, returnpath_domain] if d]
    unique  = set(domains)

    domains_match   = len(unique) <= 1
    mismatch_count  = len(unique)
    from_is_freemail = from_domain in _FREEMAIL if from_domain else False

    # ── Sub-scores ──────────────────────────────────────────────────────────
    # domain_mismatch: 0 if all same, scales with how many unique domains
    domain_mismatch  = min(1.0, (mismatch_count - 1) / 2) if mismatch_count > 1 else 0.0

    # replyto_differs: 1.0 if reply-to domain ≠ from domain (classic phish signal)
    replyto_differs  = 0.0
    if replyto_domain and from_domain and replyto_domain != from_domain:
        replyto_differs = 1.0

    # returnpath_differs: 0.7 weight — less definitive than reply-to
    returnpath_differs = 0.0
    if returnpath_domain and from_domain and returnpath_domain != from_domain:
        returnpath_differs = 0.7

    freemail_score = 0.3 if from_is_freemail else 0.0

    # ── Composite score ──────────────────────────────────────────────────────
    # Weighted combination; mismatch is the dominant signal
    score = min(1.0,
        domain_mismatch   * 0.50 +
        replyto_differs   * 0.25 +
        returnpath_differs* 0.15 +
        freemail_score    * 0.10
    )

    return {
        "score":             round(score, 4),
        "from_domain":       from_domain,
        "replyto_domain":    replyto_domain,
        "returnpath_domain": returnpath_domain,
        "domains_match":     domains_match,
        "from_is_freemail":  from_is_freemail,
        "mismatch_count":    mismatch_count,
        "features": {
            "domain_mismatch":      round(domain_mismatch,   4),
            "replyto_differs":      round(replyto_differs,   4),
            "returnpath_differs":   round(returnpath_differs,4),
            "from_is_freemail":     round(freemail_score,    4),
        }
    }