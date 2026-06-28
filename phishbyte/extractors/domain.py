"""
phishbyte/extractors/domain.py
Layer 1 — Domain consistency scorer (v2).
Adds brand impersonation detection — looks for legit brand names in body
that don't match the actual sender domain.
"""

import re
import email
import email.utils
from typing import Dict, Any


_FREEMAIL = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "aol.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com",
}

_BRAND_DOMAIN_MAP = {
    "paypal":      ["paypal.com"],
    "amazon":      ["amazon.com", "amazon.co.uk", "amazon.de"],
    "apple":       ["apple.com", "icloud.com"],
    "microsoft":   ["microsoft.com", "outlook.com", "live.com"],
    "google":      ["google.com", "gmail.com", "googlemail.com"],
    "netflix":     ["netflix.com"],
    "ebay":        ["ebay.com", "ebay.co.uk"],
    "facebook":    ["facebook.com", "fb.com"],
    "instagram":   ["instagram.com"],
    "linkedin":    ["linkedin.com"],
    "twitter":     ["twitter.com", "x.com"],
    "whatsapp":    ["whatsapp.com"],
    "fedex":       ["fedex.com"],
    "ups":         ["ups.com"],
    "dhl":         ["dhl.com"],
    "usps":        ["usps.com"],
    "chase":       ["chase.com"],
    "wellsfargo":  ["wellsfargo.com"],
    "citibank":    ["citi.com", "citibank.com"],
    "hsbc":        ["hsbc.com", "hsbc.co.uk"],
    "irs":         ["irs.gov"],
    "dropbox":     ["dropbox.com"],
    "docusign":    ["docusign.com", "docusign.net"],
    "office365":   ["microsoft.com", "office.com"],
}


def _extract_domain(header_value: str):
    if not header_value:
        return None
    _, addr = email.utils.parseaddr(header_value)
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None


def _extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    try:    body += payload.decode("utf-8", errors="ignore")
                    except: body += payload.decode("latin-1", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:    body += payload.decode("utf-8", errors="ignore")
            except: body += payload.decode("latin-1", errors="ignore")
    return body


def _check_brand_impersonation(
    body_text: str,
    subject:   str,
    from_domain: str,
) -> float:
    """
    Look for legit brand names in subject/body and check if the From domain
    actually matches that brand. Returns 0.0 if no brand mentioned, 1.0 if
    brand mentioned but sender domain doesn't match the brand's real domains.
    """
    if not from_domain:
        return 0.0

    text = (subject + " " + body_text[:2000]).lower()
    for brand, legit_domains in _BRAND_DOMAIN_MAP.items():
        if brand in text:
            sender_matches = any(
                from_domain.endswith(d) or from_domain == d
                for d in legit_domains
            )
            if not sender_matches:
                if from_domain in _FREEMAIL:
                    return 1.0
                base = from_domain.split('.')[0]
                if brand in base:
                    return 0.0
                return 1.0
    return 0.0


def score_domain(raw_email: str) -> Dict[str, Any]:
    """
    Analyse domain consistency + brand impersonation.

    NEW in v2: brand impersonation check —
    detects "I'm from PayPal" claims sent from random domains.
    """
    msg = email.message_from_string(raw_email)

    from_domain       = _extract_domain(msg.get("From"))
    replyto_domain    = _extract_domain(msg.get("Reply-To"))
    returnpath_domain = _extract_domain(msg.get("Return-Path"))
    subject           = (msg.get("Subject") or "")

    domains = [d for d in [from_domain, replyto_domain, returnpath_domain] if d]
    unique  = set(domains)
    domains_match    = len(unique) <= 1
    mismatch_count   = len(unique)
    from_is_freemail = from_domain in _FREEMAIL if from_domain else False

    body_text = _extract_body(msg)
    brand_impersonation = _check_brand_impersonation(body_text, subject, from_domain or "")

    domain_mismatch = min(1.0, (mismatch_count - 1) / 2) if mismatch_count > 1 else 0.0

    replyto_differs = 0.0
    if replyto_domain and from_domain and replyto_domain != from_domain:
        replyto_differs = 1.0

    returnpath_differs = 0.0
    if returnpath_domain and from_domain and returnpath_domain != from_domain:
        returnpath_differs = 0.7

    freemail_score = 0.3 if from_is_freemail else 0.0

    score = min(1.0,
        domain_mismatch     * 0.30 +
        replyto_differs     * 0.20 +
        returnpath_differs  * 0.10 +
        freemail_score      * 0.05 +
        brand_impersonation * 0.35
    )

    return {
        "score":             round(score, 4),
        "from_domain":       from_domain,
        "replyto_domain":    replyto_domain,
        "returnpath_domain": returnpath_domain,
        "domains_match":     domains_match,
        "from_is_freemail":  from_is_freemail,
        "mismatch_count":    mismatch_count,
        "brand_impersonation": bool(brand_impersonation),
        "features": {
            "domain_mismatch":     round(domain_mismatch,     4),
            "replyto_differs":     round(replyto_differs,     4),
            "returnpath_differs":  round(returnpath_differs,  4),
            "from_is_freemail":    round(freemail_score,      4),
            "brand_impersonation": round(brand_impersonation, 4),
        }
    }