"""
phishbyte/extractors/domain.py — v3
Adds:
  - display_name_mismatch: "PayPal Security" <attacker@bad.com> → phish signal
  - suspicious_domain_pattern: heuristic for newly-registered-style domains
  - 7 features total (was 5)
"""
import re
import email
import email.utils
from typing import Dict, Any

_FREEMAIL = {
    "gmail.com","yahoo.com","hotmail.com","outlook.com",
    "protonmail.com","aol.com","icloud.com","mail.com",
    "zoho.com","yandex.com",
}

_BRAND_DOMAIN_MAP = {
    "paypal":["paypal.com"],"amazon":["amazon.com","amazon.co.uk","amazon.de"],
    "apple":["apple.com","icloud.com"],"microsoft":["microsoft.com","outlook.com","live.com"],
    "google":["google.com","gmail.com","googlemail.com"],"netflix":["netflix.com"],
    "ebay":["ebay.com","ebay.co.uk"],"facebook":["facebook.com","fb.com"],
    "instagram":["instagram.com"],"linkedin":["linkedin.com"],
    "twitter":["twitter.com","x.com"],"whatsapp":["whatsapp.com"],
    "fedex":["fedex.com"],"ups":["ups.com"],"dhl":["dhl.com"],"usps":["usps.com"],
    "chase":["chase.com"],"wellsfargo":["wellsfargo.com"],
    "citibank":["citi.com","citibank.com"],"hsbc":["hsbc.com","hsbc.co.uk"],
    "irs":["irs.gov"],"dropbox":["dropbox.com"],"docusign":["docusign.com","docusign.net"],
}

_DISPLAY_NAME_BRANDS = list(_BRAND_DOMAIN_MAP.keys())

_SUSPICIOUS_DOMAIN_PATTERNS = [
    r'\d{4,}',              # 4+ consecutive digits (secure1234login)
    r'-{2,}',               # double hyphens (paypal--secure)
    r'(?:\w+-){3,}',        # 3+ hyphen segments (secure-login-verify-now)
    r'[a-z]{30,}',          # very long domain (30+ chars without hyphens)
]

_SUSPICIOUS_TLDS_DOMAIN = re.compile(
    r'\.(?:tk|ml|ga|cf|gq|xyz|top|click|loan|win|racing|stream)$'
)


def _extract_domain(header_value: str):
    if not header_value: return None
    _, addr = email.utils.parseaddr(header_value)
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None


def _extract_display_name(header_value: str) -> str:
    """Extract just the display name from 'Display Name <addr>'."""
    if not header_value: return ""
    m = re.match(r'^"?([^"<@]+)"?\s*<', header_value.strip())
    if m:
        return m.group(1).strip().lower()
    return ""


def _display_name_mismatch(from_header: str, from_domain: str) -> float:
    """
    Check if the display name claims a known brand but the sending domain
    doesn't match. 'PayPal Security <attacker@evil.com>' = 1.0.
    """
    if not from_header or not from_domain: return 0.0
    display = _extract_display_name(from_header)
    if not display: return 0.0
    for brand, legit_domains in _BRAND_DOMAIN_MAP.items():
        if brand in display:
            if not any(from_domain.endswith(d) for d in legit_domains):
                return 1.0
    return 0.0


def _suspicious_domain_pattern(domain: str) -> float:
    """
    Heuristic for freshly-registered / auto-generated phishing domains.
    Works without WHOIS — just regex on the domain string itself.
    """
    if not domain: return 0.0
    score = 0.0
    for pat in _SUSPICIOUS_DOMAIN_PATTERNS:
        if re.search(pat, domain): score += 0.25
    if _SUSPICIOUS_TLDS_DOMAIN.search(domain): score += 0.25
    return min(1.0, score)


def _extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain","text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    try:    body += payload.decode("utf-8",errors="ignore")
                    except: body += payload.decode("latin-1",errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:    body += payload.decode("utf-8",errors="ignore")
            except: body += payload.decode("latin-1",errors="ignore")
    return body


def _check_brand_impersonation(body_text, subject, from_domain):
    if not from_domain: return 0.0
    text = (subject + " " + body_text[:2000]).lower()
    for brand, legit_domains in _BRAND_DOMAIN_MAP.items():
        if brand in text:
            sender_matches = any(
                from_domain.endswith(d) or from_domain == d
                for d in legit_domains
            )
            if not sender_matches:
                if from_domain in _FREEMAIL: return 1.0
                if brand in from_domain.split('.')[0]: return 0.0
                return 1.0
    return 0.0


def score_domain(raw_email: str) -> Dict[str, Any]:
    """
    Analyse domain consistency, brand impersonation, display name mismatch,
    and suspicious domain patterns.

    Features (7):
        domain_mismatch, replyto_differs, returnpath_differs,
        from_is_freemail, brand_impersonation,
        display_name_mismatch, suspicious_domain_pattern
    """
    msg = email.message_from_string(raw_email)

    from_header       = msg.get("From","")
    from_domain       = _extract_domain(from_header)
    replyto_domain    = _extract_domain(msg.get("Reply-To",""))
    returnpath_domain = _extract_domain(msg.get("Return-Path",""))
    subject           = msg.get("Subject","") or ""

    domains = [d for d in [from_domain,replyto_domain,returnpath_domain] if d]
    unique  = set(domains)
    mismatch_count   = len(unique)
    from_is_freemail = from_domain in _FREEMAIL if from_domain else False

    body_text = _extract_body(msg)
    brand_impersonation   = _check_brand_impersonation(body_text, subject, from_domain or "")
    disp_name_mismatch    = _display_name_mismatch(from_header, from_domain or "")
    susp_domain           = _suspicious_domain_pattern(from_domain or "")

    domain_mismatch    = min(1.0,(mismatch_count-1)/2) if mismatch_count>1 else 0.0
    replyto_differs    = 1.0 if (replyto_domain and from_domain and replyto_domain!=from_domain) else 0.0
    returnpath_differs = 0.7 if (returnpath_domain and from_domain and returnpath_domain!=from_domain) else 0.0
    freemail_score     = 0.3 if from_is_freemail else 0.0

    score = min(1.0,
        domain_mismatch     * 0.20 +
        replyto_differs     * 0.15 +
        returnpath_differs  * 0.10 +
        freemail_score      * 0.05 +
        brand_impersonation * 0.20 +
        disp_name_mismatch  * 0.20 +
        susp_domain         * 0.10
    )

    return {
        "score":               round(score,4),
        "from_domain":         from_domain,
        "replyto_domain":      replyto_domain,
        "returnpath_domain":   returnpath_domain,
        "domains_match":       len(unique)<=1,
        "from_is_freemail":    from_is_freemail,
        "mismatch_count":      mismatch_count,
        "brand_impersonation": bool(brand_impersonation),
        "features": {
            "domain_mismatch":          round(domain_mismatch,4),
            "replyto_differs":          round(replyto_differs,4),
            "returnpath_differs":       round(returnpath_differs,4),
            "from_is_freemail":         round(freemail_score,4),
            "brand_impersonation":      round(brand_impersonation,4),
            "display_name_mismatch":    round(disp_name_mismatch,4),
            "suspicious_domain_pattern":round(susp_domain,4),
        }
    }