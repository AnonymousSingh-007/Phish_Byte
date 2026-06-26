"""
phishbyte/extractors/urls.py
Layer 1 — URL and anchor mismatch scorer.
Refactored from original Phish_Byte Url(), Anchors, embed_mismatch().
Returns numeric scores instead of printing.
"""

import re
import email
from urllib.parse import urlparse
from html.parser import HTMLParser
from typing import Dict, Any, List


# Suspicious TLDs commonly used in phishing domains
_SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Freenom free TLDs
    ".xyz", ".top", ".click", ".link",
    ".loan", ".win", ".racing", ".stream",
    ".download", ".accountant", ".faith"
}

# Urgency keywords — high signal in phishing body text
_URGENCY_WORDS = [
    "urgent", "immediately", "verify", "confirm", "account suspended",
    "limited time", "act now", "expires", "click here", "login",
    "update your", "unusual activity", "security alert", "validate",
    "your account", "will be closed", "suspended", "blocked", "verify now",
    "kindly", "dear customer", "valued member", "bank account",
    "social security", "credit card", "wire transfer"
]


class _AnchorParser(HTMLParser):
    """Minimal HTML parser — extracts anchor href + visible text pairs."""

    def __init__(self):
        super().__init__()
        self.anchors: List[Dict] = []
        self._current: Dict | None = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            self._current = {"href": None, "text": ""}
            for attr, val in attrs:
                if attr.lower() == "href":
                    self._current["href"] = val

    def handle_data(self, data):
        if self._current is not None:
            self._current["text"] += data.strip()

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._current is not None:
            self.anchors.append(self._current)
            self._current = None


def _extract_body(msg: email.message.Message) -> str:
    """Walk the email MIME tree and collect all text/html + text/plain content."""
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            ct = part.get_content_type()
            if ct in ("text/plain", "text/html"):
                payload = part.get_payload(decode=True)
                if payload:
                    try:
                        body += payload.decode("utf-8", errors="ignore")
                    except Exception:
                        body += payload.decode("latin-1", errors="ignore")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                body += payload.decode("utf-8", errors="ignore")
            except Exception:
                body += payload.decode("latin-1", errors="ignore")
    return body


def _domain_from_url(url: str) -> str:
    """Return lowercase netloc from a URL string."""
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""


def _has_suspicious_tld(url: str) -> bool:
    domain = _domain_from_url(url)
    return any(domain.endswith(tld) for tld in _SUSPICIOUS_TLDS)


def score_urls(raw_email: str) -> Dict[str, Any]:
    """
    Analyse URLs, anchor mismatches, body urgency signals, and link density.

    Returns
    -------
    {
        "score":                float 0.0–1.0
        "secure_url_count":     int
        "insecure_url_count":   int
        "total_urls":           int
        "mismatched_anchors":   list of {text, href}
        "suspicious_tld_urls":  int
        "urgency_word_hits":    int
        "link_density":         float  (links per 100 chars of text)
        "features": {
            "http_ratio":           float
            "anchor_mismatch_score":float
            "suspicious_tld_score": float
            "urgency_score":        float
            "link_density_score":   float
        }
    }
    """
    msg  = email.message_from_string(raw_email)
    body = _extract_body(msg)

    # ── URL counts ────────────────────────────────────────────────────────────
    secure_urls   = re.findall(r'https://[^\s\'"<>]+', body)
    insecure_urls = re.findall(r'http://[^\s\'"<>]+',  body)
    all_urls      = secure_urls + insecure_urls
    total_urls    = len(all_urls)

    # ── HTTP ratio ────────────────────────────────────────────────────────────
    if total_urls == 0:
        http_ratio = 0.0
    else:
        http_ratio = len(insecure_urls) / total_urls

    # ── Anchor mismatches ─────────────────────────────────────────────────────
    mismatched_anchors: List[Dict] = []
    if "<a " in body.lower():
        parser = _AnchorParser()
        parser.feed(body)
        for anchor in parser.anchors:
            href = anchor.get("href") or ""
            text = anchor.get("text", "").strip()
            if href and "." in text:
                href_domain = _domain_from_url(href)
                if href_domain and text.lower() not in href_domain:
                    mismatched_anchors.append({"text": text, "href": href})

    anchor_mismatch_score = min(1.0, len(mismatched_anchors) / 5) if mismatched_anchors else 0.0

    # ── Suspicious TLDs ───────────────────────────────────────────────────────
    suspicious_tld_count = sum(1 for u in all_urls if _has_suspicious_tld(u))
    suspicious_tld_score = min(1.0, suspicious_tld_count / 3)

    # ── Urgency words ─────────────────────────────────────────────────────────
    body_lower      = body.lower()
    urgency_hits    = sum(1 for w in _URGENCY_WORDS if w in body_lower)
    urgency_score   = min(1.0, urgency_hits / 8)

    # ── Link density ──────────────────────────────────────────────────────────
    # Strip tags to count pure text chars
    clean_text       = re.sub(r'<[^>]+>', '', body)
    text_len         = max(len(clean_text), 1)
    link_density     = total_urls / (text_len / 100)
    link_density_score = min(1.0, link_density / 2)

    # ── Composite score ───────────────────────────────────────────────────────
    score = min(1.0,
        http_ratio            * 0.30 +
        anchor_mismatch_score * 0.30 +
        suspicious_tld_score  * 0.15 +
        urgency_score         * 0.15 +
        link_density_score    * 0.10
    )

    return {
        "score":               round(score, 4),
        "secure_url_count":    len(secure_urls),
        "insecure_url_count":  len(insecure_urls),
        "total_urls":          total_urls,
        "mismatched_anchors":  mismatched_anchors,
        "suspicious_tld_urls": suspicious_tld_count,
        "urgency_word_hits":   urgency_hits,
        "link_density":        round(link_density, 4),
        "features": {
            "http_ratio":            round(http_ratio,            4),
            "anchor_mismatch_score": round(anchor_mismatch_score, 4),
            "suspicious_tld_score":  round(suspicious_tld_score,  4),
            "urgency_score":         round(urgency_score,         4),
            "link_density_score":    round(link_density_score,    4),
        }
    }