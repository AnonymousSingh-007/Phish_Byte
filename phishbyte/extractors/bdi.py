"""
phishbyte/extractors/bdi.py
Body Domain Identification (BDI) features.
Inspired by: "A Study of Effectiveness of Brand Domain Identification Features
for Phishing Detection" (arXiv 2503.06487, 2025) — 99.7% accuracy with 3 features.

Three features derived from HTML body:
  1. most_common_link_domain_mismatch  — most frequent link domain ≠ From domain
  2. form_action_domain_mismatch       — form action domain ≠ From domain
  3. external_link_ratio               — fraction of links pointing outside From domain

These are structural body features — they fire regardless of email language/era,
catching Nigerian fraud (2008) and modern PayPal phishing (2025) equally.
"""

import re
import email
import email.utils
from urllib.parse import urlparse
from html.parser import HTMLParser
from collections import Counter
from typing import Dict, Any, List, Optional


class _LinkFormParser(HTMLParser):
    """Extract all href links and form action URLs from HTML."""

    def __init__(self):
        super().__init__()
        self.links: List[str]  = []
        self.forms: List[str]  = []

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag.lower() == "a" and "href" in attrs_dict:
            href = attrs_dict["href"] or ""
            if href.startswith(("http://","https://")):
                self.links.append(href)
        if tag.lower() == "form" and "action" in attrs_dict:
            action = attrs_dict["action"] or ""
            if action.startswith(("http://","https://")):
                self.forms.append(action)


def _get_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _sender_domain(msg) -> Optional[str]:
    from_hdr = msg.get("From","")
    _, addr  = email.utils.parseaddr(from_hdr)
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None


def _extract_body(msg) -> str:
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/html","text/plain"):
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


def score_bdi(raw_email: str) -> Dict[str, Any]:
    """
    Body Domain Identification scoring.

    Returns
    -------
    {
        "score": float 0.0–1.0
        "most_common_link_domain": str
        "form_action_domain": str | None
        "total_links": int
        "features": {
            "mcld_mismatch":      float  (most common link domain ≠ sender domain)
            "form_action_mismatch":float  (form action domain ≠ sender domain)
            "external_link_ratio": float  (fraction of links to non-sender domains)
        }
    }
    """
    msg    = email.message_from_string(raw_email)
    body   = _extract_body(msg)
    sender = _sender_domain(msg)

    # Parse links + forms from HTML body
    parser = _LinkFormParser()
    try:
        parser.feed(body)
    except Exception:
        pass

    links  = parser.links
    forms  = parser.forms

    # ── Most Common Link Domain (MCLD) ────────────────────────────────────────
    if links:
        domain_counts = Counter(_get_domain(u) for u in links if _get_domain(u))
        most_common   = domain_counts.most_common(1)[0][0] if domain_counts else ""
    else:
        most_common = ""

    mcld_mismatch = 0.0
    if most_common and sender:
        if not (most_common.endswith(sender) or sender.endswith(most_common)):
            mcld_mismatch = 1.0

    # ── Form Action Domain ────────────────────────────────────────────────────
    form_domain         = _get_domain(forms[0]) if forms else ""
    form_action_mismatch = 0.0
    if form_domain and sender:
        if not (form_domain.endswith(sender) or sender.endswith(form_domain)):
            form_action_mismatch = 1.0

    # ── External Link Ratio ───────────────────────────────────────────────────
    if links and sender:
        external = sum(
            1 for u in links
            if sender not in _get_domain(u) and _get_domain(u)
        )
        external_link_ratio = external / len(links)
    else:
        external_link_ratio = 0.0

    # ── Composite score ───────────────────────────────────────────────────────
    score = min(1.0,
        mcld_mismatch        * 0.45 +
        form_action_mismatch * 0.35 +
        external_link_ratio  * 0.20
    )

    return {
        "score":                  round(score, 4),
        "most_common_link_domain": most_common,
        "form_action_domain":      form_domain or None,
        "total_links":             len(links),
        "features": {
            "mcld_mismatch":       round(mcld_mismatch, 4),
            "form_action_mismatch":round(form_action_mismatch, 4),
            "external_link_ratio": round(external_link_ratio, 4),
        }
    }