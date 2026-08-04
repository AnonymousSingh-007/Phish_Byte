"""
phishbyte/extractors/bdi.py — v2
Upgrades:
  - form_action_is_ip: form posts to raw IP instead of domain (strong tell)
  - redirect_param_present: URL has ?redirect=/?url=/?next= pattern
  - mcld_lexical: runs lexical scoring on the most-common-link domain
"""
import re
import email
import email.utils
from urllib.parse import urlparse
from html.parser import HTMLParser
from collections import Counter
from typing import Dict, Any, List, Optional

from phishbyte.extractors.lexical import score_lexical

_IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
_REDIRECT_PARAMS = re.compile(r'[?&](?:redirect|url|next|return|goto|dest|target)=', re.IGNORECASE)


class _LinkFormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[str] = []
        self.forms: List[str] = []
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
    try: return urlparse(url).netloc.lower().lstrip("www.")
    except: return ""

def _sender_domain(msg) -> Optional[str]:
    from_hdr = msg.get("From","")
    _, addr  = email.utils.parseaddr(from_hdr)
    if "@" in addr: return addr.split("@")[1].strip().lower()
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

def _root_domain(domain: str) -> str:
    if not domain: return ""
    parts = domain.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def score_bdi(raw_email: str) -> Dict[str, Any]:
    """
    Body Domain Identification v2.

    Features (5, was 3):
        mcld_mismatch          — most common link domain != sender root domain
        form_action_mismatch   — form action domain != sender root domain
        external_link_ratio    — fraction of links to external domains
        form_action_is_ip      — form posts to raw IP address (very strong signal)
        redirect_param_present — URL contains open-redirect-style parameter
    """
    msg    = email.message_from_string(raw_email)
    body   = _extract_body(msg)
    sender = _sender_domain(msg)
    sender_root = _root_domain(sender) if sender else None

    parser = _LinkFormParser()
    try: parser.feed(body)
    except Exception: pass

    links, forms = parser.links, parser.forms

    if links:
        domain_counts = Counter(_get_domain(u) for u in links if _get_domain(u))
        most_common = domain_counts.most_common(1)[0][0] if domain_counts else ""
    else:
        most_common = ""

    mcld_mismatch = 0.0
    if most_common and sender_root:
        mcld_root = _root_domain(most_common)
        if mcld_root != sender_root:
            mcld_mismatch = 1.0

    form_domain = _get_domain(forms[0]) if forms else ""
    form_action_mismatch = 0.0
    form_action_is_ip = 0.0
    if forms:
        raw_form_host = urlparse(forms[0]).netloc.split(":")[0]
        if _IP_PATTERN.match(raw_form_host):
            form_action_is_ip = 1.0
        elif form_domain and sender_root:
            if _root_domain(form_domain) != sender_root:
                form_action_mismatch = 1.0

    if links and sender_root:
        external = sum(1 for u in links if sender_root not in _get_domain(u) and _get_domain(u))
        external_link_ratio = external / len(links)
    else:
        external_link_ratio = 0.0

    redirect_param_present = 1.0 if any(_REDIRECT_PARAMS.search(u) for u in links) else 0.0

    score = min(1.0,
        mcld_mismatch          * 0.30 +
        form_action_mismatch   * 0.20 +
        form_action_is_ip      * 0.25 +
        external_link_ratio    * 0.15 +
        redirect_param_present * 0.10
    )

    # Lexical analysis on the most-common-link domain — feeds into cross_signal
    mcld_lexical = score_lexical(most_common) if most_common else {
        k: 0.0 for k in ["digit_run_score","hyphen_run_score","entropy_score",
                         "vowel_ratio_anomaly","brand_typosquat_score","domain_length_score"]
    }

    return {
        "score":                   round(score,4),
        "most_common_link_domain": most_common,
        "form_action_domain":      form_domain or None,
        "total_links":             len(links),
        "mcld_lexical":            mcld_lexical,   # dict, consumed by cross_signal
        "features": {
            "mcld_mismatch":          round(mcld_mismatch,4),
            "form_action_mismatch":   round(form_action_mismatch,4),
            "external_link_ratio":    round(external_link_ratio,4),
            "form_action_is_ip":      round(form_action_is_ip,4),
            "redirect_param_present": round(redirect_param_present,4),
        }
    }