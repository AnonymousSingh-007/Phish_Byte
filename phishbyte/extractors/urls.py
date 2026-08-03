"""
phishbyte/extractors/urls.py — v4
Fix: link_density uses unique domains not raw count.
Fix: caps_ratio strips MIME base64 lines before computing.
Fix: link_density weight reduced from 0.10 to 0.05.
"""
import re, email
from urllib.parse import urlparse
from html.parser import HTMLParser
from collections import Counter
from typing import Dict, Any, List

_SUSPICIOUS_TLDS = {".tk",".ml",".ga",".cf",".gq",".xyz",".top",".click",
                    ".link",".loan",".win",".racing",".stream",".download",".accountant",".faith"}

_URGENCY_WORDS = [
    "urgent","immediately","verify","confirm","account suspended","limited time",
    "act now","expires","click here","login","update your","unusual activity",
    "security alert","validate","your account","will be closed","suspended",
    "blocked","verify now","kindly","dear customer","valued member","bank account",
    "social security","credit card","wire transfer","winner","lottery","million",
    "prize","congratulations","transfer","beneficiary","deceased","estate",
    "viagra","pharmacy","pills","discount",
]

class _AnchorParser(HTMLParser):
    def __init__(self):
        super().__init__(); self.anchors=[]; self._current=None
    def handle_starttag(self, tag, attrs):
        if tag.lower()=="a":
            self._current={"href":None,"text":""}
            for a,v in attrs:
                if a.lower()=="href": self._current["href"]=v
    def handle_data(self, data):
        if self._current is not None: self._current["text"]+=data.strip()
    def handle_endtag(self, tag):
        if tag.lower()=="a" and self._current is not None:
            self.anchors.append(self._current); self._current=None

def _extract_body(msg):
    body=""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ("text/plain","text/html"):
                payload=part.get_payload(decode=True)
                if payload:
                    try: body+=payload.decode("utf-8",errors="ignore")
                    except: body+=payload.decode("latin-1",errors="ignore")
    else:
        payload=msg.get_payload(decode=True)
        if payload:
            try: body+=payload.decode("utf-8",errors="ignore")
            except: body+=payload.decode("latin-1",errors="ignore")
    return body

def _domain_from_url(url):
    try: return urlparse(url).netloc.lower().lstrip("www.")
    except: return ""

def _has_suspicious_tld(url):
    d=_domain_from_url(url)
    return any(d.endswith(t) for t in _SUSPICIOUS_TLDS)

def _char_level_features(body):
    if not body:
        return {"caps_ratio":0.0,"digit_ratio":0.0,"special_density":0.0,"avg_word_length":0.0,"html_text_ratio":0.0}
    clean = re.sub(r'<[^>]+>','',body)
    text_len = max(len(clean),1)
    # Strip base64 lines before computing caps ratio
    clean_no_b64 = re.sub(r'^[A-Za-z0-9+/=]{40,}$','',clean,flags=re.MULTILINE)
    n_alpha_clean = max(sum(1 for c in clean_no_b64 if c.isalpha()),1)
    n_caps_clean  = sum(1 for c in clean_no_b64 if c.isupper())
    caps_ratio    = min(1.0,(n_caps_clean/n_alpha_clean)*3)
    digit_ratio   = min(1.0,(sum(1 for c in clean if c.isdigit())/text_len)*10)
    specials      = re.findall(r'[!?$£€¥₹*#@%&]',clean)
    special_density = min(1.0,(len(specials)/(text_len/100))/5)
    words         = re.findall(r'\b[a-zA-Z]+\b',clean)
    avg_len       = sum(len(w) for w in words)/len(words) if words else 0.0
    avg_word_norm = min(1.0,abs(avg_len-4.5)/4.5) if avg_len>0 else 0.0
    html_tags     = len(re.findall(r'<[^>]+>',body))
    html_text_ratio = min(1.0,html_tags/max(len(words),1))
    return {
        "caps_ratio":round(caps_ratio,4),"digit_ratio":round(digit_ratio,4),
        "special_density":round(special_density,4),"avg_word_length":round(avg_word_norm,4),
        "html_text_ratio":round(html_text_ratio,4),
    }

def score_urls(raw_email: str) -> Dict[str, Any]:
    msg  = email.message_from_string(raw_email)
    body = _extract_body(msg)
    secure_urls   = re.findall(r'https://[^\s\'"<>]+',body)
    insecure_urls = re.findall(r'http://[^\s\'"<>]+',body)
    all_urls      = secure_urls+insecure_urls
    total_urls    = len(all_urls)
    http_ratio    = (len(insecure_urls)/total_urls) if total_urls else 0.0

    mismatched_anchors = []
    if "<a " in body.lower():
        parser=_AnchorParser(); parser.feed(body)
        for anchor in parser.anchors:
            href=anchor.get("href") or ""; text=anchor.get("text","").strip()
            if href and "." in text:
                href_domain=_domain_from_url(href)
                if href_domain and text.lower() not in href_domain:
                    mismatched_anchors.append({"text":text,"href":href})

    anchor_mismatch_score = min(1.0,len(mismatched_anchors)/5) if mismatched_anchors else 0.0
    suspicious_tld_count  = sum(1 for u in all_urls if _has_suspicious_tld(u))
    suspicious_tld_score  = min(1.0,suspicious_tld_count/3)

    clean_text = re.sub(r'<[^>]+>','',body)
    body_lower = clean_text.lower()
    words      = re.findall(r'\b\w+\b',clean_text)
    n_words    = max(len(words),1)
    urgency_hits  = sum(1 for w in _URGENCY_WORDS if w in body_lower)
    urgency_score = min(1.0,(urgency_hits/n_words)*100)

    # KEY FIX: unique link domains, not raw count
    if all_urls:
        link_domains   = [_domain_from_url(u) for u in all_urls if _domain_from_url(u)]
        unique_domains = len(set(link_domains))
        unique_density = unique_domains/(n_words/100)
        link_density_score = min(1.0, unique_density/3.0)
    else:
        link_domains=[];unique_domains=0;link_density_score=0.0

    char_features = _char_level_features(body)

    score = min(1.0,
        http_ratio*0.20 + anchor_mismatch_score*0.20 + suspicious_tld_score*0.15 +
        urgency_score*0.15 + link_density_score*0.05 +
        char_features["caps_ratio"]*0.10 + char_features["special_density"]*0.10 +
        char_features["html_text_ratio"]*0.05
    )

    features = {
        "http_ratio":round(http_ratio,4),"anchor_mismatch_score":round(anchor_mismatch_score,4),
        "suspicious_tld_score":round(suspicious_tld_score,4),"urgency_score":round(urgency_score,4),
        "link_density_score":round(link_density_score,4),
    }
    features.update(char_features)
    return {
        "score":round(score,4),"secure_url_count":len(secure_urls),
        "insecure_url_count":len(insecure_urls),"total_urls":total_urls,
        "unique_link_domains":unique_domains,"mismatched_anchors":mismatched_anchors,
        "suspicious_tld_urls":suspicious_tld_count,"urgency_word_hits":urgency_hits,
        "features":features,
    }