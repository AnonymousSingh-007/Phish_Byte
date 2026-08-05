"""
phishbyte/extractors/spf.py — v2

Complete rewrite. Old version did a live DNS SPF lookup on the envelope
sender and compared it to the From domain — which fires 'spf_fail' on
every legitimate email sent via an ESP (Marketo, Mailgun, SendGrid, listserv),
because those services use their own domain as the envelope sender.

This is wrong because DMARC was designed to handle exactly this case.
DMARC performs an *aligned* authentication check that correctly handles
legitimate third-party senders.

New approach:
  - Parse the Authentication-Results header (present in all modern email)
  - Extract DMARC result, DKIM result + signing domain, raw SPF result
  - Compute alignment: does DKIM signing domain match the From root domain?
  - Compute AUTH_ALIGNMENT_SCORE — the relationship between the three
  - Still expose the raw signals so the MLP can learn from them individually
  - Preserve backward-compatible feature names so we don't break build_feature_vector

Features (6 — expanded from 3):
  spf_fail                0.0/1.0  raw SPF result from Authentication-Results
  no_spf_record           0.0/1.0  SPF record genuinely absent (not just ESP relay)
  no_sending_ip           0.0/1.0  no sending IP extractable (keep for compat)
  dmarc_pass              0.0/1.0  DMARC alignment check passed
  dkim_aligned            0.0/1.0  DKIM signing domain root matches From root
  auth_alignment_score    0.0-1.0  composite: dmarc×0.5 + dkim_aligned×0.3 + spf×0.2

The overall 'score' is now INVERTED from the old version:
  high score = strong authentication failure = phishing signal
  low score  = strong authentication pass = legitimacy signal

This means the MLP now gets honest trust signal from the auth layer
instead of being systematically misled by ESP relay patterns.
"""

import re
import email
import email.utils
from typing import Dict, Any, Optional, List


# Regex patterns for Authentication-Results parsing
_DMARC_RE   = re.compile(r'\bdmarc\s*=\s*(pass|fail|temperror|permerror|none)',    re.I)
_DKIM_RE    = re.compile(r'\bdkim\s*=\s*(pass|fail|temperror|permerror|none)',      re.I)
_SPF_RE     = re.compile(r'\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror)',re.I)
_DKIM_HDR_RE= re.compile(r'header\.i\s*=\s*@?([\w.\-]+)',                           re.I)
_DMARC_POL_RE = re.compile(r'\bp\s*=\s*(none|quarantine|reject)',                  re.I)
_RECEIVED_IP_RE = re.compile(r'[\[\(](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[\]\)]')


def _root_domain(domain: str) -> str:
    if not domain: return ""
    parts = domain.lower().strip().split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def _get_from_domain(msg) -> Optional[str]:
    from_hdr = msg.get("From", "")
    _, addr = email.utils.parseaddr(from_hdr)
    if "@" in addr:
        return addr.split("@")[1].strip().lower()
    return None


def _parse_auth_results(msg) -> Dict[str, Any]:
    """
    Parse Authentication-Results header(s) — may appear multiple times.
    Extracts: dmarc result, dkim result + signing domains, spf result, dmarc policy.
    """
    auth_headers: List[str] = []
    for key, val in msg.items():
        if key.lower() == "authentication-results" and val:
            auth_headers.append(val)
    # Also check ARC-Authentication-Results for forwarded mail
    for key, val in msg.items():
        if key.lower() == "arc-authentication-results" and val:
            auth_headers.append(val)

    combined = " ".join(auth_headers).lower()

    # DMARC result
    dmarc_match = _DMARC_RE.search(combined)
    dmarc_result = dmarc_match.group(1) if dmarc_match else "none"

    # DMARC policy strength
    pol_match = _DMARC_POL_RE.search(combined)
    dmarc_policy = pol_match.group(1) if pol_match else "none"

    # DKIM result(s) — there may be multiple
    dkim_results = [m.group(1) for m in _DKIM_RE.finditer(combined)]
    dkim_pass = any(r == "pass" for r in dkim_results)

    # DKIM signing domains — look for header.i=@domain
    # Use original case headers for domain extraction
    combined_orig = " ".join(auth_headers)
    dkim_signing_domains = [
        m.group(1).lower()
        for m in _DKIM_HDR_RE.finditer(combined_orig)
    ]

    # Raw SPF result
    spf_match = _SPF_RE.search(combined)
    spf_result = spf_match.group(1) if spf_match else "none"

    return {
        "dmarc_result":        dmarc_result,
        "dmarc_policy":        dmarc_policy,
        "dkim_pass":           dkim_pass,
        "dkim_signing_domains":dkim_signing_domains,
        "spf_result":          spf_result,
        "raw_combined":        combined,
    }


def _check_dkim_alignment(from_domain: Optional[str],
                           signing_domains: List[str]) -> bool:
    """
    DKIM is 'aligned' when at least one signing domain shares a root domain
    with the From address. This correctly handles:
      - linkedin.com signing for maile.linkedin.com From → aligned
      - google.com signing for googlecloud@google.com From → aligned
      - mailgun.org signing for higgsfield.ai From → NOT aligned (but dmarc may still pass)
      - evil.com signing for paypal.com From → NOT aligned
    """
    if not from_domain or not signing_domains:
        return False
    from_root = _root_domain(from_domain)
    for signing in signing_domains:
        if _root_domain(signing) == from_root:
            return True
    return False


def _policy_score(policy: str) -> float:
    """Higher policy = sender has stronger commitment to authentication."""
    return {"reject": 1.0, "quarantine": 0.5, "none": 0.1}.get(policy.lower(), 0.0)


def _get_sending_ip(msg) -> Optional[str]:
    """Extract first public IP from Received headers."""
    for key, val in msg.items():
        if key.lower() == "received" and val:
            m = _RECEIVED_IP_RE.search(val)
            if m:
                ip = m.group(1)
                # Skip RFC1918 private ranges
                parts = ip.split(".")
                if parts[0] in ("10", "127") or \
                   (parts[0] == "172" and 16 <= int(parts[1]) <= 31) or \
                   (parts[0] == "192" and parts[1] == "168"):
                    continue
                return ip
    return None


def score_spf(raw_email: str) -> Dict[str, Any]:
    """
    Authentication alignment scoring — v2.

    Returns 6 features:
      spf_fail              raw SPF result fail (from Authentication-Results, not DNS)
      no_spf_record         SPF record absent entirely
      no_sending_ip         no extractable sending IP
      dmarc_pass            DMARC alignment check passed
      dkim_aligned          DKIM signing domain root matches From root
      auth_alignment_score  composite trust signal (0=strong trust, 1=no auth)

    And diagnostic fields:
      spf_result            raw string ('pass'/'fail'/'softfail'/etc)
      dmarc_result          raw string
      dmarc_policy          'none'/'quarantine'/'reject'
      dkim_signing_domains  list of domains that signed with DKIM
    """
    msg = email.message_from_string(raw_email)
    from_domain = _get_from_domain(msg)
    sending_ip  = _get_sending_ip(msg)

    # Parse Authentication-Results
    auth = _parse_auth_results(msg)

    dmarc_result = auth["dmarc_result"]   # pass/fail/none
    spf_result   = auth["spf_result"]     # pass/fail/softfail/none
    dkim_pass    = auth["dkim_pass"]
    signing_domains = auth["dkim_signing_domains"]
    dmarc_policy = auth["dmarc_policy"]

    # Derived binary features
    dmarc_pass_flag   = 1.0 if dmarc_result == "pass" else 0.0
    spf_fail_flag     = 1.0 if spf_result   in ("fail", "softfail") else 0.0
    no_spf_flag       = 1.0 if spf_result   == "none" else 0.0
    no_sending_ip_flag= 0.0 if sending_ip   else 1.0

    # DKIM alignment — signing domain root matches From root
    dkim_aligned_flag = 1.0 if _check_dkim_alignment(from_domain, signing_domains) else 0.0

    # AUTH ALIGNMENT SCORE
    # Low = strong authentication = legitimacy signal
    # High = weak authentication = phishing signal
    #
    # Components:
    #   DMARC pass → strong trust (weight 0.50)
    #   DKIM aligned → structural trust (weight 0.30)
    #   SPF pass → envelope trust (weight 0.20)
    #
    # Policy multiplier: reject policy → publisher is serious about authentication
    policy_mult = 1.0 + _policy_score(dmarc_policy) * 0.2  # 1.0 to 1.2

    trust_score = (
        dmarc_pass_flag    * 0.50 +
        dkim_aligned_flag  * 0.30 +
        (1 - spf_fail_flag)* 0.20    # SPF pass contributes positively
    ) * policy_mult

    # Invert: high trust_score → low auth_alignment_score (phishing signal)
    auth_alignment_score = round(max(0.0, 1.0 - min(1.0, trust_score)), 4)

    # Overall module score — phishing likelihood from auth perspective
    score = auth_alignment_score

    return {
        "score":                  round(score, 4),
        "spf_result":             spf_result,
        "dmarc_result":           dmarc_result,
        "dmarc_policy":           dmarc_policy,
        "dkim_signing_domains":   signing_domains,
        "sending_ip":             sending_ip,
        "from_domain":            from_domain,
        "features": {
            # Backward-compatible names for build_feature_vector
            "spf_fail":              round(spf_fail_flag, 4),
            "no_spf_record":         round(no_spf_flag, 4),
            "no_sending_ip":         round(no_sending_ip_flag, 4),
            # New features
            "dmarc_pass":            round(dmarc_pass_flag, 4),
            "dkim_aligned":          round(dkim_aligned_flag, 4),
            "auth_alignment_score":  auth_alignment_score,
        }
    }