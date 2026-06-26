"""
phishbyte/extractors/spf.py
Layer 1 — SPF validation scorer.
Refactored from original Phish_Byte spf_validation_check().
Returns numeric score + feature dict instead of string verdict.
"""

import re
import email
import email.utils
import ipaddress
from typing import Dict, Any

try:
    import dns.resolver
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


def _get_sender_domain(msg: email.message.Message) -> str | None:
    """Extract sender domain from Return-Path or From header."""
    return_path = msg.get("Return-Path")
    from_header = msg.get("From")

    sender_email = None
    if return_path:
        sender_email = return_path.strip().strip("<>")
    elif from_header:
        _, addr = email.utils.parseaddr(from_header)
        sender_email = addr

    if sender_email and "@" in sender_email:
        return sender_email.split("@")[1].strip().lower()
    return None


def _get_spf_record(domain: str) -> str | None:
    """Query DNS TXT records and return the SPF record string if found."""
    if not _DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
        for rdata in answers:
            txt = "".join(
                s.decode() if isinstance(s, bytes) else s
                for s in rdata.strings
            )
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return None


def _parse_allowed_networks(spf_record: str) -> list:
    """Extract ip4 CIDR ranges from an SPF record string."""
    networks = []
    for pattern in re.findall(r'ip4:([0-9./]+)', spf_record):
        try:
            if "/" not in pattern:
                pattern += "/32"
            networks.append(ipaddress.ip_network(pattern, strict=False))
        except Exception:
            continue
    return networks


def _get_sending_ip(msg: email.message.Message) -> str | None:
    """Extract the first IP address found in Received headers."""
    received = msg.get_all("Received", [])
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for header in received:
        ips = re.findall(ip_pattern, header)
        if ips:
            # Skip private/loopback IPs — keep going until public IP found
            for ip in ips:
                try:
                    obj = ipaddress.ip_address(ip)
                    if not obj.is_private and not obj.is_loopback:
                        return ip
                except Exception:
                    continue
    return None


def score_spf(raw_email: str) -> Dict[str, Any]:
    """
    Validate SPF record for the sender domain against the sending IP.

    Returns
    -------
    {
        "score":            float 0.0–1.0   (higher = more suspicious)
        "sender_domain":    str | None
        "sending_ip":       str | None
        "spf_record_found": bool
        "spf_result":       "pass" | "fail" | "no_record" | "dns_error" | "no_ip"
        "features": {
            "spf_fail":         float       (1.0 = hard fail, 0.5 = soft, 0.0 = pass)
            "no_spf_record":    float
            "no_sending_ip":    float
        }
    }
    """
    msg = email.message_from_string(raw_email)

    sender_domain = _get_sender_domain(msg)
    sending_ip    = _get_sending_ip(msg)

    # ── Cannot validate without domain ───────────────────────────────────────
    if not sender_domain:
        return _build_result(
            score=0.6, domain=None, ip=sending_ip,
            spf_found=False, result="dns_error",
            spf_fail=0.6, no_record=0.0, no_ip=0.0
        )

    # ── No sending IP found ──────────────────────────────────────────────────
    if not sending_ip:
        return _build_result(
            score=0.4, domain=sender_domain, ip=None,
            spf_found=False, result="no_ip",
            spf_fail=0.0, no_record=0.0, no_ip=0.4
        )

    # ── DNS lookup ───────────────────────────────────────────────────────────
    spf_record = _get_spf_record(sender_domain)

    if spf_record is None:
        # No SPF = moderate suspicion, not definitive
        return _build_result(
            score=0.45, domain=sender_domain, ip=sending_ip,
            spf_found=False, result="no_record",
            spf_fail=0.0, no_record=0.45, no_ip=0.0
        )

    # ── Check if sending IP is in allowed networks ───────────────────────────
    allowed_networks = _parse_allowed_networks(spf_record)

    try:
        sending_ip_obj = ipaddress.ip_address(sending_ip)
        for network in allowed_networks:
            if sending_ip_obj in network:
                # SPF PASS
                return _build_result(
                    score=0.0, domain=sender_domain, ip=sending_ip,
                    spf_found=True, result="pass",
                    spf_fail=0.0, no_record=0.0, no_ip=0.0
                )
    except Exception:
        pass

    # SPF FAIL — IP not in any authorised range
    return _build_result(
        score=1.0, domain=sender_domain, ip=sending_ip,
        spf_found=True, result="fail",
        spf_fail=1.0, no_record=0.0, no_ip=0.0
    )


def _build_result(
    score, domain, ip, spf_found, result,
    spf_fail, no_record, no_ip
) -> Dict[str, Any]:
    return {
        "score":             round(score, 4),
        "sender_domain":     domain,
        "sending_ip":        ip,
        "spf_record_found":  spf_found,
        "spf_result":        result,
        "features": {
            "spf_fail":      round(spf_fail,  4),
            "no_spf_record": round(no_record, 4),
            "no_sending_ip": round(no_ip,     4),
        }
    }