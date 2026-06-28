"""
phishbyte/extractors/spf.py
Layer 1 — SPF validation scorer.

Two modes:
  - LIVE (default): performs real DNS TXT lookups, validates sending IP against
    SPF record. Used at inference time on fresh emails.
  - SKIP (training): returns neutral scores without any DNS calls. Used when
    training on historical datasets where domains may be dead or DNS would
    take hours. Toggled via environment variable PHISHBYTE_SKIP_SPF=1.
"""

import os
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


def _spf_skipped() -> bool:
    """Check env var. Set PHISHBYTE_SKIP_SPF=1 to bypass DNS during training."""
    return os.environ.get("PHISHBYTE_SKIP_SPF", "0") == "1"


def _neutral_result(domain=None, ip=None) -> Dict[str, Any]:
    """Return a neutral SPF result — neither pass nor fail."""
    return {
        "score":            0.0,
        "sender_domain":    domain,
        "sending_ip":       ip,
        "spf_record_found": False,
        "spf_result":       "skipped",
        "features": {
            "spf_fail":      0.0,
            "no_spf_record": 0.0,
            "no_sending_ip": 0.0,
        },
    }


def _get_sender_domain(msg: email.message.Message):
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


def _get_spf_record(domain: str):
    if not _DNS_AVAILABLE:
        return None
    try:
        answers = dns.resolver.resolve(domain, "TXT", lifetime=5.0)
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s
                          for s in rdata.strings)
            if txt.startswith("v=spf1"):
                return txt
    except Exception:
        pass
    return None


def _parse_allowed_networks(spf_record: str) -> list:
    networks = []
    for pattern in re.findall(r'ip4:([0-9./]+)', spf_record):
        try:
            if "/" not in pattern:
                pattern += "/32"
            networks.append(ipaddress.ip_network(pattern, strict=False))
        except Exception:
            continue
    return networks


def _get_sending_ip(msg: email.message.Message):
    received = msg.get_all("Received", [])
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    for header in received:
        ips = re.findall(ip_pattern, header)
        for ip in ips:
            try:
                obj = ipaddress.ip_address(ip)
                if not obj.is_private and not obj.is_loopback:
                    return ip
            except Exception:
                continue
    return None


def _build_result(score, domain, ip, spf_found, result,
                  spf_fail, no_record, no_ip) -> Dict[str, Any]:
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
        },
    }


def score_spf(raw_email: str) -> Dict[str, Any]:
    """
    Validate SPF for the sender domain against the sending IP.
    If PHISHBYTE_SKIP_SPF=1, returns a neutral result with no DNS calls.
    """
    if _spf_skipped():
        try:
            msg = email.message_from_string(raw_email)
            return _neutral_result(_get_sender_domain(msg), _get_sending_ip(msg))
        except Exception:
            return _neutral_result()

    msg = email.message_from_string(raw_email)
    sender_domain = _get_sender_domain(msg)
    sending_ip    = _get_sending_ip(msg)

    if not sender_domain:
        return _build_result(0.6, None, sending_ip, False, "dns_error",
                             0.6, 0.0, 0.0)
    if not sending_ip:
        return _build_result(0.4, sender_domain, None, False, "no_ip",
                             0.0, 0.0, 0.4)

    spf_record = _get_spf_record(sender_domain)
    if spf_record is None:
        return _build_result(0.45, sender_domain, sending_ip, False, "no_record",
                             0.0, 0.45, 0.0)

    allowed_networks = _parse_allowed_networks(spf_record)
    try:
        sending_ip_obj = ipaddress.ip_address(sending_ip)
        for network in allowed_networks:
            if sending_ip_obj in network:
                return _build_result(0.0, sender_domain, sending_ip, True, "pass",
                                     0.0, 0.0, 0.0)
    except Exception:
        pass

    return _build_result(1.0, sender_domain, sending_ip, True, "fail",
                         1.0, 0.0, 0.0)