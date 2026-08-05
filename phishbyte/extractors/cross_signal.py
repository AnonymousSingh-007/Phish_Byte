"""
phishbyte/extractors/cross_signal.py — v2

Key change: trust_consistency_score now uses DMARC pass + DKIM alignment
as the primary trust anchor instead of raw SPF result.
This fixes false positives on ESP-relayed legitimate email.

DMARC alignment is the correct metric because:
  - It was designed to handle third-party senders (Marketo, Mailgun, etc.)
  - It validates the From domain (what the user sees) not the envelope sender
  - p=REJECT means the domain owner will not legitimate mail fail DMARC
"""
from typing import Dict, Any


def score_cross_signal(
    domain_result: Dict[str, Any],
    url_result:    Dict[str, Any],
    spf_result:    Dict[str, Any],
    bdi_result:    Dict[str, Any],
) -> Dict[str, Any]:
    """
    Cross-extractor interaction features — v2.

    Features (5):
        trust_consistency_score  — DMARC pass + DKIM aligned + domain consistency
                                   + MCLD matches sender = legitimacy signal
        spf_pass_url_discount    — if auth aligns, discount link density penalty
        multi_signal_phish_score — how many independent modules flag >0.5
        domain_bdi_agreement     — domain mismatch AND mcld_mismatch compound
        lexical_brand_confusion  — typosquat + brand impersonation compound
    """
    f_spf = spf_result.get("features", {})

    # ── Trust consistency — now DMARC/DKIM anchored ──────────────────────────
    dmarc_pass       = f_spf.get("dmarc_pass", 0.0)
    dkim_aligned     = f_spf.get("dkim_aligned", 0.0)
    auth_align_score = f_spf.get("auth_alignment_score", 1.0)  # low=trusted
    domains_match    = domain_result.get("domains_match", False)
    mcld_mismatch    = bdi_result["features"].get("mcld_mismatch", 0.0)

    trust_consistency_score = 0.0
    # DMARC pass is now the primary trust anchor (was raw SPF before)
    if dmarc_pass >= 1.0:
        trust_consistency_score += 0.45
    # DKIM aligned to From domain adds structural trust
    if dkim_aligned >= 1.0:
        trust_consistency_score += 0.25
    # Header domain consistency
    if domains_match:
        trust_consistency_score += 0.15
    # BDI: most-common-link-domain matches sender
    if mcld_mismatch < 0.5:
        trust_consistency_score += 0.15
    trust_consistency_score = min(1.0, trust_consistency_score)

    # ── Auth-pass URL discount ────────────────────────────────────────────────
    # If DMARC passes AND DKIM is aligned, ESP-sent email with many tracking
    # links should not be penalized for link density.
    # auth_alignment_score is 0.0 for fully trusted, 1.0 for no auth.
    link_density = url_result["features"].get("link_density_score", 0.0)
    auth_trust   = 1.0 - auth_align_score  # 1.0 = fully trusted
    spf_pass_url_discount = round(link_density * (1.0 - auth_trust * 0.7), 4)

    # ── Multi-signal agreement ────────────────────────────────────────────────
    module_scores = [
        domain_result.get("score", 0.0),
        url_result.get("score", 0.0),
        bdi_result.get("score", 0.0),
    ]
    n_agreeing = sum(1 for s in module_scores if s > 0.5)
    multi_signal_phish_score = round(n_agreeing / len(module_scores), 4)

    # ── Domain + BDI compounding ──────────────────────────────────────────────
    domain_mismatch_val = domain_result["features"].get("domain_mismatch", 0.0)
    domain_bdi_agreement = round(
        min(1.0, domain_mismatch_val * mcld_mismatch * 1.5), 4
    )

    # ── Lexical brand confusion ───────────────────────────────────────────────
    mcld_lexical    = bdi_result.get("mcld_lexical", {})
    typosquat_score = mcld_lexical.get("brand_typosquat_score", 0.0)
    brand_imperson  = domain_result["features"].get("brand_impersonation", 0.0)
    lexical_brand_confusion = round(
        min(1.0, typosquat_score * 0.6 + brand_imperson * 0.4), 4
    )

    # ── Composite cross-signal score ──────────────────────────────────────────
    score = min(1.0,
        (1.0 - trust_consistency_score) * 0.20 +
        spf_pass_url_discount           * 0.15 +
        multi_signal_phish_score        * 0.30 +
        domain_bdi_agreement            * 0.20 +
        lexical_brand_confusion         * 0.15
    )

    return {
        "score": round(score, 4),
        "features": {
            "trust_consistency_score":  round(trust_consistency_score, 4),
            "spf_pass_url_discount":    spf_pass_url_discount,
            "multi_signal_phish_score": multi_signal_phish_score,
            "domain_bdi_agreement":     domain_bdi_agreement,
            "lexical_brand_confusion":  lexical_brand_confusion,
        }
    }