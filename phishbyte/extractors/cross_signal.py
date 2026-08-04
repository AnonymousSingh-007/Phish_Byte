"""
phishbyte/extractors/cross_signal.py — NEW MODULE

This is the layer that was missing: features computed AFTER all six base
extractors run, capturing interactions between them that no single
extractor can see alone.

This directly targets the GitHub false-positive pattern: SPF passes +
consistent root domains + high link count to ONE legitimate domain should
actively DISCOUNT the phishing signal, not sit next to it unexplained.

Called once per email, after domain/urls/spf/subject/bdi have all run.
Takes their output dicts as input — computes nothing from raw email text.
"""
from typing import Dict, Any


def score_cross_signal(
    domain_result: Dict[str, Any],
    url_result:    Dict[str, Any],
    spf_result:    Dict[str, Any],
    bdi_result:    Dict[str, Any],
) -> Dict[str, Any]:
    """
    Cross-extractor interaction features.

    Features (5):
        trust_consistency_score  — SPF pass + matching root domains across
                                    From/Reply-To/Return-Path + MCLD matches
                                    sender = strong legitimacy signal
        spf_pass_url_discount    — if SPF passes, high link density / BDI
                                    scores are discounted (legitimate senders
                                    with SPF can still send link-heavy mail)
        multi_signal_phish_score — how many of {domain, url, bdi, subject}
                                    independently flagged phishing >0.5.
                                    Agreement across modules is much stronger
                                    evidence than one module firing alone.
        domain_bdi_agreement     — domain mismatch AND mcld_mismatch fire
                                    together = compounding evidence, not
                                    just additive
        lexical_brand_confusion  — sender domain lexically resembles a brand
                                    (from BDI's mcld_lexical) AND domain
                                    extractor's brand_impersonation both fire
    """
    spf_passed = spf_result.get("spf_result") == "pass"

    # ── Trust consistency ─────────────────────────────────────────────────────
    # High when: SPF passes, domains are internally consistent, MCLD matches sender
    domains_match  = domain_result.get("domains_match", False)
    mcld_mismatch  = bdi_result["features"].get("mcld_mismatch", 0.0)
    trust_consistency_score = 0.0
    if spf_passed:
        trust_consistency_score += 0.5
    if domains_match:
        trust_consistency_score += 0.3
    if mcld_mismatch < 0.5:
        trust_consistency_score += 0.2
    trust_consistency_score = min(1.0, trust_consistency_score)

    # ── SPF-pass discount ─────────────────────────────────────────────────────
    # If SPF passes, legitimate high-link-count notification emails
    # (GitHub, Jira, AWS) shouldn't be penalized as heavily for link density.
    # This is a DOWNWARD adjustment applied conceptually — the MLP learns
    # to use it, we just hand it the raw material.
    link_density = url_result["features"].get("link_density_score", 0.0)
    spf_pass_url_discount = link_density * (0.3 if spf_passed else 1.0)
    spf_pass_url_discount = round(min(1.0, spf_pass_url_discount), 4)

    # ── Multi-signal agreement ────────────────────────────────────────────────
    # Count how many independent modules score above 0.5 — agreement across
    # modules is much stronger evidence than any single module firing alone.
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
    )  # multiplicative — both must fire for this to be high

    # ── Lexical brand confusion (typosquat + impersonation both firing) ──────
    mcld_lexical = bdi_result.get("mcld_lexical", {})
    typosquat_score = mcld_lexical.get("brand_typosquat_score", 0.0)
    brand_imperson  = domain_result["features"].get("brand_impersonation", 0.0)
    lexical_brand_confusion = round(min(1.0, typosquat_score * 0.6 + brand_imperson * 0.4), 4)

    score = min(1.0,
        (1.0 - trust_consistency_score) * 0.20 +   # inverse — low trust raises score
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