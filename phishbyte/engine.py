"""
phishbyte/engine.py
The PhishByte cascading analysis engine.

Flow:
    Email → Layer 1 (rules) → gate → Layer 2 (MLP) → gate → Layer 3 (deep) → Verdict

Layer 2 only runs if Layer 1 is uncertain.
Layer 3 only runs if Layer 2 is uncertain.
Every verdict carries probability, confidence, layer_used, and feature weights.
"""

import os
import torch
from typing import Dict, Any, Optional

from phishbyte.extractors.domain import score_domain
from phishbyte.extractors.urls   import score_urls
from phishbyte.extractors.spf    import score_spf
from phishbyte.model.mlp         import PhishByteMLPLayer, build_feature_vector, FEATURE_NAMES
from phishbyte.verdict           import PhishVerdict


# ── Thresholds ────────────────────────────────────────────────────────────────
# If Layer 1 composite score is outside this band → confident, skip Layer 2
L1_PHISH_THRESHOLD  = 0.75   # above → phishing, high confidence
L1_CLEAN_THRESHOLD  = 0.25   # below → legitimate, high confidence
# If MLP output is outside this band → confident, skip Layer 3
L2_PHISH_THRESHOLD  = 0.80
L2_CLEAN_THRESHOLD  = 0.20

DEFAULT_WEIGHTS_PATH = os.path.join(
    os.path.dirname(__file__), "model", "weights", "phishbyte_mlp.pt"
)


class PhishByteEngine:
    """
    Cascading phishing analysis engine.

    Usage
    -----
    engine  = PhishByteEngine()               # Layer 2 untrained (rule-only mode)
    engine  = PhishByteEngine(weights="...")  # Layer 2 loaded from checkpoint
    verdict = engine.analyze(raw_email_str)
    print(verdict)
    """

    def __init__(self, weights_path: Optional[str] = None):
        self.model: Optional[PhishByteMLPLayer] = None
        self._model_loaded = False

        # Try loading MLP weights
        path = weights_path or DEFAULT_WEIGHTS_PATH
        if os.path.exists(path):
            self._load_model(path)
        else:
            print(
                f"[PhishByte] No weights found at {path}. "
                "Running in Layer 1 rule-only mode until training is complete."
            )

    def _load_model(self, path: str):
        """Load trained MLP checkpoint."""
        try:
            self.model = PhishByteMLPLayer()
            state = torch.load(path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state)
            self.model.eval()
            self._model_loaded = True
            print(f"[PhishByte] MLP loaded from {path}")
        except Exception as e:
            print(f"[PhishByte] Failed to load weights: {e}. Falling back to Layer 1.")
            self.model = None
            self._model_loaded = False

    # ── Public API ────────────────────────────────────────────────────────────

    def analyze(self, raw_email: str) -> PhishVerdict:
        """
        Run the full cascading analysis pipeline on a raw email string.

        Parameters
        ----------
        raw_email : str
            Complete email including headers. Paste from your email client
            (View Source / Show Original).

        Returns
        -------
        PhishVerdict dataclass with label, probability, confidence,
        layer_used, and per-feature weights.
        """
        # ── Layer 1 ───────────────────────────────────────────────────────────
        domain_result = score_domain(raw_email)
        url_result    = score_urls(raw_email)
        spf_result    = score_spf(raw_email)

        l1_score      = self._layer1_composite(domain_result, url_result, spf_result)
        feature_weights = self._build_feature_weights(domain_result, url_result, spf_result)

        # Gate 1 — high confidence from rules alone?
        if l1_score >= L1_PHISH_THRESHOLD:
            return PhishVerdict(
                label           = "phishing",
                probability     = round(l1_score, 4),
                confidence      = "high",
                layer_used      = 1,
                feature_weights = feature_weights,
                detail          = self._l1_detail(domain_result, url_result, spf_result),
            )

        if l1_score <= L1_CLEAN_THRESHOLD:
            return PhishVerdict(
                label           = "legitimate",
                probability     = round(l1_score, 4),
                confidence      = "high",
                layer_used      = 1,
                feature_weights = feature_weights,
                detail          = "All Layer 1 signals within safe thresholds.",
            )

        # ── Layer 2 — MLP ─────────────────────────────────────────────────────
        if self._model_loaded and self.model is not None:
            fvec      = build_feature_vector(domain_result, url_result, spf_result)
            l2_prob   = self.model.predict_proba(fvec)
            mlp_weights = self._mlp_feature_weights(fvec)

            # Merge MLP attribution into feature weights
            feature_weights.update(mlp_weights)

            if l2_prob >= L2_PHISH_THRESHOLD:
                return PhishVerdict(
                    label           = "phishing",
                    probability     = round(l2_prob, 4),
                    confidence      = "high",
                    layer_used      = 2,
                    feature_weights = feature_weights,
                    detail          = f"MLP confidence: {l2_prob:.2%}. Layer 1 was uncertain at {l1_score:.2%}.",
                )

            if l2_prob <= L2_CLEAN_THRESHOLD:
                return PhishVerdict(
                    label           = "legitimate",
                    probability     = round(l2_prob, 4),
                    confidence      = "high",
                    layer_used      = 2,
                    feature_weights = feature_weights,
                    detail          = f"MLP confidence: {(1-l2_prob):.2%} legitimate.",
                )

            # Still uncertain after Layer 2
            return PhishVerdict(
                label           = "phishing" if l2_prob > 0.5 else "legitimate",
                probability     = round(l2_prob, 4),
                confidence      = "low",
                layer_used      = 2,
                feature_weights = feature_weights,
                detail          = (
                    f"Layer 2 uncertain at {l2_prob:.2%}. "
                    "Layer 3 deep analysis not yet implemented — "
                    "treat with caution."
                ),
            )

        # ── No model loaded — return Layer 1 uncertain verdict ────────────────
        return PhishVerdict(
            label           = "phishing" if l1_score > 0.5 else "legitimate",
            probability     = round(l1_score, 4),
            confidence      = "medium",
            layer_used      = 1,
            feature_weights = feature_weights,
            detail          = (
                f"Layer 1 uncertain ({l1_score:.2%}). "
                "Train and load MLP weights for Layer 2 analysis."
            ),
        )

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _layer1_composite(
        domain_result: Dict,
        url_result:    Dict,
        spf_result:    Dict,
    ) -> float:
        """
        Weighted composite of the three Layer 1 scorer outputs.
        Domain and URL signals carry more weight than SPF alone.
        """
        return min(1.0,
            domain_result["score"] * 0.40 +
            url_result["score"]    * 0.40 +
            spf_result["score"]    * 0.20
        )

    @staticmethod
    def _build_feature_weights(
        domain_result: Dict,
        url_result:    Dict,
        spf_result:    Dict,
    ) -> Dict[str, float]:
        """Flatten all sub-feature scores into a single dict for the verdict."""
        weights = {}
        weights.update(domain_result["features"])
        weights.update(url_result["features"])
        weights.update(spf_result["features"])
        weights["domain_layer_score"] = domain_result["score"]
        weights["url_layer_score"]    = url_result["score"]
        weights["spf_layer_score"]    = spf_result["score"]
        return weights

    @staticmethod
    def _mlp_feature_weights(fvec: torch.Tensor) -> Dict[str, float]:
        """
        Naïve feature attribution: raw input values as importance proxy.
        Replaced by SHAP once training is complete.
        """
        return {
            f"mlp_input_{name}": round(float(fvec[i]), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }

    @staticmethod
    def _l1_detail(domain_result: Dict, url_result: Dict, spf_result: Dict) -> str:
        """Build a human-readable summary of which Layer 1 signals fired."""
        fired = []
        if domain_result["features"]["domain_mismatch"] > 0:
            fired.append("domain mismatch")
        if domain_result["features"]["replyto_differs"] > 0:
            fired.append("Reply-To differs")
        if spf_result["spf_result"] == "fail":
            fired.append("SPF fail")
        if url_result["features"]["anchor_mismatch_score"] > 0:
            fired.append("anchor mismatch")
        if url_result["features"]["urgency_score"] > 0.3:
            fired.append("urgency keywords")
        if url_result["features"]["http_ratio"] > 0.5:
            fired.append("high HTTP ratio")
        return "Signals fired: " + (", ".join(fired) if fired else "composite threshold")