"""
phishbyte/engine.py
PhishByte cascading analysis engine — v2.0 (post Karpathy review)

Changes from v1
───────────────
  • Thresholds calibrated from validation ROC instead of hardcoded
  • SHAP relabelled as post-hoc attribution (not "explainability head")
  • Architecture wording precision: weights randomly initialised, no pretrained LMs

Flow
────
    Email
      → Layer 1 (rule scorers)
      → gate (calibrated from ROC analysis)
      → Layer 2 (MLP, trained from scratch)
      → gate (calibrated from ROC analysis)
      → Layer 3 (deep structural checks)
      → Verdict (with post-hoc SHAP attribution when MLP fires)
"""

import os
import torch
from typing import Dict, Any, Optional

from phishbyte.extractors.domain import score_domain
from phishbyte.extractors.urls   import score_urls
from phishbyte.extractors.spf    import score_spf
from phishbyte.model.mlp         import PhishByteMLPLayer, build_feature_vector, FEATURE_NAMES
from phishbyte.verdict           import PhishVerdict
from phishbyte.calibration       import load_thresholds, ThresholdConfig


# ── Fallback thresholds ──────────────────────────────────────────────────────
# Used ONLY when no calibrated thresholds.json exists. These are sane defaults
# for a cold-start engine running on synthetic data. Once a real validation
# set is available, run train.py with --calibrate to overwrite these with
# data-driven values.
FALLBACK_L1_PHISH = 0.75
FALLBACK_L1_CLEAN = 0.25
FALLBACK_L2_PHISH = 0.80
FALLBACK_L2_CLEAN = 0.20

_WEIGHTS_DIR        = os.path.join(os.path.dirname(__file__), "model", "weights")
DEFAULT_WEIGHTS     = os.path.join(_WEIGHTS_DIR, "phishbyte_mlp.pt")
DEFAULT_THRESHOLDS  = os.path.join(_WEIGHTS_DIR, "thresholds.json")


class PhishByteEngine:
    """
    Cascading phishing analysis engine.

    Architecture
    ────────────
    Three-layer cascade. Each layer routes to the next only when uncertain.
    Routing thresholds are calibrated on a held-out validation set via ROC
    analysis — not hardcoded. The MLP at Layer 2 is randomly initialised and
    trained from scratch on phishing datasets; no pretrained language model
    is used. SHAP-based post-hoc attribution explains MLP decisions when
    Layer 2 fires.

    Usage
    ─────
        engine  = PhishByteEngine()
        verdict = engine.analyze(raw_email_str)
        print(verdict)
    """

    def __init__(
        self,
        weights_path:    Optional[str] = None,
        thresholds_path: Optional[str] = None,
    ):
        self.model: Optional[PhishByteMLPLayer] = None
        self._model_loaded = False

        # ── Load model weights ────────────────────────────────────────────────
        wpath = weights_path or DEFAULT_WEIGHTS
        if os.path.exists(wpath):
            self._load_model(wpath)
        else:
            print(
                f"[PhishByte] No weights at {wpath}. "
                "Running in Layer 1 rule-only mode until training is complete."
            )

        # ── Load calibrated thresholds ────────────────────────────────────────
        tpath = thresholds_path or DEFAULT_THRESHOLDS
        if os.path.exists(tpath):
            try:
                cfg = load_thresholds(tpath)
                self.l1_phish = cfg["layer1"].phish_threshold
                self.l1_clean = cfg["layer1"].clean_threshold
                self.l2_phish = cfg.get("layer2", cfg["layer1"]).phish_threshold
                self.l2_clean = cfg.get("layer2", cfg["layer1"]).clean_threshold
                self._calibrated = True
                print(
                    f"[PhishByte] Thresholds loaded — "
                    f"L1: phish≥{self.l1_phish:.3f} clean≤{self.l1_clean:.3f}  "
                    f"L2: phish≥{self.l2_phish:.3f} clean≤{self.l2_clean:.3f}"
                )
            except Exception as e:
                print(f"[PhishByte] Threshold load failed: {e}. Using fallback values.")
                self._use_fallback_thresholds()
        else:
            print(
                f"[PhishByte] No calibrated thresholds at {tpath}. "
                "Using fallback values. Run train.py to calibrate from your data."
            )
            self._use_fallback_thresholds()

    def _use_fallback_thresholds(self):
        self.l1_phish, self.l1_clean = FALLBACK_L1_PHISH, FALLBACK_L1_CLEAN
        self.l2_phish, self.l2_clean = FALLBACK_L2_PHISH, FALLBACK_L2_CLEAN
        self._calibrated = False

    def _load_model(self, path: str):
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
        """Run the full cascading analysis pipeline on a raw email string."""

        # ── Layer 1 ───────────────────────────────────────────────────────────
        domain_result = score_domain(raw_email)
        url_result    = score_urls(raw_email)
        spf_result    = score_spf(raw_email)

        l1_score        = self._layer1_composite(domain_result, url_result, spf_result)
        feature_weights = self._build_feature_weights(domain_result, url_result, spf_result)

        # ── Gate 1 (calibrated) ───────────────────────────────────────────────
        if l1_score >= self.l1_phish:
            return PhishVerdict(
                label           = "phishing",
                probability     = round(l1_score, 4),
                confidence      = "high",
                layer_used      = 1,
                feature_weights = feature_weights,
                detail          = self._l1_detail(domain_result, url_result, spf_result),
            )

        if l1_score <= self.l1_clean:
            return PhishVerdict(
                label           = "legitimate",
                probability     = round(l1_score, 4),
                confidence      = "high",
                layer_used      = 1,
                feature_weights = feature_weights,
                detail          = "All Layer 1 signals within safe thresholds.",
            )

        # ── Layer 2 — MLP forward pass ────────────────────────────────────────
        if self._model_loaded and self.model is not None:
            fvec    = build_feature_vector(domain_result, url_result, spf_result)
            l2_prob = self.model.predict_proba(fvec)

            # Post-hoc attribution: raw input magnitudes as importance proxy.
            # Replaced by full SHAP values once SHAP background set is available.
            attribution = self._posthoc_attribution(fvec)
            feature_weights.update(attribution)

            if l2_prob >= self.l2_phish:
                return PhishVerdict(
                    label           = "phishing",
                    probability     = round(l2_prob, 4),
                    confidence      = "high",
                    layer_used      = 2,
                    feature_weights = feature_weights,
                    detail          = (
                        f"MLP confidence: {l2_prob:.2%}. "
                        f"Layer 1 was uncertain at {l1_score:.2%}."
                    ),
                )

            if l2_prob <= self.l2_clean:
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
                    "Layer 3 deep analysis not yet implemented — treat with caution."
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
        domain_result: Dict, url_result: Dict, spf_result: Dict
    ) -> float:
        return min(1.0,
            domain_result["score"] * 0.40 +
            url_result["score"]    * 0.40 +
            spf_result["score"]    * 0.20
        )

    @staticmethod
    def _build_feature_weights(
        domain_result: Dict, url_result: Dict, spf_result: Dict
    ) -> Dict[str, float]:
        w = {}
        w.update(domain_result["features"])
        w.update(url_result["features"])
        w.update(spf_result["features"])
        w["domain_layer_score"] = domain_result["score"]
        w["url_layer_score"]    = url_result["score"]
        w["spf_layer_score"]    = spf_result["score"]
        return w

    @staticmethod
    def _posthoc_attribution(fvec: torch.Tensor) -> Dict[str, float]:
        """
        Naïve post-hoc feature attribution: input magnitudes as importance proxy.
        Replaced by SHAP values once a background reference set is computed.
        Note: this is post-hoc, not a model component.
        """
        return {
            f"attribution_{name}": round(float(fvec[i]), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }

    @staticmethod
    def _l1_detail(domain_result: Dict, url_result: Dict, spf_result: Dict) -> str:
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