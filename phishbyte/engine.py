"""
phishbyte/engine.py — v4

CRITICAL FIX from v3:
  Layer 1 only handles EXTREME high-confidence cases.
  Everything else routes to the MLP, which has the real decision boundary.
  Previous v3 was short-circuiting at Layer 1 with low scores, bypassing
  the MLP entirely. The MLP achieves Youden J = 0.656 on the val set —
  we need it to actually run.

New behaviour:
  - Layer 1 phish gate raised to 0.85 (very confident "obvious phishing")
  - Layer 1 clean gate kept low at 0.05 (very confident "nothing suspicious")
  - Almost everything routes to MLP, which is what should be making decisions
  - --force-mlp flag bypasses Layer 1 entirely for debugging
"""

import os
import torch
from typing import Dict, Any, Optional

from phishbyte.extractors.domain  import score_domain
from phishbyte.extractors.urls    import score_urls
from phishbyte.extractors.spf     import score_spf
from phishbyte.extractors.subject import score_subject
from phishbyte.model.mlp          import PhishByteMLPLayer, build_feature_vector, FEATURE_NAMES
from phishbyte.verdict            import PhishVerdict
from phishbyte.calibration        import load_thresholds


# v4 defaults — Layer 1 only handles extreme cases now
FALLBACK_L1_PHISH = 0.85    # was 0.75 — only veto on very obvious phishing
FALLBACK_L1_CLEAN = 0.05    # was 0.25 — only veto on very obvious legit
FALLBACK_L2_PHISH = 0.70    # MLP threshold — set per calibration
FALLBACK_L2_CLEAN = 0.30

_WEIGHTS_DIR        = os.path.join(os.path.dirname(__file__), "model", "weights")
DEFAULT_WEIGHTS     = os.path.join(_WEIGHTS_DIR, "phishbyte_mlp.pt")
DEFAULT_THRESHOLDS  = os.path.join(_WEIGHTS_DIR, "thresholds.json")


class PhishByteEngine:
    """
    v4 cascade — MLP-centric routing.

    Layer 1 acts as a fast veto only — handles extreme cases (P > 0.85 obvious
    phishing, P < 0.05 obvious legitimate). Everything else (the uncertain
    middle, which is most real email) gets routed to the trained MLP, which
    has learned the actual decision boundary.
    """

    def __init__(self, weights_path=None, thresholds_path=None, force_mlp=False):
        self.model: Optional[PhishByteMLPLayer] = None
        self._model_loaded = False
        self.force_mlp = force_mlp

        wpath = weights_path or DEFAULT_WEIGHTS
        if os.path.exists(wpath):
            self._load_model(wpath)
        else:
            print(f"[PhishByte] No weights at {wpath}. Layer 1 only.")

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
                    f"[PhishByte] Thresholds — "
                    f"L1: ≥{self.l1_phish:.3f}/≤{self.l1_clean:.3f}  "
                    f"L2: ≥{self.l2_phish:.3f}/≤{self.l2_clean:.3f}"
                )
            except Exception as e:
                print(f"[PhishByte] Threshold load failed: {e}. Fallback values.")
                self._use_fallback_thresholds()
        else:
            print(f"[PhishByte] Using fallback thresholds.")
            self._use_fallback_thresholds()

        if self.force_mlp:
            print(f"[PhishByte] FORCE-MLP mode: bypassing Layer 1 routing.")

    def _use_fallback_thresholds(self):
        self.l1_phish, self.l1_clean = FALLBACK_L1_PHISH, FALLBACK_L1_CLEAN
        self.l2_phish, self.l2_clean = FALLBACK_L2_PHISH, FALLBACK_L2_CLEAN
        self._calibrated = False

    def _load_model(self, path):
        try:
            self.model = PhishByteMLPLayer()
            state = torch.load(path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state)
            self.model.eval()
            self._model_loaded = True
            print(f"[PhishByte] MLP loaded from {path}")
        except Exception as e:
            print(f"[PhishByte] Failed to load weights: {e}.")
            self.model = None
            self._model_loaded = False

    def analyze(self, raw_email: str) -> PhishVerdict:
        d   = score_domain(raw_email)
        u   = score_urls(raw_email)
        s   = score_spf(raw_email)
        sub = score_subject(raw_email)

        l1_score = self._layer1_composite(d, u, s, sub)
        feature_weights = self._build_feature_weights(d, u, s, sub)

        # Layer 1 acts as VETO only — extreme cases short-circuit
        if not self.force_mlp:
            if l1_score >= self.l1_phish:
                return PhishVerdict(
                    label="phishing", probability=round(l1_score, 4),
                    confidence="high", layer_used=1,
                    feature_weights=feature_weights,
                    detail=self._l1_detail(d, u, s, sub),
                )
            if l1_score <= self.l1_clean:
                return PhishVerdict(
                    label="legitimate", probability=round(l1_score, 4),
                    confidence="high", layer_used=1,
                    feature_weights=feature_weights,
                    detail="No suspicious signals detected at Layer 1.",
                )

        # Default path: MLP decides
        if self._model_loaded and self.model is not None:
            fvec    = build_feature_vector(d, u, s, sub)
            l2_prob = self.model.predict_proba(fvec)
            feature_weights.update(self._posthoc_attribution(fvec))

            label = "phishing" if l2_prob >= 0.5 else "legitimate"
            if l2_prob >= self.l2_phish or l2_prob <= self.l2_clean:
                confidence = "high"
            elif 0.35 <= l2_prob <= 0.65:
                confidence = "low"
            else:
                confidence = "medium"

            return PhishVerdict(
                label=label, probability=round(l2_prob, 4),
                confidence=confidence, layer_used=2,
                feature_weights=feature_weights,
                detail=f"MLP probability: {l2_prob:.2%}. Layer 1 score: {l1_score:.2%}.",
            )

        return PhishVerdict(
            label="phishing" if l1_score > 0.5 else "legitimate",
            probability=round(l1_score, 4),
            confidence="medium", layer_used=1,
            feature_weights=feature_weights,
            detail=f"No MLP available. Layer 1 only ({l1_score:.2%}).",
        )

    @staticmethod
    def _layer1_composite(d, u, s, sub):
        return min(1.0,
            d["score"]*0.30 + u["score"]*0.30 + sub["score"]*0.25 + s["score"]*0.15
        )

    @staticmethod
    def _build_feature_weights(d, u, s, sub):
        w = {}
        w.update(d["features"]); w.update(u["features"])
        w.update(s["features"]); w.update(sub["features"])
        w["domain_layer_score"]  = d["score"]
        w["url_layer_score"]     = u["score"]
        w["spf_layer_score"]     = s["score"]
        w["subject_layer_score"] = sub["score"]
        return w

    @staticmethod
    def _posthoc_attribution(fvec):
        return {
            f"attribution_{name}": round(float(fvec[i]), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }

    @staticmethod
    def _l1_detail(d, u, s, sub):
        fired = []
        if d["features"]["domain_mismatch"] > 0:        fired.append("domain mismatch")
        if d["features"]["replyto_differs"] > 0:        fired.append("Reply-To differs")
        if d["features"]["brand_impersonation"] > 0:    fired.append("brand impersonation")
        if s["spf_result"] == "fail":                   fired.append("SPF fail")
        if u["features"]["anchor_mismatch_score"] > 0:  fired.append("anchor mismatch")
        if u["features"]["urgency_score"] > 0.3:        fired.append("body urgency")
        if u["features"]["http_ratio"] > 0.5:           fired.append("high HTTP ratio")
        if sub["features"]["subject_urgency"] > 0.3:    fired.append("subject urgency")
        if sub["features"]["subject_brand_name"] > 0:   fired.append("brand in subject")
        return "Signals fired: " + (", ".join(fired) if fired else "composite threshold")