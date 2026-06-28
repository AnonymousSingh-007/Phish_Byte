"""
phishbyte/engine.py
PhishByte cascading analysis engine — v3.

Changes from v2
───────────────
  • Added subject scorer to Layer 1 (4 extractors now)
  • Brand impersonation rolled into domain score
  • Composite L1 score reweighted across 4 modules
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

    Four Layer 1 scorers feed both the gate logic and the Layer 2 MLP:
      • domain  — From/Reply-To/Return-Path consistency + brand impersonation
      • url     — HTTPS ratio, anchor mismatches, suspicious TLDs, urgency
      • spf     — DNS-based SPF validation (skipped on historical training data)
      • subject — urgency, security theme, brand names, fake transaction IDs

    Layer 2 MLP only runs when Layer 1 is uncertain.
    Thresholds calibrated from validation ROC analysis.
    """

    def __init__(
        self,
        weights_path:    Optional[str] = None,
        thresholds_path: Optional[str] = None,
    ):
        self.model: Optional[PhishByteMLPLayer] = None
        self._model_loaded = False

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
                    f"[PhishByte] Thresholds loaded — "
                    f"L1: phish≥{self.l1_phish:.3f} clean≤{self.l1_clean:.3f}  "
                    f"L2: phish≥{self.l2_phish:.3f} clean≤{self.l2_clean:.3f}"
                )
            except Exception as e:
                print(f"[PhishByte] Threshold load failed: {e}. Fallback values.")
                self._use_fallback_thresholds()
        else:
            print(f"[PhishByte] No calibrated thresholds. Using fallback.")
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
            print(f"[PhishByte] Failed to load weights: {e}. Layer 1 only.")
            self.model = None
            self._model_loaded = False

    def analyze(self, raw_email: str) -> PhishVerdict:
        domain_result  = score_domain(raw_email)
        url_result     = score_urls(raw_email)
        spf_result     = score_spf(raw_email)
        subject_result = score_subject(raw_email)

        l1_score = self._layer1_composite(
            domain_result, url_result, spf_result, subject_result
        )
        feature_weights = self._build_feature_weights(
            domain_result, url_result, spf_result, subject_result
        )

        if l1_score >= self.l1_phish:
            return PhishVerdict(
                label="phishing", probability=round(l1_score, 4),
                confidence="high", layer_used=1,
                feature_weights=feature_weights,
                detail=self._l1_detail(domain_result, url_result, spf_result, subject_result),
            )

        if l1_score <= self.l1_clean:
            return PhishVerdict(
                label="legitimate", probability=round(l1_score, 4),
                confidence="high", layer_used=1,
                feature_weights=feature_weights,
                detail="All Layer 1 signals within safe thresholds.",
            )

        if self._model_loaded and self.model is not None:
            fvec    = build_feature_vector(domain_result, url_result, spf_result, subject_result)
            l2_prob = self.model.predict_proba(fvec)
            attribution = self._posthoc_attribution(fvec)
            feature_weights.update(attribution)

            if l2_prob >= self.l2_phish:
                return PhishVerdict(
                    label="phishing", probability=round(l2_prob, 4),
                    confidence="high", layer_used=2,
                    feature_weights=feature_weights,
                    detail=f"MLP confidence: {l2_prob:.2%}. Layer 1 was uncertain at {l1_score:.2%}.",
                )
            if l2_prob <= self.l2_clean:
                return PhishVerdict(
                    label="legitimate", probability=round(l2_prob, 4),
                    confidence="high", layer_used=2,
                    feature_weights=feature_weights,
                    detail=f"MLP confidence: {(1-l2_prob):.2%} legitimate.",
                )
            return PhishVerdict(
                label="phishing" if l2_prob > 0.5 else "legitimate",
                probability=round(l2_prob, 4),
                confidence="low", layer_used=2,
                feature_weights=feature_weights,
                detail=f"Layer 2 uncertain at {l2_prob:.2%}. Layer 3 not implemented.",
            )

        return PhishVerdict(
            label="phishing" if l1_score > 0.5 else "legitimate",
            probability=round(l1_score, 4),
            confidence="medium", layer_used=1,
            feature_weights=feature_weights,
            detail=f"Layer 1 uncertain ({l1_score:.2%}). Train MLP for Layer 2.",
        )

    @staticmethod
    def _layer1_composite(d, u, s, sub) -> float:
        return min(1.0,
            d["score"]   * 0.30 +
            u["score"]   * 0.30 +
            sub["score"] * 0.25 +
            s["score"]   * 0.15
        )

    @staticmethod
    def _build_feature_weights(d, u, s, sub) -> Dict[str, float]:
        w = {}
        w.update(d["features"])
        w.update(u["features"])
        w.update(s["features"])
        w.update(sub["features"])
        w["domain_layer_score"]  = d["score"]
        w["url_layer_score"]     = u["score"]
        w["spf_layer_score"]     = s["score"]
        w["subject_layer_score"] = sub["score"]
        return w

    @staticmethod
    def _posthoc_attribution(fvec: torch.Tensor) -> Dict[str, float]:
        return {
            f"attribution_{name}": round(float(fvec[i]), 4)
            for i, name in enumerate(FEATURE_NAMES)
        }

    @staticmethod
    def _l1_detail(d, u, s, sub) -> str:
        fired = []
        if d["features"]["domain_mismatch"] > 0:        fired.append("domain mismatch")
        if d["features"]["replyto_differs"] > 0:        fired.append("Reply-To differs")
        if d["features"]["brand_impersonation"] > 0:    fired.append("brand impersonation")
        if s["spf_result"] == "fail":                   fired.append("SPF fail")
        if u["features"]["anchor_mismatch_score"] > 0:  fired.append("anchor mismatch")
        if u["features"]["urgency_score"] > 0.3:        fired.append("body urgency")
        if u["features"]["http_ratio"] > 0.5:           fired.append("high HTTP ratio")
        if sub["features"]["subject_urgency"] > 0.3:    fired.append("subject urgency")
        if sub["features"]["subject_security"] > 0.3:   fired.append("subject security theme")
        if sub["features"]["subject_brand_name"] > 0:   fired.append("brand in subject")
        return "Signals fired: " + (", ".join(fired) if fired else "composite threshold")