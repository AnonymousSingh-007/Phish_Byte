"""
phishbyte/engine.py — v6 (Hub-aware)

Adds from_pretrained() classmethod that pulls weights + thresholds.json
from HuggingFace Hub or a local directory.
"""

import os, json, torch
from typing import Dict, Optional, Union
from pathlib import Path

from huggingface_hub import hf_hub_download

from phishbyte.extractors.domain  import score_domain
from phishbyte.extractors.urls    import score_urls
from phishbyte.extractors.spf     import score_spf
from phishbyte.extractors.subject import score_subject
from phishbyte.model.mlp          import PhishByteMLPLayer, build_feature_vector, FEATURE_NAMES
from phishbyte.verdict            import PhishVerdict
from phishbyte.calibration        import load_thresholds


FALLBACK_L1_PHISH = 0.85
FALLBACK_L1_CLEAN = 0.05
FALLBACK_L2_PHISH = 0.70
FALLBACK_L2_CLEAN = 0.30

_HERE              = os.path.dirname(__file__)
DEFAULT_WEIGHTS    = os.path.join(_HERE, "model", "weights", "phishbyte_mlp.pt")
DEFAULT_THRESHOLDS = os.path.join(_HERE, "model", "weights", "thresholds.json")


class PhishByteEngine:
    """
    Phish_Byte cascading inference engine.

    Load methods
    ────────────
        engine = PhishByteEngine()                                    # use local weights
        engine = PhishByteEngine.from_pretrained("user/phishbyte")    # pull from HF Hub
        engine = PhishByteEngine.from_pretrained("/path/to/model_dir") # local dir
    """

    def __init__(
        self,
        model: Optional[PhishByteMLPLayer] = None,
        thresholds: Optional[Dict] = None,
        force_mlp: bool = False,
        weights_path: Optional[str] = None,
        thresholds_path: Optional[str] = None,
    ):
        self.model = model
        self._model_loaded = model is not None
        self.force_mlp = force_mlp

        if not self._model_loaded:
            wpath = weights_path or DEFAULT_WEIGHTS
            if os.path.exists(wpath):
                self._load_local_model(wpath)
            else:
                print(f"[PhishByte] No weights at {wpath}. Layer 1 only.")

        if thresholds is not None:
            self._apply_thresholds(thresholds)
        else:
            tpath = thresholds_path or DEFAULT_THRESHOLDS
            if os.path.exists(tpath):
                try:
                    cfg = load_thresholds(tpath)
                    self._apply_thresholds_cfg(cfg)
                except Exception as e:
                    print(f"[PhishByte] Threshold load failed: {e}. Fallback values.")
                    self._use_fallback_thresholds()
            else:
                self._use_fallback_thresholds()

        if self.force_mlp:
            print(f"[PhishByte] FORCE-MLP mode: bypassing Layer 1 entirely.")

    @classmethod
    def from_pretrained(
        cls,
        pretrained_model_name_or_path: Union[str, Path],
        force_mlp: bool = False,
        **kwargs,
    ) -> "PhishByteEngine":
        """
        Load weights + thresholds.json from HuggingFace Hub or a local dir.
        """
        path_str = str(pretrained_model_name_or_path)

        try:
            model = PhishByteMLPLayer.from_pretrained(path_str, **kwargs)
            model.eval()
            print(f"[PhishByte] MLP loaded from {path_str}")
        except Exception as e:
            print(f"[PhishByte] MLP load failed: {e}")
            model = None

        thresholds = None
        if os.path.isdir(path_str):
            tpath = os.path.join(path_str, "thresholds.json")
            if os.path.exists(tpath):
                with open(tpath) as f:
                    thresholds = json.load(f)
                print(f"[PhishByte] Thresholds loaded from {tpath}")
        else:
            try:
                tpath = hf_hub_download(
                    repo_id=path_str,
                    filename="thresholds.json",
                    **kwargs,
                )
                with open(tpath) as f:
                    thresholds = json.load(f)
                print(f"[PhishByte] Thresholds loaded from Hub: {tpath}")
            except Exception as e:
                print(f"[PhishByte] No thresholds.json on Hub ({e}). Using fallback.")

        return cls(model=model, thresholds=thresholds, force_mlp=force_mlp)

    def save_pretrained(self, save_directory: Union[str, Path]):
        """Save weights + thresholds.json to a local directory."""
        save_dir = Path(save_directory)
        save_dir.mkdir(parents=True, exist_ok=True)

        if self.model is not None:
            self.model.save_pretrained(str(save_dir))
            print(f"[PhishByte] MLP saved → {save_dir}")

        thresholds_data = {
            "layer1": {
                "phish_threshold": self.l1_phish,
                "clean_threshold": self.l1_clean,
            },
            "layer2": {
                "phish_threshold": self.l2_phish,
                "clean_threshold": self.l2_clean,
            },
        }
        with open(save_dir / "thresholds.json", "w") as f:
            json.dump(thresholds_data, f, indent=2)
        print(f"[PhishByte] Thresholds saved → {save_dir / 'thresholds.json'}")

    def push_to_hub(self, repo_id: str, **kwargs):
        """Push weights + thresholds.json to HuggingFace Hub."""
        if self.model is None:
            raise RuntimeError("No MLP loaded — cannot push to Hub.")

        self.model.push_to_hub(repo_id, **kwargs)

        from huggingface_hub import upload_file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "layer1": {
                    "phish_threshold": self.l1_phish,
                    "clean_threshold": self.l1_clean,
                },
                "layer2": {
                    "phish_threshold": self.l2_phish,
                    "clean_threshold": self.l2_clean,
                },
            }, f, indent=2)
            tmppath = f.name
        upload_file(
            path_or_fileobj=tmppath,
            path_in_repo="thresholds.json",
            repo_id=repo_id,
            commit_message="Upload calibrated thresholds",
            **kwargs,
        )
        os.unlink(tmppath)
        print(f"[PhishByte] Pushed weights + thresholds → {repo_id}")

    def _apply_thresholds_cfg(self, cfg):
        self.l1_phish = cfg["layer1"].phish_threshold
        self.l1_clean = cfg["layer1"].clean_threshold
        self.l2_phish = cfg.get("layer2", cfg["layer1"]).phish_threshold
        self.l2_clean = cfg.get("layer2", cfg["layer1"]).clean_threshold
        print(
            f"[PhishByte] Thresholds — "
            f"L1: ≥{self.l1_phish:.3f}/≤{self.l1_clean:.3f}  "
            f"L2: ≥{self.l2_phish:.3f}/≤{self.l2_clean:.3f}"
        )

    def _apply_thresholds(self, thresholds: Dict):
        l1 = thresholds.get("layer1", {})
        l2 = thresholds.get("layer2", l1)
        self.l1_phish = l1.get("phish_threshold", FALLBACK_L1_PHISH)
        self.l1_clean = l1.get("clean_threshold", FALLBACK_L1_CLEAN)
        self.l2_phish = l2.get("phish_threshold", FALLBACK_L2_PHISH)
        self.l2_clean = l2.get("clean_threshold", FALLBACK_L2_CLEAN)
        print(
            f"[PhishByte] Thresholds — "
            f"L1: ≥{self.l1_phish:.3f}/≤{self.l1_clean:.3f}  "
            f"L2: ≥{self.l2_phish:.3f}/≤{self.l2_clean:.3f}"
        )

    def _use_fallback_thresholds(self):
        self.l1_phish, self.l1_clean = FALLBACK_L1_PHISH, FALLBACK_L1_CLEAN
        self.l2_phish, self.l2_clean = FALLBACK_L2_PHISH, FALLBACK_L2_CLEAN
        print(f"[PhishByte] Using fallback thresholds.")

    def _load_local_model(self, path: str):
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

        if not self.force_mlp:
            if l1_score >= self.l1_phish:
                return PhishVerdict(
                    label="phishing", probability=round(l1_score, 4),
                    confidence="high", layer_used=1,
                    feature_weights=feature_weights,
                    detail=self._l1_detail(d, u, s, sub),
                )
            if not self._model_loaded and l1_score <= self.l1_clean:
                return PhishVerdict(
                    label="legitimate", probability=round(l1_score, 4),
                    confidence="medium", layer_used=1,
                    feature_weights=feature_weights,
                    detail="No suspicious signals at Layer 1. (MLP unavailable.)",
                )

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