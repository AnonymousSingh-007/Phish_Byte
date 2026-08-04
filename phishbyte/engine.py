"""
phishbyte/engine.py — v8

Full pipeline: domain, urls, spf, subject, bdi extractors run first.
Then lexical scoring runs on sender domain AND most-common-link domain.
Then cross_signal computes interaction features from all prior outputs.
Then TF-IDF transform. Then all six groups concatenate into 104-dim vector.
"""
import os, json, torch
from typing import Dict, Optional, Union
from pathlib import Path

from phishbyte.extractors.domain         import score_domain
from phishbyte.extractors.urls           import score_urls
from phishbyte.extractors.spf            import score_spf
from phishbyte.extractors.subject        import score_subject
from phishbyte.extractors.bdi            import score_bdi
from phishbyte.extractors.lexical        import score_lexical
from phishbyte.extractors.cross_signal   import score_cross_signal
from phishbyte.extractors.tfidf_features import TFIDFVocab
from phishbyte.model.mlp                 import PhishByteMLPLayer, build_feature_vector, INPUT_DIM
from phishbyte.verdict                   import PhishVerdict
from phishbyte.calibration               import load_thresholds

FALLBACK_L1_PHISH = 0.85
FALLBACK_L1_CLEAN = 0.05
FALLBACK_L2_PHISH = 0.70
FALLBACK_L2_CLEAN = 0.30

_HERE              = os.path.dirname(__file__)
DEFAULT_WEIGHTS    = os.path.join(_HERE, "model", "weights", "phishbyte_mlp.pt")
DEFAULT_THRESHOLDS = os.path.join(_HERE, "model", "weights", "thresholds.json")
DEFAULT_VOCAB      = os.path.join(_HERE, "model", "weights", "tfidf_vocab.json")


class PhishByteEngine:
    """
    Phish_Byte cascading inference engine — v8.

    Extractors: domain, url, spf, subject, bdi (6 base) + lexical (2 calls,
    sender + mcld domain) + cross_signal (interaction features) + tfidf.
    MLP: 104 features, ~716K parameters, temperature-scaled sigmoid.
    """

    def __init__(self, weights_path=None, thresholds_path=None,
                 vocab_path=None, force_mlp=False):
        self.model: Optional[PhishByteMLPLayer] = None
        self._model_loaded = False
        self.vocab: Optional[TFIDFVocab] = None
        self.force_mlp = force_mlp

        wpath = weights_path or DEFAULT_WEIGHTS
        if os.path.exists(wpath):
            self._load_model(wpath)
        else:
            print(f"[PhishByte] No weights at {wpath}. Layer 1 only.")

        vpath = vocab_path or DEFAULT_VOCAB
        if os.path.exists(vpath):
            self.vocab = TFIDFVocab.load(vpath)
            print(f"[PhishByte] TF-IDF vocab loaded ({len(self.vocab.vocab)} terms)")
        else:
            print(f"[PhishByte] No TF-IDF vocab at {vpath}. Train first.")

        tpath = thresholds_path or DEFAULT_THRESHOLDS
        if os.path.exists(tpath):
            try:
                cfg = load_thresholds(tpath)
                self.l1_phish = cfg["layer1"].phish_threshold
                self.l1_clean = cfg["layer1"].clean_threshold
                self.l2_phish = cfg.get("layer2", cfg["layer1"]).phish_threshold
                self.l2_clean = cfg.get("layer2", cfg["layer1"]).clean_threshold
                print(f"[PhishByte] Thresholds — "
                      f"L1:≥{self.l1_phish:.3f}/≤{self.l1_clean:.3f}  "
                      f"L2:≥{self.l2_phish:.3f}/≤{self.l2_clean:.3f}")
            except Exception as e:
                print(f"[PhishByte] Threshold load failed: {e}. Fallback.")
                self._use_fallback_thresholds()
        else:
            self._use_fallback_thresholds()

        if self.force_mlp:
            print(f"[PhishByte] FORCE-MLP mode.")

    def _use_fallback_thresholds(self):
        self.l1_phish, self.l1_clean = FALLBACK_L1_PHISH, FALLBACK_L1_CLEAN
        self.l2_phish, self.l2_clean = FALLBACK_L2_PHISH, FALLBACK_L2_CLEAN
        print(f"[PhishByte] Using fallback thresholds.")

    def _load_model(self, path):
        try:
            self.model = PhishByteMLPLayer()
            state = torch.load(path, map_location="cpu", weights_only=True)
            self.model.load_state_dict(state)
            self.model.eval()
            self._model_loaded = True
            params = sum(p.numel() for p in self.model.parameters())
            print(f"[PhishByte] MLP loaded ({params:,} params) from {path}")
        except Exception as e:
            print(f"[PhishByte] Failed to load weights: {e}.")
            self.model = None; self._model_loaded = False

    @classmethod
    def from_pretrained(cls, pretrained_model_name_or_path, force_mlp=False, **kwargs):
        path = str(pretrained_model_name_or_path)
        try:
            model = PhishByteMLPLayer.from_pretrained(path, **kwargs)
            model.eval()
            print(f"[PhishByte] MLP loaded from {path}")
        except Exception as e:
            print(f"[PhishByte] MLP load failed: {e}")
            model = None

        thresholds, vocab = None, None
        if os.path.isdir(path):
            tpath = os.path.join(path, "thresholds.json")
            vpath = os.path.join(path, "tfidf_vocab.json")
            if os.path.exists(tpath):
                with open(tpath) as f: thresholds = json.load(f)
            if os.path.exists(vpath):
                vocab = TFIDFVocab.load(vpath)
        else:
            from huggingface_hub import hf_hub_download
            for fname, kind in [("thresholds.json","t"), ("tfidf_vocab.json","v")]:
                try:
                    p = hf_hub_download(repo_id=path, filename=fname, **kwargs)
                    if kind == "t":
                        with open(p) as f: thresholds = json.load(f)
                    else:
                        vocab = TFIDFVocab.load(p)
                    print(f"[PhishByte] {fname} loaded from Hub")
                except Exception:
                    pass

        engine = cls.__new__(cls)
        engine.model         = model
        engine._model_loaded = model is not None
        engine.vocab         = vocab
        engine.force_mlp     = force_mlp
        engine.l1_phish      = FALLBACK_L1_PHISH
        engine.l1_clean      = FALLBACK_L1_CLEAN
        engine.l2_phish      = FALLBACK_L2_PHISH
        engine.l2_clean      = FALLBACK_L2_CLEAN

        if thresholds:
            l1 = thresholds.get("layer1", {})
            l2 = thresholds.get("layer2", l1)
            engine.l1_phish = l1.get("phish_threshold", FALLBACK_L1_PHISH)
            engine.l1_clean = l1.get("clean_threshold", FALLBACK_L1_CLEAN)
            engine.l2_phish = l2.get("phish_threshold", FALLBACK_L2_PHISH)
            engine.l2_clean = l2.get("clean_threshold", FALLBACK_L2_CLEAN)
        return engine

    def save_pretrained(self, save_directory: Union[str, Path]):
        save_dir = Path(save_directory)
        save_dir.mkdir(parents=True, exist_ok=True)
        if self.model is not None:
            self.model.save_pretrained(str(save_dir))
        if self.vocab is not None:
            self.vocab.save(str(save_dir / "tfidf_vocab.json"))
        with open(save_dir / "thresholds.json", "w") as f:
            json.dump({
                "layer1": {"phish_threshold": self.l1_phish, "clean_threshold": self.l1_clean},
                "layer2": {"phish_threshold": self.l2_phish, "clean_threshold": self.l2_clean},
            }, f, indent=2)
        print(f"[PhishByte] Saved to {save_dir}")

    def push_to_hub(self, repo_id: str, **kwargs):
        if self.model is None:
            raise RuntimeError("No MLP loaded.")
        self.model.push_to_hub(repo_id, **kwargs)
        from huggingface_hub import upload_file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump({
                "layer1": {"phish_threshold": self.l1_phish, "clean_threshold": self.l1_clean},
                "layer2": {"phish_threshold": self.l2_phish, "clean_threshold": self.l2_clean},
            }, f, indent=2)
            tmppath = f.name
        upload_file(path_or_fileobj=tmppath, path_in_repo="thresholds.json",
                    repo_id=repo_id, commit_message="Upload thresholds", **kwargs)
        os.unlink(tmppath)
        if self.vocab is not None:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
                json.dump({"vocab": self.vocab.vocab, "idf": self.vocab.idf}, f, indent=2)
                tmppath = f.name
            upload_file(path_or_fileobj=tmppath, path_in_repo="tfidf_vocab.json",
                        repo_id=repo_id, commit_message="Upload TF-IDF vocab", **kwargs)
            os.unlink(tmppath)
        print(f"[PhishByte] Pushed weights + thresholds + vocab → {repo_id}")

    def analyze(self, raw_email: str) -> PhishVerdict:
        d   = score_domain(raw_email)
        u   = score_urls(raw_email)
        s   = score_spf(raw_email)
        sub = score_subject(raw_email)
        bdi = score_bdi(raw_email)

        # Lexical scoring — sender domain and most-common-link domain
        sender_lexical = score_lexical(d.get("from_domain") or "")
        mcld_lexical   = bdi.get("mcld_lexical") or {
            k: 0.0 for k in ["digit_run_score","hyphen_run_score","entropy_score",
                             "vowel_ratio_anomaly","brand_typosquat_score","domain_length_score"]
        }

        # Cross-extractor interaction features
        cross = score_cross_signal(d, u, s, bdi)

        l1_score = self._layer1_composite(d, u, s, sub, bdi, cross)
        feature_weights = self._build_feature_weights(d, u, s, sub, bdi, cross, sender_lexical, mcld_lexical)

        if not self.force_mlp and l1_score >= self.l1_phish:
            return PhishVerdict(
                label="phishing", probability=round(l1_score, 4),
                confidence="high", layer_used=1,
                feature_weights=feature_weights,
                detail=self._l1_detail(d, u, s, sub, bdi, cross),
            )

        if self._model_loaded and self.model is not None:
            tfidf = (self.vocab.transform(raw_email) if self.vocab
                     else {f"tfidf_pad_{i}": 0.0 for i in range(50)})
            fvec = build_feature_vector(d, u, s, sub, bdi, cross, sender_lexical, mcld_lexical, tfidf)
            l2_prob = self.model.predict_proba(fvec)
            feature_weights.update({k: round(v, 4) for k, v in tfidf.items()})

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
                detail=f"MLP probability (calibrated): {l2_prob:.2%}. L1 score: {l1_score:.2%}. "
                       f"Trust consistency: {cross['features']['trust_consistency_score']:.2f}.",
            )

        return PhishVerdict(
            label="phishing" if l1_score > 0.5 else "legitimate",
            probability=round(l1_score, 4), confidence="medium", layer_used=1,
            feature_weights=feature_weights,
            detail=f"No MLP available. Layer 1 only ({l1_score:.2%}).",
        )

    @staticmethod
    def _layer1_composite(d, u, s, sub, bdi, cross):
        return min(1.0,
            d["score"]     * 0.20 +
            u["score"]     * 0.20 +
            sub["score"]   * 0.15 +
            bdi["score"]   * 0.20 +
            s["score"]     * 0.10 +
            cross["score"] * 0.15
        )

    @staticmethod
    def _build_feature_weights(d, u, s, sub, bdi, cross, sender_lex, mcld_lex):
        w = {}
        w.update(d["features"]); w.update(u["features"])
        w.update(s["features"]); w.update(sub["features"])
        w.update(bdi["features"]); w.update(cross["features"])
        w.update({f"sender_{k}": v for k, v in sender_lex.items()})
        w.update({f"mcld_{k}": v for k, v in mcld_lex.items()})
        w["domain_layer_score"]  = d["score"]
        w["url_layer_score"]     = u["score"]
        w["spf_layer_score"]     = s["score"]
        w["subject_layer_score"] = sub["score"]
        w["bdi_layer_score"]     = bdi["score"]
        w["cross_signal_score"]  = cross["score"]
        return w

    @staticmethod
    def _l1_detail(d, u, s, sub, bdi, cross):
        fired = []
        if d["features"]["domain_mismatch"] > 0:          fired.append("domain mismatch")
        if d["features"]["brand_impersonation"] > 0:      fired.append("brand impersonation")
        if d["features"]["display_name_mismatch"] > 0:    fired.append("display name spoof")
        if s["spf_result"] == "fail":                      fired.append("SPF fail")
        if bdi["features"]["mcld_mismatch"] > 0:           fired.append("link domain mismatch")
        if bdi["features"]["form_action_is_ip"] > 0:       fired.append("form posts to raw IP")
        if bdi["features"]["redirect_param_present"] > 0:  fired.append("open redirect pattern")
        if cross["features"]["multi_signal_phish_score"] >= 0.66: fired.append("multi-module agreement")
        if u["features"]["urgency_score"] > 0.3:           fired.append("body urgency")
        if sub["features"]["subject_urgency"] > 0.3:       fired.append("subject urgency")
        return "Signals: " + (", ".join(fired) if fired else "composite threshold")