"""
train/calibrate_thresholds.py
Run AFTER train.py finishes. Computes Layer 1 and Layer 2 thresholds
from the validation set using ROC analysis, saves to thresholds.json
next to the model weights.

Usage
─────
    python train/calibrate_thresholds.py
"""

import os, sys, random
import numpy as np
import torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phishbyte.extractors.domain import score_domain
from phishbyte.extractors.urls   import score_urls
from phishbyte.extractors.spf    import score_spf
from phishbyte.model.mlp         import PhishByteMLPLayer, build_feature_vector
from phishbyte.calibration       import calibrate_layer, save_thresholds

WEIGHTS_DIR     = os.path.join(ROOT, "phishbyte", "model", "weights")
WEIGHTS_PATH    = os.path.join(WEIGHTS_DIR, "phishbyte_mlp.pt")
THRESHOLDS_PATH = os.path.join(WEIGHTS_DIR, "thresholds.json")


def main():
    print(f"\n{'═'*52}")
    print(f"  PHISH_BYTE — THRESHOLD CALIBRATION")
    print(f"{'═'*52}\n")

    # ── Generate val data (use real CEAS-2008 once available) ─────────────────
    sys.path.insert(0, os.path.join(ROOT, "train"))
    from synthetic_data import generate_dataset

    random.seed(123)              # different seed than training
    samples = generate_dataset(n_phish=200, n_legit=200)
    print(f"  Validation samples: {len(samples)}")

    # ── Layer 1 score collection ──────────────────────────────────────────────
    print(f"  Computing Layer 1 scores...")
    l1_scores, l2_scores, labels = [], [], []

    # Load trained model for L2 scoring
    if os.path.exists(WEIGHTS_PATH):
        model = PhishByteMLPLayer()
        model.load_state_dict(torch.load(WEIGHTS_PATH, map_location="cpu", weights_only=True))
        model.eval()
        has_model = True
        print(f"  MLP loaded — calibrating both layers")
    else:
        has_model = False
        print(f"  No MLP weights — calibrating Layer 1 only")

    for raw, label in samples:
        try:
            d = score_domain(raw)
            u = score_urls(raw)
            s = score_spf(raw)
            l1 = min(1.0, d["score"]*0.40 + u["score"]*0.40 + s["score"]*0.20)
            l1_scores.append(l1)
            labels.append(label)

            if has_model:
                fvec = build_feature_vector(d, u, s)
                l2_scores.append(model.predict_proba(fvec))
        except Exception:
            continue

    l1_scores = np.array(l1_scores)
    labels    = np.array(labels)
    if has_model:
        l2_scores = np.array(l2_scores)

    # ── Calibrate Layer 1 ─────────────────────────────────────────────────────
    print(f"\n  Calibrating Layer 1 gate...")
    cfg1 = calibrate_layer(
        l1_scores, labels,
        layer_name           = "layer1",
        target_precision     = 0.95,
        target_clean_recall  = 0.95,
    )
    print(f"    phish≥{cfg1.phish_threshold:.4f} (precision={cfg1.phish_precision:.3f})")
    print(f"    clean≤{cfg1.clean_threshold:.4f} (recall  ={cfg1.clean_recall:.3f})")
    print(f"    Youden J={cfg1.youden_j:.3f}  Coverage={cfg1.coverage:.1%}")
    print(f"    {cfg1.notes}")

    configs = {"layer1": cfg1}

    # ── Calibrate Layer 2 ─────────────────────────────────────────────────────
    if has_model:
        print(f"\n  Calibrating Layer 2 gate...")
        cfg2 = calibrate_layer(
            l2_scores, labels,
            layer_name           = "layer2",
            target_precision     = 0.97,
            target_clean_recall  = 0.97,
        )
        print(f"    phish≥{cfg2.phish_threshold:.4f} (precision={cfg2.phish_precision:.3f})")
        print(f"    clean≤{cfg2.clean_threshold:.4f} (recall  ={cfg2.clean_recall:.3f})")
        print(f"    Youden J={cfg2.youden_j:.3f}  Coverage={cfg2.coverage:.1%}")
        print(f"    {cfg2.notes}")
        configs["layer2"] = cfg2

    # ── Save ──────────────────────────────────────────────────────────────────
    save_thresholds(configs, THRESHOLDS_PATH)
    print(f"\n  Thresholds saved → {THRESHOLDS_PATH}")
    print(f"{'═'*52}\n")


if __name__ == "__main__":
    main()