"""
train/calibrate_thresholds.py — v2
Loads validation samples from --data CSV if available, else synthetic.
Now uses 4-extractor pipeline.
"""
import os, sys, argparse, random
import numpy as np, torch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, default=None)
    parser.add_argument("--skip-spf", action="store_true", default=True)
    parser.add_argument("--n-val", type=int, default=2000)
    args = parser.parse_args()

    if args.skip_spf:
        os.environ["PHISHBYTE_SKIP_SPF"] = "1"

    from phishbyte.extractors.domain  import score_domain
    from phishbyte.extractors.urls    import score_urls
    from phishbyte.extractors.spf     import score_spf
    from phishbyte.extractors.subject import score_subject
    from phishbyte.model.mlp          import PhishByteMLPLayer, build_feature_vector
    from phishbyte.calibration        import calibrate_layer, save_thresholds

    WEIGHTS = os.path.join(ROOT, "phishbyte", "model", "weights", "phishbyte_mlp.pt")
    OUTPATH = os.path.join(ROOT, "phishbyte", "model", "weights", "thresholds.json")

    print(f"\n{'═'*52}")
    print(f"  PHISH_BYTE — THRESHOLD CALIBRATION (v2)")
    print(f"{'═'*52}")

    if args.data and os.path.exists(args.data):
        import pandas as pd
        df = pd.read_csv(args.data).dropna()
        cols = {c.lower(): c for c in df.columns}
        df = df.sample(n=min(args.n_val, len(df)), random_state=123)
        samples = list(zip(df[cols["email_text"]].tolist(),
                           df[cols["label"]].astype(int).tolist()))
        print(f"  Source: {args.data}")
        print(f"  Validation samples: {len(samples):,}")
    else:
        sys.path.insert(0, os.path.join(ROOT, "train"))
        from synthetic_data import generate_dataset
        random.seed(123)
        samples = generate_dataset(n_phish=200, n_legit=200)
        print(f"  Source: synthetic")
        print(f"  Validation samples: {len(samples)}")

    if os.path.exists(WEIGHTS):
        model = PhishByteMLPLayer()
        model.load_state_dict(torch.load(WEIGHTS, map_location="cpu", weights_only=True))
        model.eval()
        has_model = True
        print(f"  MLP loaded — calibrating both layers")
    else:
        has_model = False
        print(f"  No MLP weights — Layer 1 only")

    l1_scores, l2_scores, labels = [], [], []
    for raw, label in samples:
        try:
            d = score_domain(raw); u = score_urls(raw)
            s = score_spf(raw);    sub = score_subject(raw)
            l1 = min(1.0, d["score"]*0.30 + u["score"]*0.30 + sub["score"]*0.25 + s["score"]*0.15)
            l1_scores.append(l1); labels.append(label)
            if has_model:
                fvec = build_feature_vector(d, u, s, sub)
                l2_scores.append(model.predict_proba(fvec))
        except Exception:
            continue

    l1 = np.array(l1_scores); labels = np.array(labels)

    print(f"\n  L1 score distribution:")
    print(f"    phish samples : mean {l1[labels==1].mean():.3f}  std {l1[labels==1].std():.3f}")
    print(f"    legit samples : mean {l1[labels==0].mean():.3f}  std {l1[labels==0].std():.3f}")

    print(f"\n  Calibrating Layer 1...")
    cfg1 = calibrate_layer(l1, labels, "layer1", 0.95, 0.95)
    print(f"    phish≥{cfg1.phish_threshold:.4f}  precision={cfg1.phish_precision:.3f}")
    print(f"    clean≤{cfg1.clean_threshold:.4f}  recall  ={cfg1.clean_recall:.3f}")
    print(f"    Youden J={cfg1.youden_j:.3f}  Coverage={cfg1.coverage:.1%}")
    print(f"    {cfg1.notes}")

    configs = {"layer1": cfg1}

    if has_model:
        l2 = np.array(l2_scores)
        print(f"\n  L2 score distribution:")
        print(f"    phish samples : mean {l2[labels==1].mean():.3f}  std {l2[labels==1].std():.3f}")
        print(f"    legit samples : mean {l2[labels==0].mean():.3f}  std {l2[labels==0].std():.3f}")

        print(f"\n  Calibrating Layer 2...")
        cfg2 = calibrate_layer(l2, labels, "layer2", 0.95, 0.95)
        print(f"    phish≥{cfg2.phish_threshold:.4f}  precision={cfg2.phish_precision:.3f}")
        print(f"    clean≤{cfg2.clean_threshold:.4f}  recall  ={cfg2.clean_recall:.3f}")
        print(f"    Youden J={cfg2.youden_j:.3f}  Coverage={cfg2.coverage:.1%}")
        print(f"    {cfg2.notes}")
        configs["layer2"] = cfg2

    save_thresholds(configs, OUTPATH)
    print(f"\n  Thresholds saved → {OUTPATH}")
    print(f"{'═'*52}\n")


if __name__ == "__main__":
    main()