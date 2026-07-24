"""
eval.py — v2
Batch evaluate the engine on CEAS or combined corpus.
Works with v7 pipeline (engine handles all extractor calls internally).
"""
import os, sys, argparse, random, time

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--n",         type=int, default=2000)
    parser.add_argument("--force-mlp", action="store_true")
    parser.add_argument("--seed",      type=int, default=42)
    parser.add_argument("--data",      type=str,
                        default=os.path.join(ROOT, "data", "combined",
                                             "phishbyte_v3_corpus.csv"))
    args = parser.parse_args()

    # SPF skip for eval on historical data
    os.environ["PHISHBYTE_SKIP_SPF"] = "1"

    from phishbyte.engine import PhishByteEngine

    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE — BATCH EVALUATION")
    print(f"{'═'*60}")
    print(f"  Samples   : {args.n:,}")
    print(f"  Force MLP : {args.force_mlp}")
    print(f"  Data      : {args.data}")

    engine = PhishByteEngine(force_mlp=args.force_mlp)

    # Load evaluation samples
    if os.path.exists(args.data):
        import pandas as pd
        df      = pd.read_csv(args.data).dropna()
        df      = df.sample(n=min(args.n, len(df)), random_state=args.seed)
        samples = list(zip(df["email_text"].tolist(),
                           df["label"].astype(int).tolist()))
    else:
        print(f"  [WARN] Data not found at {args.data}")
        print(f"  Using CEAS-2008 fallback...")
        ceas = os.path.join(ROOT, "data", "ceas2008_phishbyte.csv")
        if not os.path.exists(ceas):
            print(f"  [ERROR] No evaluation data found."); sys.exit(1)
        import pandas as pd
        df      = pd.read_csv(ceas).dropna()
        df      = df.sample(n=min(args.n, len(df)), random_state=args.seed)
        samples = list(zip(df["email_text"].tolist(),
                           df["label"].astype(int).tolist()))

    tp = fp = tn = fn = 0
    layer_used  = {}
    conf_counts = {"high": 0, "medium": 0, "low": 0}
    t0          = time.time()

    for i, (raw, label) in enumerate(samples):
        verdict   = engine.analyze(raw)
        predicted = 1 if verdict.label == "phishing" else 0
        if predicted == 1 and label == 1: tp += 1
        elif predicted == 1 and label == 0: fp += 1
        elif predicted == 0 and label == 0: tn += 1
        elif predicted == 0 and label == 1: fn += 1
        layer_used[verdict.layer_used]  = layer_used.get(verdict.layer_used, 0) + 1
        conf_counts[verdict.confidence] = conf_counts.get(verdict.confidence, 0) + 1
        if (i+1) % 500 == 0:
            print(f"  Progress: {i+1:,} / {args.n:,}")

    elapsed   = time.time() - t0
    total     = tp + fp + tn + fn
    accuracy  = (tp + tn) / total
    precision = tp / (tp + fp + 1e-8)
    recall    = tp / (tp + fn + 1e-8)
    f1        = 2 * precision * recall / (precision + recall + 1e-8)

    print(f"\n{'═'*60}")
    print(f"  RESULTS  ({total:,} emails, {elapsed:.1f}s, {total/elapsed:.0f} emails/sec)")
    print(f"{'═'*60}")
    print(f"  Accuracy   : {accuracy:.4f}  ({accuracy:.2%})")
    print(f"  Precision  : {precision:.4f}")
    print(f"  Recall     : {recall:.4f}")
    print(f"  F1 Score   : {f1:.4f}")
    print(f"\n  Confusion matrix:")
    print(f"                  predicted")
    print(f"               phish    legit")
    print(f"  actual phish  {tp:>6}   {fn:>6}")
    print(f"  actual legit  {fp:>6}   {tn:>6}")
    print(f"\n  Layer routing:")
    for layer, count in sorted(layer_used.items()):
        print(f"    Layer {layer}: {count:,} ({count/total:.1%})")
    print(f"\n  Confidence:")
    for conf, count in conf_counts.items():
        if count > 0:
            print(f"    {conf:>6}: {count:,} ({count/total:.1%})")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()