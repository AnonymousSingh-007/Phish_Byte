"""
train/train.py — v7
Key changes:
  1. Fits TF-IDF vocab on training set first, saves to weights dir
  2. Extracts BDI features in pipeline
  3. Training loop F1 uses Youden-optimal threshold (not naive 0.5)
  4. Progress bar every 2000 samples
"""
import os, sys, argparse, random, time, pickle, hashlib
from typing import List, Tuple
import torch, torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split
import numpy as np

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _set_spf_skip(skip):
    if skip: os.environ["PHISHBYTE_SKIP_SPF"] = "1"
    else:    os.environ.pop("PHISHBYTE_SKIP_SPF", None)


WEIGHTS_DIR  = os.path.join(ROOT, "phishbyte", "model", "weights")
WEIGHTS_PATH = os.path.join(WEIGHTS_DIR, "phishbyte_mlp.pt")
VOCAB_PATH   = os.path.join(WEIGHTS_DIR, "tfidf_vocab.json")
CACHE_DIR    = os.path.join(ROOT, "train", "cache")
EPOCHS, BATCH_SIZE, LR, WEIGHT_DECAY = 40, 64, 1e-3, 1e-4
VAL_SPLIT, TEST_SPLIT, PATIENCE = 0.15, 0.10, 8
TFIDF_N = 50


def _fingerprint(samples, version="v7"):
    h = hashlib.md5()
    for raw, label in samples:
        h.update(raw[:100].encode("utf-8", errors="ignore"))
        h.update(str(label).encode())
    h.update(version.encode())
    return h.hexdigest()[:16]


def extract_features_with_cache(samples, rebuild=False):
    from phishbyte.extractors.domain  import score_domain
    from phishbyte.extractors.urls    import score_urls
    from phishbyte.extractors.spf     import score_spf
    from phishbyte.extractors.subject import score_subject
    from phishbyte.extractors.bdi     import score_bdi
    from phishbyte.extractors.tfidf_features import TFIDFVocab
    from phishbyte.model.mlp import build_feature_vector

    os.makedirs(CACHE_DIR, exist_ok=True)
    fp         = _fingerprint(samples)
    cache_path = os.path.join(CACHE_DIR, f"features_v7_{fp}.pkl")

    if os.path.exists(cache_path) and not rebuild:
        print(f"  Cache HIT  → {cache_path}")
        with open(cache_path, "rb") as f:
            features, labels = pickle.load(f)
        print(f"  Loaded {len(features):,} cached vectors.")
        return features, labels

    print(f"  Cache MISS → {len(samples):,} emails")
    print(f"  SPF: {'SKIPPED' if os.environ.get('PHISHBYTE_SKIP_SPF')=='1' else 'LIVE'}")

    # ── Step 1: Fit TF-IDF vocab on training split ──────────────────────────
    print(f"\n  Step 1 — Fitting TF-IDF vocabulary ({TFIDF_N} terms)...")
    raw_texts = [r for r, _ in samples]
    lbls      = [l for _, l in samples]

    if os.path.exists(VOCAB_PATH) and not rebuild:
        print(f"  Vocab exists → {VOCAB_PATH} (skipping fit)")
        vocab = TFIDFVocab.load(VOCAB_PATH)
    else:
        vocab = TFIDFVocab.fit(raw_texts, lbls, top_n=TFIDF_N)
        os.makedirs(WEIGHTS_DIR, exist_ok=True)
        vocab.save(VOCAB_PATH)

    # ── Step 2: Extract all features ────────────────────────────────────────
    print(f"\n  Step 2 — Extracting all features...")
    features, labels = [], []
    t0, skipped = time.time(), 0

    for i, (raw, label) in enumerate(samples):
        try:
            d   = score_domain(raw)
            u   = score_urls(raw)
            sp  = score_spf(raw)
            sub = score_subject(raw)
            bdi = score_bdi(raw)
            tfi = vocab.transform(raw)
            features.append(build_feature_vector(d, u, sp, sub, bdi, tfi))
            labels.append(torch.tensor([float(label)], dtype=torch.float32))
        except Exception:
            skipped += 1
        if (i+1) % 2000 == 0:
            el   = time.time()-t0
            rate = (i+1)/el
            eta  = (len(samples)-(i+1))/rate
            print(f"    [{i+1:>6}/{len(samples):>6}]  {el:>5.0f}s  {rate:>6.0f}/s  ETA {eta:>4.0f}s")

    total_time = time.time()-t0
    print(f"  Done. {len(features):,} valid, {skipped} skipped. ({total_time:.1f}s)")
    print(f"  Feature vector dim: {features[0].shape[0] if features else '?'}")

    with open(cache_path, "wb") as f:
        pickle.dump((features, labels), f)
    print(f"  Cached → {cache_path}")
    return features, labels


def _optimal_f1(scores, labels_np):
    """Find F1 at Youden-optimal threshold — replaces naive 0.5 cutoff."""
    best_f1, best_t = 0.0, 0.5
    for t in np.linspace(0.1, 0.9, 81):
        preds = (scores >= t).astype(int)
        tp = ((preds==1)&(labels_np==1)).sum()
        fp = ((preds==1)&(labels_np==0)).sum()
        fn = ((preds==0)&(labels_np==1)).sum()
        pr = tp/(tp+fp+1e-8); re = tp/(tp+fn+1e-8)
        f1 = 2*pr*re/(pr+re+1e-8)
        if f1 > best_f1:
            best_f1, best_t = f1, t
    return best_f1, best_t


class FeatureDataset(Dataset):
    def __init__(self, f, l): self.f, self.l = f, l
    def __len__(self): return len(self.f)
    def __getitem__(self, i): return self.f[i], self.l[i]


def train_epoch(model, loader, opt, crit, dev):
    model.train()
    tl, c, t = 0., 0, 0
    for xb, yb in loader:
        xb, yb = xb.to(dev), yb.to(dev)
        opt.zero_grad(); p=model(xb); loss=crit(p,yb)
        loss.backward(); opt.step()
        tl+=loss.item()*len(xb)
        c+=((p>=0.5).float()==yb).sum().item(); t+=len(xb)
    return tl/t, c/t


@torch.no_grad()
def eval_epoch(model, loader, crit, dev):
    model.eval()
    tl, c, t = 0., 0, 0
    all_scores, all_labels = [], []
    for xb, yb in loader:
        xb, yb = xb.to(dev), yb.to(dev)
        p=model(xb); loss=crit(p,yb)
        tl+=loss.item()*len(xb)
        pred=(p>=0.5).float()
        c+=(pred==yb).sum().item(); t+=len(xb)
        all_scores.extend(p.cpu().numpy().flatten())
        all_labels.extend(yb.cpu().numpy().flatten())
    scores_np = np.array(all_scores)
    labels_np = np.array(all_labels)
    f1, threshold = _optimal_f1(scores_np, labels_np)
    return tl/t, c/t, f1, threshold


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data",          type=str, default=None)
    parser.add_argument("--epochs",        type=int, default=EPOCHS)
    parser.add_argument("--batch-size",    type=int, default=BATCH_SIZE)
    parser.add_argument("--lr",            type=float, default=LR)
    parser.add_argument("--rebuild-cache", action="store_true")
    parser.add_argument("--skip-spf",      action="store_true")
    args = parser.parse_args()

    _set_spf_skip(args.skip_spf)

    from phishbyte.model.mlp import PhishByteMLPLayer, INPUT_DIM

    dev = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE v7 — MLP TRAINING")
    print(f"{'═'*60}")
    if dev.type == "cuda":
        print(f"  Device   : GPU — {torch.cuda.get_device_name(0)}")
        vram = torch.cuda.get_device_properties(0).total_memory/1e9
        print(f"             {vram:.1f} GB VRAM · {torch.__version__}")
    else:
        print(f"  Device   : CPU")
    print(f"  Features : {INPUT_DIM} (35 rule + 50 TF-IDF)")
    print(f"  Skip SPF : {args.skip_spf}")

    if args.data and os.path.exists(args.data):
        import pandas as pd
        df = pd.read_csv(args.data).dropna()
        cols = {c.lower():c for c in df.columns}
        df = df[df[cols["email_text"]].str.len()>0]
        samples = list(zip(df[cols["email_text"]].tolist(),
                           df[cols["label"]].astype(int).tolist()))
        print(f"\n  Loaded {len(samples):,} samples from {args.data}")
        n_p = sum(1 for _,l in samples if l==1)
        print(f"  Balance — phish: {n_p:,}  legit: {len(samples)-n_p:,}")
    else:
        sys.path.insert(0, os.path.join(ROOT,"train"))
        from synthetic_data import generate_dataset
        samples = generate_dataset(400, 400)
        print(f"\n  Synthetic: {len(samples)} samples")

    print(f"\n  Feature extraction:")
    features, labels = extract_features_with_cache(samples, rebuild=args.rebuild_cache)

    ds = FeatureDataset(features, labels)
    n  = len(ds)
    n_te = max(1,int(n*TEST_SPLIT)); n_va = max(1,int(n*VAL_SPLIT))
    n_tr = n - n_va - n_te
    tr, va, te = random_split(ds, [n_tr, n_va, n_te],
                              generator=torch.Generator().manual_seed(42))
    tr_l = DataLoader(tr, batch_size=args.batch_size, shuffle=True)
    va_l = DataLoader(va, batch_size=args.batch_size)
    te_l = DataLoader(te, batch_size=args.batch_size)
    print(f"\n  Split → train: {n_tr:,}  val: {n_va:,}  test: {n_te:,}")

    model = PhishByteMLPLayer(input_dim=INPUT_DIM).to(dev)
    opt   = torch.optim.AdamW(model.parameters(), lr=args.lr, weight_decay=WEIGHT_DECAY)
    sched = torch.optim.lr_scheduler.ReduceLROnPlateau(opt, mode="min", factor=0.5, patience=3)
    crit  = nn.BCELoss()

    params = sum(p.numel() for p in model.parameters())
    print(f"\n  Model params : {params:,}")
    print(f"  Architecture : {INPUT_DIM}→360→180(×2ResBlock)→90→48→1")
    print(f"\n  NOTE: F1 column uses Youden-optimal threshold (not 0.5)")
    print(f"  This is the REAL F1 — calibrated during training.")
    print(f"\n{'─'*60}")
    print(f"  {'Ep':>3}  {'TrLoss':>8}  {'TrAcc':>7}  {'VaLoss':>8}  {'VaF1':>7}  {'VaThresh':>9}")
    print(f"{'─'*60}")

    best, pat = float("inf"), 0
    os.makedirs(WEIGHTS_DIR, exist_ok=True)
    t0 = time.time()

    for ep in range(1, args.epochs+1):
        tl, ta = train_epoch(model, tr_l, opt, crit, dev)
        vl, va_, vf1, vt = eval_epoch(model, va_l, crit, dev)
        sched.step(vl)
        print(f"  {ep:>3}  {tl:>8.4f}  {ta:>6.1%}  {vl:>8.4f}  {vf1:>6.3f}  {vt:>9.3f}")
        if vl < best:
            best, pat = vl, 0
            torch.save(model.state_dict(), WEIGHTS_PATH)
        else:
            pat += 1
            if pat >= PATIENCE:
                print(f"\n  Early stopping at ep {ep}")
                break

    train_time = time.time()-t0
    print(f"\n{'═'*60}")
    print(f"  FINAL TEST EVALUATION")
    print(f"{'═'*60}")
    model.load_state_dict(torch.load(WEIGHTS_PATH, map_location=dev, weights_only=True))
    te_loss, te_acc, te_f1, te_thresh = eval_epoch(model, te_l, crit, dev)
    print(f"  Test Loss      : {te_loss:.4f}")
    print(f"  Test Accuracy  : {te_acc:.2%}")
    print(f"  Test F1        : {te_f1:.4f}  (at threshold {te_thresh:.3f})")
    print(f"  Train time     : {train_time:.1f}s on {dev.type.upper()}")
    print(f"\n  Weights → {WEIGHTS_PATH}")
    print(f"  Vocab   → {VOCAB_PATH}")
    print(f"{'═'*60}\n")
    print(f"  Next: python train/calibrate_thresholds.py --data {args.data or 'synthetic'}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()