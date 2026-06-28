"""
train/train.py
PhishByte MLP — end-to-end training pipeline (v3)

Changes from v2
───────────────
  • Adds --skip-spf flag for historical datasets (sets PHISHBYTE_SKIP_SPF=1)
  • Better CSV loading: handles 'email_text' column case-insensitively
  • Reports label balance and split balance before training
  • CEAS-2008 ready

Usage
─────
    python train/train.py                                        # synthetic
    python train/train.py --data data/ceas2008_phishbyte.csv     # real
    python train/train.py --data data/ceas2008_phishbyte.csv --skip-spf
"""

import os
import sys
import argparse
import random
import time
import pickle
import hashlib
from typing import List, Tuple

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _set_spf_skip(skip: bool):
    """Must run BEFORE importing extractors — they check env at import."""
    if skip:
        os.environ["PHISHBYTE_SKIP_SPF"] = "1"
    else:
        os.environ.pop("PHISHBYTE_SKIP_SPF", None)


WEIGHTS_DIR  = os.path.join(ROOT, "phishbyte", "model", "weights")
WEIGHTS_PATH = os.path.join(WEIGHTS_DIR, "phishbyte_mlp.pt")
CACHE_DIR    = os.path.join(ROOT, "train", "cache")

EPOCHS       = 40
BATCH_SIZE   = 32
LR           = 1e-3
WEIGHT_DECAY = 1e-4
VAL_SPLIT    = 0.15
TEST_SPLIT   = 0.10
PATIENCE     = 8


def _dataset_fingerprint(samples: List[Tuple[str, int]]) -> str:
    h = hashlib.md5()
    for raw_email, label in samples:
        h.update(raw_email[:100].encode("utf-8", errors="ignore"))
        h.update(str(label).encode())
    return h.hexdigest()[:16]


def extract_features_with_cache(samples, rebuild=False):
    from phishbyte.extractors.domain import score_domain
    from phishbyte.extractors.urls   import score_urls
    from phishbyte.extractors.spf    import score_spf
    from phishbyte.model.mlp         import build_feature_vector

    os.makedirs(CACHE_DIR, exist_ok=True)
    fingerprint = _dataset_fingerprint(samples)
    cache_path  = os.path.join(CACHE_DIR, f"features_{fingerprint}.pkl")

    if os.path.exists(cache_path) and not rebuild:
        print(f"  Cache HIT  → {cache_path}")
        with open(cache_path, "rb") as f:
            features, labels = pickle.load(f)
        print(f"  Loaded {len(features):,} cached vectors instantly.")
        return features, labels

    print(f"  Cache MISS → extracting features for {len(samples):,} emails")
    if os.environ.get("PHISHBYTE_SKIP_SPF") == "1":
        print(f"  SPF: SKIPPED (training mode, no DNS)")
    else:
        print(f"  SPF: LIVE  (real DNS lookups — slow on dead domains)")

    features, labels = [], []
    t0      = time.time()
    skipped = 0
    for i, (raw_email, label) in enumerate(samples):
        try:
            d = score_domain(raw_email)
            u = score_urls(raw_email)
            s = score_spf(raw_email)
            features.append(build_feature_vector(d, u, s))
            labels.append(torch.tensor([float(label)], dtype=torch.float32))
        except Exception:
            skipped += 1
        if (i + 1) % 500 == 0:
            elapsed = time.time() - t0
            rate    = (i + 1) / elapsed
            eta     = (len(samples) - (i + 1)) / rate
            print(f"    [{i+1:>6}/{len(samples):>6}]  "
                  f"{elapsed:>6.0f}s elapsed  {rate:>6.1f} emails/s  "
                  f"ETA {eta:>5.0f}s")

    total = time.time() - t0
    print(f"  Done. {len(features):,} valid, {skipped} skipped. ({total:.1f}s)")

    with open(cache_path, "wb") as f:
        pickle.dump((features, labels), f)
    print(f"  Cached → {cache_path}")
    return features, labels


class FeatureDataset(Dataset):
    def __init__(self, features, labels):
        self.features, self.labels = features, labels
    def __len__(self): return len(self.features)
    def __getitem__(self, idx): return self.features[idx], self.labels[idx]


def train_epoch(model, loader, optimizer, criterion, device):
    model.train()
    total_loss, correct, total = 0.0, 0, 0
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        optimizer.zero_grad()
        preds = model(xb)
        loss  = criterion(preds, yb)
        loss.backward()
        optimizer.step()
        total_loss += loss.item() * len(xb)
        correct    += ((preds >= 0.5).float() == yb).sum().item()
        total      += len(xb)
    return total_loss / total, correct / total


@torch.no_grad()
def eval_epoch(model, loader, criterion, device):
    model.eval()
    total_loss, correct, total = 0.0, 0, 0
    tp = fp = tn = fn = 0
    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        preds  = model(xb)
        loss   = criterion(preds, yb)
        total_loss += loss.item() * len(xb)
        predicted   = (preds >= 0.5).float()
        correct    += (predicted == yb).sum().item()
        total      += len(xb)
        tp += ((predicted == 1) & (yb == 1)).sum().item()
        fp += ((predicted == 1) & (yb == 0)).sum().item()
        tn += ((predicted == 0) & (yb == 0)).sum().item()
        fn += ((predicted == 0) & (yb == 1)).sum().item()
    precision = tp / (tp + fp + 1e-8)
    recall    = tp / (tp + fn + 1e-8)
    f1        = 2 * precision * recall / (precision + recall + 1e-8)
    return total_loss / total, correct / total, precision, recall, f1


def main():
    parser = argparse.ArgumentParser(description="Train PhishByte MLP")
    parser.add_argument("--data",          type=str,   default=None)
    parser.add_argument("--epochs",        type=int,   default=EPOCHS)
    parser.add_argument("--batch-size",    type=int,   default=BATCH_SIZE)
    parser.add_argument("--lr",            type=float, default=LR)
    parser.add_argument("--rebuild-cache", action="store_true")
    parser.add_argument("--skip-spf",      action="store_true",
                        help="Bypass SPF DNS lookups (use for historical datasets).")
    args = parser.parse_args()

    _set_spf_skip(args.skip_spf)

    from phishbyte.model.mlp import PhishByteMLPLayer, INPUT_DIM

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE — MLP TRAINING")
    print(f"{'═'*60}")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        cap      = torch.cuda.get_device_capability(0)
        vram_gb  = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"  Device   : GPU — {gpu_name}")
        print(f"             Compute capability {cap[0]}.{cap[1]}  ·  {vram_gb:.1f} GB VRAM")
        print(f"             PyTorch {torch.__version__}")
    else:
        print(f"  Device   : CPU (no CUDA detected)")
        print(f"             PyTorch {torch.__version__}")
    print(f"  Epochs   : {args.epochs}")
    print(f"  Batch    : {args.batch_size}")
    print(f"  LR       : {args.lr}")
    print(f"  Skip SPF : {args.skip_spf}")

    if args.data and os.path.exists(args.data):
        print(f"\n  Loading real data from {args.data}...")
        import pandas as pd
        df = pd.read_csv(args.data)

        cols = {c.lower(): c for c in df.columns}
        if "email_text" not in cols:
            print(f"  [ERROR] CSV must have 'email_text' column. Got: {list(df.columns)}")
            sys.exit(1)
        if "label" not in cols:
            print(f"  [ERROR] CSV must have 'label' column. Got: {list(df.columns)}")
            sys.exit(1)

        text_col  = cols["email_text"]
        label_col = cols["label"]
        df = df.dropna(subset=[text_col, label_col])
        df = df[df[text_col].str.len() > 0]
        samples = list(zip(df[text_col].tolist(), df[label_col].astype(int).tolist()))
        print(f"  Loaded {len(samples):,} samples.")
        n_phish = sum(1 for _, l in samples if l == 1)
        n_legit = len(samples) - n_phish
        print(f"  Balance — phish: {n_phish:,}  legit: {n_legit:,}  "
              f"({n_phish/len(samples):.1%} phish)")
    else:
        print(f"\n  Using synthetic dataset.")
        train_dir = os.path.join(ROOT, "train")
        sys.path.insert(0, train_dir)
        from synthetic_data import generate_dataset
        samples = generate_dataset(n_phish=400, n_legit=400)
        print(f"  Generated {len(samples)} synthetic samples.")

    print(f"\n  Feature extraction pipeline:")
    features, labels = extract_features_with_cache(samples, rebuild=args.rebuild_cache)
    full_dataset = FeatureDataset(features, labels)

    n        = len(full_dataset)
    n_test   = max(1, int(n * TEST_SPLIT))
    n_val    = max(1, int(n * VAL_SPLIT))
    n_train  = n - n_val - n_test
    train_ds, val_ds, test_ds = random_split(
        full_dataset, [n_train, n_val, n_test],
        generator=torch.Generator().manual_seed(42)
    )
    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True)
    val_loader   = DataLoader(val_ds,   batch_size=args.batch_size)
    test_loader  = DataLoader(test_ds,  batch_size=args.batch_size)
    print(f"\n  Split → train: {n_train:,}  val: {n_val:,}  test: {n_test:,}")

    model     = PhishByteMLPLayer().to(device)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=args.lr, weight_decay=WEIGHT_DECAY
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3
    )
    criterion = nn.BCELoss()

    params = sum(p.numel() for p in model.parameters())
    print(f"\n  Model params : {params:,}")
    print(f"  Architecture : {INPUT_DIM}→64→32→1 (sigmoid)")
    print(f"\n{'─'*60}")
    print(f"  {'Epoch':>5}  {'TrLoss':>8}  {'TrAcc':>7}  {'VaLoss':>8}  {'VaAcc':>7}  {'F1':>7}")
    print(f"{'─'*60}")

    best_val_loss = float("inf")
    patience_ctr  = 0
    os.makedirs(WEIGHTS_DIR, exist_ok=True)
    t_train_start = time.time()

    for epoch in range(1, args.epochs + 1):
        tr_loss, tr_acc = train_epoch(model, train_loader, optimizer, criterion, device)
        va_loss, va_acc, prec, rec, f1 = eval_epoch(model, val_loader, criterion, device)
        scheduler.step(va_loss)
        print(f"  {epoch:>5}  {tr_loss:>8.4f}  {tr_acc:>6.1%}  "
              f"{va_loss:>8.4f}  {va_acc:>6.1%}  {f1:>6.3f}")
        if va_loss < best_val_loss:
            best_val_loss, patience_ctr = va_loss, 0
            torch.save(model.state_dict(), WEIGHTS_PATH)
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f"\n  Early stopping at epoch {epoch} (patience={PATIENCE})")
                break

    train_time = time.time() - t_train_start

    print(f"\n{'═'*60}")
    print(f"  FINAL TEST EVALUATION")
    print(f"{'═'*60}")
    model.load_state_dict(torch.load(WEIGHTS_PATH, map_location=device, weights_only=True))
    te_loss, te_acc, prec, rec, f1 = eval_epoch(model, test_loader, criterion, device)
    print(f"  Test Loss      : {te_loss:.4f}")
    print(f"  Test Accuracy  : {te_acc:.2%}")
    print(f"  Precision      : {prec:.4f}")
    print(f"  Recall         : {rec:.4f}")
    print(f"  F1 Score       : {f1:.4f}")
    print(f"  Train time     : {train_time:.1f}s on {device.type.upper()}")
    print(f"\n  Weights saved  → {WEIGHTS_PATH}")
    print(f"{'═'*60}\n")
    print(f"  Next step: python train/calibrate_thresholds.py --data {args.data or 'synthetic'}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()