"""
train/train.py
PhishByte MLP — end-to-end training pipeline.

Pipeline
────────
raw email string
    → score_domain()  ]
    → score_urls()    ] Layer 1 extractors
    → score_spf()     ]
    → build_feature_vector()   15-d float32 tensor
    → PhishByteMLPLayer        forward pass
    → BCELoss                  backprop
    → saved checkpoint         phishbyte/model/weights/phishbyte_mlp.pt

Usage
─────
    cd O:\\Confidential\\Phish_Byte
    python train/train.py                        # synthetic data
    python train/train.py --data data/ceas.csv   # real CEAS-2008 later
"""

import os
import sys
import argparse
import random
import time
from typing import List, Tuple

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader, random_split

# ── Path setup ────────────────────────────────────────────────────────────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from phishbyte.extractors.domain import score_domain
from phishbyte.extractors.urls   import score_urls
from phishbyte.extractors.spf    import score_spf
from phishbyte.model.mlp         import PhishByteMLPLayer, build_feature_vector

# ── Config ────────────────────────────────────────────────────────────────────
WEIGHTS_DIR  = os.path.join(ROOT, "phishbyte", "model", "weights")
WEIGHTS_PATH = os.path.join(WEIGHTS_DIR, "phishbyte_mlp.pt")

EPOCHS       = 40
BATCH_SIZE   = 32
LR           = 1e-3
WEIGHT_DECAY = 1e-4
VAL_SPLIT    = 0.15
TEST_SPLIT   = 0.10
PATIENCE     = 8          # early stopping patience


# ── Dataset ───────────────────────────────────────────────────────────────────

class EmailDataset(Dataset):
    """
    Wraps (raw_email, label) pairs.
    Feature extraction runs once here at construction — not at every forward pass.
    """

    def __init__(self, samples: List[Tuple[str, int]]):
        self.features: List[torch.Tensor] = []
        self.labels:   List[torch.Tensor] = []

        skipped = 0
        print(f"  Extracting features from {len(samples)} emails...")
        t0 = time.time()

        for i, (raw_email, label) in enumerate(samples):
            try:
                d = score_domain(raw_email)
                u = score_urls(raw_email)
                s = score_spf(raw_email)
                fvec = build_feature_vector(d, u, s)
                self.features.append(fvec)
                self.labels.append(torch.tensor([float(label)], dtype=torch.float32))
            except Exception as e:
                skipped += 1
                continue

            if (i + 1) % 100 == 0:
                elapsed = time.time() - t0
                print(f"    [{i+1}/{len(samples)}] {elapsed:.1f}s elapsed")

        print(f"  Done. {len(self.features)} valid, {skipped} skipped.")

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return self.features[idx], self.labels[idx]


# ── Training loop ─────────────────────────────────────────────────────────────

def train_epoch(model, loader, optimizer, criterion, device):
    model.train()
    total_loss = 0.0
    correct    = 0
    total      = 0

    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        optimizer.zero_grad()
        preds = model(xb)
        loss  = criterion(preds, yb)
        loss.backward()
        optimizer.step()

        total_loss += loss.item() * len(xb)
        predicted   = (preds >= 0.5).float()
        correct    += (predicted == yb).sum().item()
        total      += len(xb)

    return total_loss / total, correct / total


@torch.no_grad()
def eval_epoch(model, loader, criterion, device):
    model.eval()
    total_loss = 0.0
    correct    = 0
    total      = 0
    tp = fp = tn = fn = 0

    for xb, yb in loader:
        xb, yb = xb.to(device), yb.to(device)
        preds       = model(xb)
        loss        = criterion(preds, yb)
        total_loss += loss.item() * len(xb)
        predicted   = (preds >= 0.5).float()
        correct    += (predicted == yb).sum().item()
        total      += len(xb)

        # Confusion matrix components
        tp += ((predicted == 1) & (yb == 1)).sum().item()
        fp += ((predicted == 1) & (yb == 0)).sum().item()
        tn += ((predicted == 0) & (yb == 0)).sum().item()
        fn += ((predicted == 0) & (yb == 1)).sum().item()

    precision = tp / (tp + fp + 1e-8)
    recall    = tp / (tp + fn + 1e-8)
    f1        = 2 * precision * recall / (precision + recall + 1e-8)

    return (
        total_loss / total,
        correct / total,
        precision, recall, f1
    )


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Train PhishByte MLP")
    parser.add_argument(
        "--data", type=str, default=None,
        help="Path to CSV with columns [email_text, label]. "
             "Leave blank to use synthetic data."
    )
    parser.add_argument("--epochs",     type=int,   default=EPOCHS)
    parser.add_argument("--batch-size", type=int,   default=BATCH_SIZE)
    parser.add_argument("--lr",         type=float, default=LR)
    args = parser.parse_args()

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"\n{'═'*52}")
    print(f"  PHISH_BYTE — MLP TRAINING")
    print(f"{'═'*52}")
    print(f"  Device   : {device}")
    print(f"  Epochs   : {args.epochs}")
    print(f"  Batch    : {args.batch_size}")
    print(f"  LR       : {args.lr}")

    # ── Load data ─────────────────────────────────────────────────────────────
    if args.data and os.path.exists(args.data):
        print(f"\n  Loading real data from {args.data}...")
        import pandas as pd
        df      = pd.read_csv(args.data)
        samples = list(zip(df["email_text"].tolist(), df["label"].tolist()))
        print(f"  Loaded {len(samples)} samples from CSV.")
    else:
        print("\n  No data path provided — using synthetic dataset.")
        print("  (Replace with CEAS-2008 CSV when ready: --data data/ceas.csv)")
        # Import here so synthetic_data.py lives in train/
        train_dir = os.path.join(ROOT, "train")
        sys.path.insert(0, train_dir)
        from synthetic_data import generate_dataset
        samples = generate_dataset(n_phish=400, n_legit=400)
        print(f"  Generated {len(samples)} synthetic samples.")

    # ── Feature extraction ────────────────────────────────────────────────────
    print("\n  Running Layer 1 extraction pipeline on all emails...")
    full_dataset = EmailDataset(samples)

    # ── Train / val / test split ──────────────────────────────────────────────
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

    print(f"\n  Split → train: {n_train}  val: {n_val}  test: {n_test}")

    # ── Model, optimizer, loss ────────────────────────────────────────────────
    model     = PhishByteMLPLayer().to(device)
    optimizer = torch.optim.AdamW(
        model.parameters(), lr=args.lr, weight_decay=WEIGHT_DECAY
    )
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(
        optimizer, mode="min", factor=0.5, patience=3, verbose=False
    )
    criterion = nn.BCELoss()

    print(f"\n  Model params : {sum(p.numel() for p in model.parameters()):,}")
    print(f"  Architecture : {INPUT_DIM}→64→32→1 (sigmoid)")
    print(f"\n{'─'*52}")
    print(f"  {'Epoch':>5}  {'TrLoss':>8}  {'TrAcc':>7}  {'VaLoss':>8}  {'VaAcc':>7}  {'F1':>7}")
    print(f"{'─'*52}")

    best_val_loss = float("inf")
    patience_ctr  = 0
    os.makedirs(WEIGHTS_DIR, exist_ok=True)

    for epoch in range(1, args.epochs + 1):
        tr_loss, tr_acc = train_epoch(model, train_loader, optimizer, criterion, device)
        va_loss, va_acc, prec, rec, f1 = eval_epoch(model, val_loader, criterion, device)
        scheduler.step(va_loss)

        print(
            f"  {epoch:>5}  {tr_loss:>8.4f}  {tr_acc:>6.1%}  "
            f"{va_loss:>8.4f}  {va_acc:>6.1%}  {f1:>6.3f}"
        )

        # Early stopping + checkpoint
        if va_loss < best_val_loss:
            best_val_loss = va_loss
            patience_ctr  = 0
            torch.save(model.state_dict(), WEIGHTS_PATH)
        else:
            patience_ctr += 1
            if patience_ctr >= PATIENCE:
                print(f"\n  Early stopping at epoch {epoch} (patience={PATIENCE})")
                break

    # ── Final test eval ───────────────────────────────────────────────────────
    print(f"\n{'═'*52}")
    print(f"  FINAL TEST EVALUATION")
    print(f"{'═'*52}")

    # Reload best checkpoint
    model.load_state_dict(torch.load(WEIGHTS_PATH, map_location=device, weights_only=True))
    te_loss, te_acc, prec, rec, f1 = eval_epoch(model, test_loader, criterion, device)

    print(f"  Test Loss      : {te_loss:.4f}")
    print(f"  Test Accuracy  : {te_acc:.2%}")
    print(f"  Precision      : {prec:.4f}")
    print(f"  Recall         : {rec:.4f}")
    print(f"  F1 Score       : {f1:.4f}")
    print(f"\n  Weights saved  → {WEIGHTS_PATH}")
    print(f"{'═'*52}\n")
    print("  Engine is now ready. Run the CLI:")
    print("  python cli.py")
    print(f"{'═'*52}\n")


# Needed for the param count printout
from phishbyte.model.mlp import INPUT_DIM

if __name__ == "__main__":
    main()