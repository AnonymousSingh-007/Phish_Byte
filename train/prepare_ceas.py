"""
train/prepare_ceas.py
Convert the Kaggle CEAS_08.csv into a Phish_Byte training CSV.

Input  (from Kaggle naserabdullahalam/phishing-email-dataset):
    CEAS_08.csv
    columns: sender, receiver, date, subject, body, urls, label

Output:
    data/ceas2008_phishbyte.csv
    columns: email_text, label
    where email_text is a reconstructed raw .eml string with headers + body,
    so it flows through the existing score_domain/score_urls extractors.

Usage:
    1. Download from Kaggle:
       https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset
    2. Extract CEAS_08.csv to data/raw/CEAS_08.csv
    3. Run: python train/prepare_ceas.py
"""

import os
import sys
import argparse
import random
from typing import Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

RAW_DEFAULT = os.path.join(ROOT, "data", "raw", "CEAS_08.csv")
OUT_DEFAULT = os.path.join(ROOT, "data", "ceas2008_phishbyte.csv")


def _safe_str(val) -> str:
    """Coerce CSV cell to a clean string, handle NaN / None."""
    if val is None:
        return ""
    s = str(val).strip()
    if s.lower() in ("nan", "none", "null"):
        return ""
    return s


def _synth_received_ip() -> str:
    """Generate a plausible IP for the Received header. Random but stable per row."""
    return f"{random.randint(50, 220)}.{random.randint(1, 254)}." \
           f"{random.randint(1, 254)}.{random.randint(1, 254)}"


def reconstruct_eml(
    sender:   str,
    receiver: str,
    date:     str,
    subject:  str,
    body:     str,
    urls:     str = "",
) -> str:
    """
    Build a raw .eml-style string from CSV columns.

    The reconstructed email is good enough for our feature extractors:
        - score_domain() reads From / Reply-To / Return-Path headers
        - score_urls()   reads body text for HTTPS/HTTP counts, anchor mismatches,
                         urgency keywords, link density
        - score_spf()    will be bypassed during training (historical data)
    """
    sender   = _safe_str(sender)
    receiver = _safe_str(receiver)
    date     = _safe_str(date)
    subject  = _safe_str(subject)
    body     = _safe_str(body)
    urls     = _safe_str(urls)

    if not sender:
        sender = "unknown@unknown.invalid"

    received_ip = _synth_received_ip()

    headers = [
        f"From: {sender}",
        f"Reply-To: {sender}",
        f"Return-Path: <{sender}>",
        f"To: {receiver}" if receiver else "To: undisclosed-recipients",
        f"Date: {date}" if date else "Date: unknown",
        f"Subject: {subject}",
        f"Received: from mail.unknown ({received_ip})",
        "Content-Type: text/html; charset=utf-8",
        "",
    ]

    return "\n".join(headers) + "\n" + body


def main():
    parser = argparse.ArgumentParser(description="Prepare CEAS-2008 for Phish_Byte training.")
    parser.add_argument("--input",  type=str, default=RAW_DEFAULT,
                        help="Path to raw CEAS_08.csv from Kaggle.")
    parser.add_argument("--output", type=str, default=OUT_DEFAULT,
                        help="Output CSV path.")
    parser.add_argument("--limit",  type=int, default=None,
                        help="Optional row limit for quick testing.")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  CEAS-2008 → Phish_Byte training CSV")
    print(f"{'═'*60}")

    if not os.path.exists(args.input):
        print(f"\n  [ERROR] Input not found: {args.input}")
        print(f"\n  Steps to fix:")
        print(f"  1. Download dataset from Kaggle:")
        print(f"     https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset")
        print(f"  2. Extract CEAS_08.csv from the zip")
        print(f"  3. Place at: {args.input}")
        print(f"  4. Rerun this script\n")
        sys.exit(1)

    try:
        import pandas as pd
    except ImportError:
        print("  [ERROR] pandas not installed. Run: pip install pandas")
        sys.exit(1)

    print(f"  Input  : {args.input}")
    print(f"  Output : {args.output}")
    print(f"\n  Loading CSV...")
    df = pd.read_csv(args.input)
    print(f"  Loaded {len(df):,} rows.")
    print(f"  Columns: {list(df.columns)}")

    required = {"sender", "subject", "body", "label"}
    missing  = required - set(df.columns)
    if missing:
        print(f"\n  [ERROR] CSV missing required columns: {missing}")
        print(f"  Expected columns: sender, receiver, date, subject, body, urls, label")
        sys.exit(1)

    if args.limit:
        df = df.head(args.limit)
        print(f"  Limited to first {len(df):,} rows.")

    print(f"\n  Reconstructing .eml strings...")
    random.seed(42)
    df["email_text"] = df.apply(
        lambda r: reconstruct_eml(
            sender   = r.get("sender",   ""),
            receiver = r.get("receiver", ""),
            date     = r.get("date",     ""),
            subject  = r.get("subject",  ""),
            body     = r.get("body",     ""),
            urls     = r.get("urls",     ""),
        ),
        axis=1,
    )

    df["label"] = df["label"].astype(int)
    out_df = df[["email_text", "label"]].copy()

    label_counts = out_df["label"].value_counts().to_dict()
    print(f"  Label distribution: {label_counts}")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    out_df.to_csv(args.output, index=False)
    print(f"\n  Wrote {len(out_df):,} rows → {args.output}")
    print(f"{'═'*60}\n")
    print(f"  Next step:")
    print(f"  python train/train.py --data {args.output}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()