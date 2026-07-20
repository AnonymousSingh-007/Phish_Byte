"""
train/peek_datasets.py
Inspect all CSVs in data/raw/ and data/ to understand their structure.
Run this BEFORE --all to make sure the acquirer knows how to parse each file.

Usage:
    python train/peek_datasets.py
"""

import os, sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pip install pandas"); sys.exit(1)


SCAN_DIRS = [
    ROOT / "data" / "raw",
    ROOT / "data",
    ROOT / "data" / "combined",
]

def peek(path: Path):
    try:
        size_mb = path.stat().st_size / 1_048_576
        df = pd.read_csv(path, nrows=5, encoding="latin-1", on_bad_lines="skip")
        n_total = sum(1 for _ in open(path, encoding="latin-1", errors="ignore")) - 1
        print(f"\n  {'─'*54}")
        print(f"  FILE  : {path.name}  ({size_mb:.1f} MB, ~{n_total:,} rows)")
        print(f"  COLS  : {list(df.columns)}")

        # Try to detect label and text columns
        cols_lower = {c.lower().strip(): c for c in df.columns}
        label_candidates = [k for k in cols_lower if any(x in k for x in ["label","spam","ham","class","phish","category"])]
        text_candidates  = [k for k in cols_lower if any(x in k for x in ["body","text","message","email","content","mail"])]
        print(f"  LABEL?: {label_candidates}")
        print(f"  TEXT? : {text_candidates}")

        # Show label distribution if detectable
        if label_candidates:
            lc = cols_lower[label_candidates[0]]
            try:
                counts = pd.read_csv(path, usecols=[lc], encoding="latin-1",
                                     on_bad_lines="skip")[lc].value_counts().to_dict()
                print(f"  DIST  : {dict(list(counts.items())[:6])}")
            except Exception as e:
                print(f"  DIST  : (could not read — {e})")

        # Show first row sample
        if text_candidates:
            tc = cols_lower[text_candidates[0]]
            sample = str(df[tc].iloc[0])[:120] if tc in df.columns else "N/A"
            print(f"  SAMPLE: {sample!r}")
    except Exception as e:
        print(f"\n  {path.name}: ERROR — {e}")


def main():
    print(f"\n{'═'*58}")
    print(f"  PHISH_BYTE — DATASET INSPECTOR")
    print(f"{'═'*58}")

    found = []
    for d in SCAN_DIRS:
        if d.exists():
            for f in sorted(d.glob("*.csv")):
                if f not in found:
                    found.append(f)

    if not found:
        print(f"  No CSV files found in {SCAN_DIRS}")
        return

    print(f"  Found {len(found)} CSV files\n")
    for f in found:
        peek(f)

    print(f"\n{'═'*58}")
    print(f"  SUMMARY — what acquire_datasets.py --all will use:")
    print(f"{'═'*58}")
    names = [f.name for f in found]
    for expected in ["CEAS_08.csv","Enron.csv","Ling.csv","Nazario.csv",
                     "Nigerian_Fraud.csv","Nigerian.csv","SpamAssasin.csv","SpamAssassin.csv"]:
        status = "✅ found" if any(expected.lower() == n.lower() for n in names) else "❌ missing"
        print(f"  {expected:<25} {status}")
    print(f"\n  Extra files detected:")
    expected_set = {"ceas_08.csv","enron.csv","ling.csv","nazario.csv",
                    "nigerian_fraud.csv","nigerian.csv","spamassasin.csv","spamassassin.csv"}
    for n in names:
        if n.lower() not in expected_set:
            size = next((f for f in found if f.name==n), None)
            mb = size.stat().st_size/1_048_576 if size else 0
            print(f"    {n}  ({mb:.1f} MB) — may contain extra training data")
    print()

if __name__ == "__main__":
    main()