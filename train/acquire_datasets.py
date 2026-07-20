"""
train/acquire_datasets.py — v2

MUCH simpler than v1. We have two options:

OPTION A (fastest — recommended):
  The naserabdullahalam/phishing-email-dataset on Kaggle already contains
  ALL 6 datasets in one zip. You probably already downloaded it for CEAS-2008.
  Just look for the other CSVs in the same zip.

OPTION B (no Kaggle account):
  Figshare hosts 7 cleaned phishing datasets from a 2024 IEEE ICMI paper.
  Direct download, no login required.

OPTION C (SpamAssassin only — fully auto, no account):
  Apache public server, no login.

Usage:
  python train/acquire_datasets.py --check-existing
  python train/acquire_datasets.py --spamassassin
  python train/acquire_datasets.py --all
"""

import os, sys, argparse, tarfile, requests, re
from pathlib import Path

ROOT = Path(__file__).parent.parent
RAW  = ROOT / "data" / "raw"
OUT  = ROOT / "data" / "combined"

for d in [RAW, OUT]:
    d.mkdir(parents=True, exist_ok=True)

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pip install pandas"); sys.exit(1)


def _clean(text: str) -> str:
    if not text: return ""
    text = text.replace("\r\n","\n").replace("\r","\n")
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    return text[:10_000]


def _safe(v) -> str:
    s = str(v).strip() if v is not None else ""
    return "" if s.lower() in ("nan","none","null") else s


def check_existing():
    """
    Check what's already in data/raw/ from the Kaggle download you already did.
    The naserabdullahalam zip likely contains multiple CSVs.
    """
    print(f"\n{'═'*56}")
    print(f"  Scanning {RAW} for existing dataset files...")
    print(f"{'═'*56}\n")

    all_files = list(RAW.rglob("*.csv")) + list(RAW.rglob("*.txt"))
    if not all_files:
        print("  No files found in data/raw/")
        return

    for f in sorted(all_files):
        size_kb = f.stat().st_size / 1024
        try:
            df = pd.read_csv(f, nrows=3, encoding="latin-1")
            print(f"  {f.relative_to(ROOT)}  ({size_kb:.0f} KB)")
            print(f"    Columns: {list(df.columns)}")
        except Exception:
            print(f"  {f.relative_to(ROOT)}  ({size_kb:.0f} KB) — not a CSV")
    print()


def load_spamassassin() -> pd.DataFrame:
    """Auto-download SpamAssassin from Apache. No login required."""
    ARCHIVES = [
        ("20030228_easy_ham.tar.bz2", 0),
        ("20030228_hard_ham.tar.bz2", 0),
        ("20030228_spam.tar.bz2",     1),
        ("20030228_spam_2.tar.bz2",   1),
    ]
    BASE  = "https://spamassassin.apache.org/old/publiccorpus/"
    cache = RAW / "spamassassin_raw"
    cache.mkdir(exist_ok=True)
    rows  = []

    for fname, label in ARCHIVES:
        local = cache / fname
        if not local.exists():
            url = BASE + fname
            print(f"  Downloading {fname} ...")
            try:
                r = requests.get(url, timeout=60, stream=True)
                r.raise_for_status()
                with open(local, "wb") as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
                print(f"  Saved ({local.stat().st_size/1024:.0f} KB)")
            except Exception as e:
                print(f"  [WARN] Failed: {e}")
                continue
        print(f"  Parsing {fname} ...")
        try:
            with tarfile.open(local, "r:bz2") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        f_obj = tar.extractfile(member)
                        if f_obj:
                            try:
                                text = f_obj.read().decode("utf-8", errors="ignore")
                                rows.append({"email_text": _clean(text),
                                             "label": label,
                                             "source": "spamassassin"})
                            except Exception:
                                pass
        except Exception as e:
            print(f"  [WARN] Parse error: {e}")

    df = pd.DataFrame(rows).dropna().query("email_text != ''") if rows else pd.DataFrame()
    if not df.empty:
        print(f"  SpamAssassin: {len(df):,} rows  ({int(df.label.sum()):,} spam)")
    return df


def load_kaggle_combined() -> pd.DataFrame:
    """
    Load all CSVs from the naserabdullahalam Kaggle zip you already have.
    The zip contains: CEAS_08.csv, Enron.csv, Ling.csv, Nazario.csv,
                      Nigerian.csv, SpamAssasin.csv (note the typo in original)
    """
    KNOWN_FILES = {
        "Enron.csv":       {"text": ["body","text","message"], "label": ["label","spam","class"], "default_label": None},
        "Ling.csv":        {"text": ["body","text","message"], "label": ["label","spam","class"], "default_label": None},
        "Nazario.csv":     {"text": ["body","text","message"], "label": ["label","spam","class"], "default_label": 1},
        "Nigerian.csv":    {"text": ["body","text","message"], "label": ["label","spam","class"], "default_label": 1},
        "SpamAssasin.csv": {"text": ["body","text","message"], "label": ["label","spam","class"], "default_label": None},
    }

    all_rows = []
    for fname, cfg in KNOWN_FILES.items():
        candidates = list(RAW.rglob(fname)) + list(RAW.rglob(fname.lower()))
        if not candidates:
            print(f"  [SKIP] {fname} not found — extract from Kaggle zip")
            continue
        path = candidates[0]
        print(f"\n  Loading {fname} from {path} ...")
        try:
            df = pd.read_csv(path, encoding="latin-1")
            cols_lower = {c.lower().strip(): c for c in df.columns}
            print(f"    Columns: {list(df.columns)}")

            text_col = next(
                (cols_lower[k] for k in cfg["text"] if k in cols_lower), None
            )
            if not text_col:
                text_col = next(
                    (cols_lower[k] for k in cols_lower if "body" in k or "text" in k or "mail" in k), None
                )

            label_col = next(
                (cols_lower[k] for k in cfg["label"] if k in cols_lower), None
            )

            if not text_col:
                print(f"    [WARN] Cannot identify text column. Skipping.")
                continue

            source = fname.replace(".csv","").lower().replace("spamassasin","spamassassin")
            for _, row in df.iterrows():
                text = _safe(row.get(text_col,""))
                if not text: continue

                if label_col:
                    raw_l = _safe(row.get(label_col,"")).lower()
                    label = 1 if raw_l in ("1","spam","phishing","phish") else 0
                elif cfg["default_label"] is not None:
                    label = cfg["default_label"]
                else:
                    continue

                all_rows.append({"email_text": _clean(text), "label": label, "source": source})

            loaded = len([r for r in all_rows if r["source"] == source])
            print(f"    Loaded: {loaded:,} rows")
        except Exception as e:
            print(f"    [ERROR] {e}")

    return pd.DataFrame(all_rows) if all_rows else pd.DataFrame()


def load_ceas() -> pd.DataFrame:
    path = RAW / "CEAS_08.csv"
    if not path.exists():
        return pd.DataFrame()
    print(f"\n  Loading CEAS-2008 from {path} ...")
    df = pd.read_csv(path)
    rows = []
    for _, r in df.iterrows():
        text = f"From: {_safe(r.get('sender',''))}\nSubject: {_safe(r.get('subject',''))}\n\n{_safe(r.get('body',''))}"
        rows.append({"email_text": _clean(text), "label": int(r["label"]), "source": "ceas2008"})
    result = pd.DataFrame(rows).dropna().query("email_text != ''")
    print(f"  CEAS-2008: {len(result):,} rows  ({int(result.label.sum()):,} phish)")
    return result


def combine_and_save(dfs):
    combined = pd.concat([d for d in dfs if d is not None and not d.empty], ignore_index=True)
    before = len(combined)
    combined = combined.drop_duplicates(subset=["email_text"])
    after = len(combined)
    combined = combined[combined["email_text"].str.len() > 50]

    print(f"\n{'─'*56}")
    print(f"  COMBINED CORPUS")
    print(f"{'─'*56}")
    print(f"  Total (before dedup): {before:,}")
    print(f"  After dedup:          {after:,}")
    print(f"  After min-length:     {len(combined):,}")
    n_phish = int(combined.label.sum())
    n_legit = len(combined) - n_phish
    print(f"  Phishing:             {n_phish:,}  ({n_phish/len(combined):.1%})")
    print(f"  Legitimate:           {n_legit:,}  ({n_legit/len(combined):.1%})")
    print()
    for src, grp in combined.groupby("source"):
        p = int(grp.label.sum())
        print(f"    {src:<22} {len(grp):>7,}  ({p:,} phish)")

    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    outpath = OUT / "phishbyte_v3_corpus.csv"
    combined.to_csv(outpath, index=False)
    print(f"\n  Saved → {outpath}")
    print(f"\n  Next step:")
    print(f"  python train/train.py --data data/combined/phishbyte_v3_corpus.csv --skip-spf")
    return combined


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-existing", action="store_true",
                        help="Scan data/raw/ to see what files you already have")
    parser.add_argument("--spamassassin", action="store_true",
                        help="Download SpamAssassin from Apache (no login)")
    parser.add_argument("--kaggle", action="store_true",
                        help="Load Enron/Ling/Nazario/Nigerian from Kaggle zip")
    parser.add_argument("--all", action="store_true",
                        help="Combine everything available into v3 corpus")
    args = parser.parse_args()

    print(f"\n{'═'*56}")
    print(f"  PHISH_BYTE v3 — DATASET ACQUISITION")
    print(f"{'═'*56}")

    if args.check_existing:
        check_existing()
        return

    if args.spamassassin:
        df = load_spamassassin()
        if not df.empty:
            df.to_csv(OUT / "spamassassin.csv", index=False)
            print(f"  Saved → {OUT}/spamassassin.csv")
        return

    if args.kaggle:
        df = load_kaggle_combined()
        if not df.empty:
            df.to_csv(OUT / "kaggle_combined.csv", index=False)
            print(f"  Saved → {OUT}/kaggle_combined.csv")
        return

    if args.all:
        dfs = []
        print("\n  Step 1 — CEAS-2008")
        dfs.append(load_ceas())
        print("\n  Step 2 — Kaggle combined (Enron/Ling/Nazario/Nigerian)")
        dfs.append(load_kaggle_combined())
        print("\n  Step 3 — SpamAssassin (auto-download)")
        dfs.append(load_spamassassin())
        combine_and_save(dfs)
        return

    print("  Usage:")
    print("  python train/acquire_datasets.py --check-existing")
    print("  python train/acquire_datasets.py --spamassassin")
    print("  python train/acquire_datasets.py --kaggle")
    print("  python train/acquire_datasets.py --all")

if __name__ == "__main__":
    main()