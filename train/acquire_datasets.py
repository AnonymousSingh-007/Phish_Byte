"""
train/acquire_datasets.py — v5

Adds HuggingFace dataset loading alongside existing Kaggle CSVs.
New: farshad72/spam_email (83K rows, label + text columns)
New: puyang2025/seven-phishing-email-datasets (203K, unified 7-source)

Usage:
    python train/acquire_datasets.py --all            # Kaggle CSVs only
    python train/acquire_datasets.py --hf             # HuggingFace datasets only
    python train/acquire_datasets.py --all --hf       # everything combined
    python train/acquire_datasets.py --check-existing # inspect what's in data/raw/
"""

import os, sys, argparse, re, tarfile, requests
from pathlib import Path

ROOT = Path(__file__).parent.parent
RAW  = ROOT / "data" / "raw"
COMB = ROOT / "data" / "combined"
for d in [RAW, COMB]: d.mkdir(parents=True, exist_ok=True)

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pip install pandas"); sys.exit(1)


def _safe(v) -> str:
    s = str(v).strip() if v is not None else ""
    return "" if s.lower() in ("nan","none","null","") else s

def _clean(text: str) -> str:
    if not text: return ""
    text = text.replace("\r\n","\n").replace("\r","\n")
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    return text[:10_000]

def _label_from_str(raw: str) -> int | None:
    r = raw.lower().strip()
    if r in ("1","spam","phishing","phish","yes","true"):  return 1
    if r in ("0","ham","legitimate","legit","no","false"): return 0
    try: return int(float(r))
    except: return None


def _load_csv(path, source, text_keys, label_keys,
              default_label=None, subject_key=None, sender_key=None):
    if not path.exists():
        print(f"  [SKIP] {path.name} not found")
        return pd.DataFrame()
    size_mb = path.stat().st_size / 1_048_576
    print(f"  Loading {path.name}  ({size_mb:.1f} MB)...")
    try:
        df = pd.read_csv(path, encoding="latin-1", on_bad_lines="skip", low_memory=False)
    except Exception as e:
        print(f"  [ERROR] {e}"); return pd.DataFrame()

    cols_lower = {c.lower().strip(): c for c in df.columns}
    text_col  = next((cols_lower[k] for k in text_keys  if k in cols_lower), None)
    label_col = next((cols_lower[k] for k in label_keys if k in cols_lower), None)
    subj_col  = cols_lower.get(subject_key) if subject_key else None
    send_col  = cols_lower.get(sender_key)  if sender_key  else None

    if not text_col:
        text_col = next((cols_lower[k] for k in cols_lower
                         if any(x in k for x in ["body","text","message","mail","content","combined"])), None)
    if not text_col:
        print(f"  [WARN] Cannot identify text column. Cols: {list(df.columns)}"); return pd.DataFrame()

    rows = []
    for _, row in df.iterrows():
        body = _safe(row.get(text_col,""))
        if not body or len(body) < 10: continue
        parts = []
        if send_col and _safe(row.get(send_col,"")): parts.append(f"From: {_safe(row[send_col])}")
        if subj_col and _safe(row.get(subj_col,"")): parts.append(f"Subject: {_safe(row[subj_col])}")
        if parts: parts.append("")
        parts.append(body)
        text  = _clean("\n".join(parts))
        label = _label_from_str(_safe(row.get(label_col,""))) if label_col else default_label
        if label is None: continue
        rows.append({"email_text": text, "label": label, "source": source})

    result = pd.DataFrame(rows).dropna()
    result = result[result["email_text"].str.len() > 30] if not result.empty else result
    n_phish = int(result["label"].sum()) if not result.empty else 0
    print(f"    → {len(result):,} rows  ({n_phish:,} phish / {len(result)-n_phish:,} legit)")
    return result


# ── Kaggle CSV loaders ────────────────────────────────────────────────────────

def load_ceas():
    return _load_csv(RAW/"CEAS_08.csv", "ceas2008",
        ["body","text","message"], ["label","spam","class"],
        subject_key="subject", sender_key="sender")

def load_enron():
    return _load_csv(RAW/"Enron.csv", "enron",
        ["body","text","message","email","mail"], ["label","spam","ham","class"])

def load_ling():
    return _load_csv(RAW/"Ling.csv", "lingspam",
        ["body","text","message","mail"], ["label","spam","ham","class"])

def load_nazario():
    return _load_csv(RAW/"Nazario.csv", "nazario",
        ["body","text","message","mail","email"], ["label","spam","class"],
        default_label=1)

def load_nigerian():
    path = RAW/"Nigerian_Fraud.csv"
    if not path.exists(): path = RAW/"Nigerian.csv"
    return _load_csv(path, "nigerian",
        ["body","text","message","mail","email"], ["label","spam","class"],
        default_label=1, subject_key="subject", sender_key="sender")

def load_spamassassin_kaggle():
    return _load_csv(RAW/"SpamAssasin.csv", "spamassassin_kaggle",
        ["body","text","message","mail","email"], ["label","spam","ham","class"],
        subject_key="subject", sender_key="sender")

def load_spamassassin_apache():
    path = COMB/"spamassassin.csv"
    if not path.exists(): return pd.DataFrame()
    return _load_csv(path, "spamassassin_apache",
        ["email_text","body","text","message"], ["label","spam","class"])


# ── HuggingFace dataset loaders ───────────────────────────────────────────────

def load_hf_farshad() -> pd.DataFrame:
    """
    farshad72/spam_email — 83,448 rows
    Columns: label (0/1), text (email body)
    Mix of Enron legit, pharmacy spam, watch replicas, stock scams.
    Has modern-ish notification-style legitimate emails.
    """
    print(f"\n  Loading farshad72/spam_email from HuggingFace...")
    try:
        from datasets import load_dataset
    except ImportError:
        print(f"  [ERROR] pip install datasets")
        return pd.DataFrame()

    try:
        ds = load_dataset("farshad72/spam_email", split="train")
        rows = []
        for item in ds:
            text  = _clean(_safe(item.get("text","")))
            label = item.get("label", None)
            if not text or len(text) < 10 or label is None: continue
            rows.append({"email_text": text, "label": int(label), "source": "farshad72"})
        result = pd.DataFrame(rows).dropna()
        result = result[result["email_text"].str.len() > 30] if not result.empty else result
        n_phish = int(result["label"].sum()) if not result.empty else 0
        print(f"    → {len(result):,} rows  ({n_phish:,} phish / {len(result)-n_phish:,} legit)")
        return result
    except Exception as e:
        print(f"  [ERROR] Failed to load farshad72/spam_email: {e}")
        return pd.DataFrame()


def load_hf_puyang() -> pd.DataFrame:
    """
    puyang2025/seven-phishing-email-datasets — 203,017 rows
    Unified 7-source corpus: Assassin, CEAS-08, Enron, Ling, TREC-05/06/07
    Will heavily overlap with our Kaggle CSVs — dedup handles it.
    """
    print(f"\n  Loading puyang2025/seven-phishing-email-datasets from HuggingFace...")
    try:
        from datasets import load_dataset
    except ImportError:
        print(f"  [ERROR] pip install datasets")
        return pd.DataFrame()

    try:
        ds = load_dataset("puyang2025/seven-phishing-email-datasets", split="train")
        rows = []
        for item in ds:
            text  = _clean(_safe(item.get("text", item.get("body", ""))))
            label = item.get("label", None)
            if not text or len(text) < 10 or label is None: continue
            source = f"puyang_{_safe(item.get('dataset_name','unknown'))}"
            rows.append({"email_text": text, "label": int(label), "source": source})
        result = pd.DataFrame(rows).dropna()
        result = result[result["email_text"].str.len() > 30] if not result.empty else result
        n_phish = int(result["label"].sum()) if not result.empty else 0
        print(f"    → {len(result):,} rows  ({n_phish:,} phish / {len(result)-n_phish:,} legit)")
        return result
    except Exception as e:
        print(f"  [ERROR] Failed to load puyang2025: {e}")
        return pd.DataFrame()


# ── SpamAssassin auto-download ────────────────────────────────────────────────

def download_spamassassin() -> pd.DataFrame:
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
            print(f"  Downloading {fname} ...")
            try:
                r = requests.get(BASE+fname, timeout=60, stream=True)
                r.raise_for_status()
                with open(local,"wb") as f:
                    for chunk in r.iter_content(8192): f.write(chunk)
            except Exception as e:
                print(f"  [WARN] {e}"); continue
        print(f"  Parsing {fname} ...")
        try:
            with tarfile.open(local, "r:bz2") as tar:
                for m in tar.getmembers():
                    if m.isfile():
                        f = tar.extractfile(m)
                        if f:
                            try:
                                text = f.read().decode("utf-8", errors="ignore")
                                rows.append({"email_text": _clean(text),
                                             "label": label, "source": "spamassassin"})
                            except Exception: pass
        except Exception as e:
            print(f"  [WARN] {e}")
    df = pd.DataFrame(rows).dropna().query("email_text != ''") if rows else pd.DataFrame()
    if not df.empty:
        out = COMB/"spamassassin.csv"
        df.to_csv(out, index=False)
        print(f"  SpamAssassin: {len(df):,} rows — saved → {out}")
    return df


# ── Combine & save ────────────────────────────────────────────────────────────

def combine_and_save(dfs: list) -> pd.DataFrame:
    valid = [d for d in dfs if d is not None and not d.empty]
    if not valid:
        print("  [ERROR] No data loaded."); return pd.DataFrame()

    combined = pd.concat(valid, ignore_index=True)
    before   = len(combined)
    combined["_key"] = combined["email_text"].str[:200]
    combined = combined.drop_duplicates(subset=["_key"]).drop(columns=["_key"])
    combined = combined[combined["email_text"].str.len() > 50]
    combined = combined.sample(frac=1, random_state=42).reset_index(drop=True)
    after    = len(combined)

    n_phish = int(combined["label"].sum())
    n_legit = len(combined) - n_phish

    print(f"\n{'═'*60}")
    print(f"  COMBINED CORPUS")
    print(f"{'═'*60}")
    print(f"  Before dedup : {before:,}")
    print(f"  After dedup  : {after:,}")
    print(f"  Phishing     : {n_phish:,}  ({n_phish/after:.1%})")
    print(f"  Legitimate   : {n_legit:,}  ({n_legit/after:.1%})")
    print(f"\n  Source breakdown:")
    for src, grp in combined.groupby("source"):
        p = int(grp["label"].sum())
        print(f"    {src:<35} {len(grp):>8,}  ({p:,} phish / {len(grp)-p:,} legit)")

    out = COMB / "phishbyte_v3_corpus.csv"
    combined[["email_text","label","source"]].to_csv(out, index=False)
    print(f"\n  ✅ Saved {after:,} rows → {out}")
    print(f"\n  Next step:")
    print(f"  python train/train.py --data data/combined/phishbyte_v3_corpus.csv --skip-spf")
    print(f"{'═'*60}\n")
    return combined


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="PhishByte dataset acquisition")
    parser.add_argument("--check-existing", action="store_true")
    parser.add_argument("--spamassassin",   action="store_true")
    parser.add_argument("--all",  action="store_true",
                        help="Load all Kaggle CSVs from data/raw/")
    parser.add_argument("--hf",   action="store_true",
                        help="Load HuggingFace datasets (requires: pip install datasets)")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE — DATASET ACQUISITION")
    print(f"{'═'*60}")

    if args.check_existing:
        print(f"\n  Scanning {RAW}...\n")
        for f in sorted(list(RAW.glob("*.csv")) + list(COMB.glob("*.csv"))):
            try:
                mb   = f.stat().st_size / 1_048_576
                rows = sum(1 for _ in open(f, encoding="latin-1", errors="ignore")) - 1
                df3  = pd.read_csv(f, nrows=2, encoding="latin-1", on_bad_lines="skip")
                print(f"  {f.name:<35} {mb:>6.1f} MB  ~{rows:>7,} rows  cols={list(df3.columns)[:5]}")
            except Exception as e:
                print(f"  {f.name}: {e}")
        return

    if args.spamassassin:
        download_spamassassin()
        return

    dfs = []

    if args.all:
        print("\n  Loading Kaggle CSVs from data/raw/...\n")
        dfs += [
            load_ceas(),
            load_enron(),
            load_ling(),
            load_nazario(),
            load_nigerian(),
            load_spamassassin_kaggle(),
            load_spamassassin_apache(),
        ]

    if args.hf:
        print("\n  Loading HuggingFace datasets...")
        print("  (requires: pip install datasets)")
        dfs += [
            load_hf_farshad(),
            load_hf_puyang(),
        ]

    if not dfs:
        print("  Use --all, --hf, or both. Examples:")
        print("  python train/acquire_datasets.py --all")
        print("  python train/acquire_datasets.py --hf")
        print("  python train/acquire_datasets.py --all --hf")
        return

    combine_and_save(dfs)


if __name__ == "__main__":
    main()