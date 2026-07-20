"""
train/acquire_datasets.py
Downloads and preprocesses all 6 phishing datasets into a unified
training CSV for PhishByte v3.

Datasets:
  1. CEAS-2008       → already in data/raw/CEAS_08.csv (done)
  2. Enron           → Kaggle: 'wandita/enron-email-dataset-phishing'
  3. SpamAssassin    → public Apache archive (auto-downloaded)
  4. Ling-Spam       → UCI ML via direct URL
  5. Nazario         → GitHub clair-ot/phishing-dataset
  6. Nigerian Fraud  → Kaggle: '20000 spam or ham emails' (Monkey Learn)

Output:
  data/combined/phishbyte_v3_corpus.csv
  columns: email_text, label, source
  label: 1=phishing/spam, 0=legitimate
  source: which dataset it came from (useful for debugging)

Usage:
  python train/acquire_datasets.py --all
  python train/acquire_datasets.py --dataset spamassassin
  python train/acquire_datasets.py --dataset enron --kaggle-key ~/.kaggle/kaggle.json
"""

import os, sys, argparse, random, re, tarfile, zipfile, requests, io
from pathlib import Path

ROOT    = Path(__file__).parent.parent
DATA    = ROOT / "data"
RAW     = DATA / "raw"
COMBINED= DATA / "combined"
OUT_CSV = COMBINED / "phishbyte_v3_corpus.csv"

for d in [RAW, COMBINED]:
    d.mkdir(parents=True, exist_ok=True)

try:
    import pandas as pd
except ImportError:
    print("[ERROR] pip install pandas")
    sys.exit(1)


def _safe_str(v) -> str:
    if v is None: return ""
    s = str(v).strip()
    return "" if s.lower() in ("nan","none","null") else s


def _clean_email_text(text: str) -> str:
    """Normalise and truncate to 10K chars to keep CSV manageable."""
    if not text: return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r'\n{4,}', '\n\n\n', text)
    return text[:10000]


# ── Dataset 1: CEAS-2008 ─────────────────────────────────────────────────────

def load_ceas() -> pd.DataFrame:
    path = RAW / "CEAS_08.csv"
    if not path.exists():
        print(f"  [SKIP] CEAS-2008 not found at {path}")
        print(f"         Download from Kaggle: naserabdullahalam/phishing-email-dataset")
        return pd.DataFrame()
    print(f"  Loading CEAS-2008 from {path}...")
    df = pd.read_csv(path)
    rows = []
    for _, r in df.iterrows():
        text = f"From: {_safe_str(r.get('sender',''))}\nSubject: {_safe_str(r.get('subject',''))}\n\n{_safe_str(r.get('body',''))}"
        rows.append({"email_text": _clean_email_text(text), "label": int(r["label"]), "source": "ceas2008"})
    result = pd.DataFrame(rows).dropna().query("email_text != ''")
    print(f"  CEAS-2008: {len(result):,} rows ({result['label'].sum():,} phish)")
    return result


# ── Dataset 2: Enron ─────────────────────────────────────────────────────────

def load_enron_kaggle() -> pd.DataFrame:
    """
    Expects data/raw/enron_spam_data.csv from Kaggle:
    wandita/enron-email-dataset-phishing
    Columns: Message ID, Subject, Message, Spam/Ham
    """
    candidates = list(RAW.glob("enron*.csv")) + list(RAW.glob("*enron*.csv"))
    if not candidates:
        print(f"  [SKIP] Enron CSV not found in {RAW}")
        print(f"         Download from Kaggle: wandita/enron-email-dataset-phishing")
        print(f"         Save as: {RAW}/enron_spam_data.csv")
        return pd.DataFrame()
    path = candidates[0]
    print(f"  Loading Enron from {path}...")
    df = pd.read_csv(path, encoding="latin-1")

    # Detect column layout
    cols = {c.lower().strip(): c for c in df.columns}
    msg_col = next((cols[k] for k in cols if "message" in k and "id" not in k), None)
    subj_col = next((cols[k] for k in cols if "subject" in k), None)
    label_col = next((cols[k] for k in cols if "spam" in k or "ham" in k or "label" in k), None)

    if not msg_col or not label_col:
        print(f"  [WARN] Could not identify columns in Enron CSV: {list(df.columns)}")
        return pd.DataFrame()

    rows = []
    for _, r in df.iterrows():
        subj = _safe_str(r.get(subj_col, "")) if subj_col else ""
        body = _safe_str(r.get(msg_col, ""))
        text = f"Subject: {subj}\n\n{body}" if subj else body
        raw_label = _safe_str(r.get(label_col, "")).lower()
        label = 1 if "spam" in raw_label or raw_label == "1" else 0
        rows.append({"email_text": _clean_email_text(text), "label": label, "source": "enron"})
    result = pd.DataFrame(rows).dropna().query("email_text != ''")
    print(f"  Enron: {len(result):,} rows ({result['label'].sum():,} phish/spam)")
    return result


# ── Dataset 3: SpamAssassin ───────────────────────────────────────────────────

def load_spamassassin() -> pd.DataFrame:
    """
    Auto-downloads SpamAssassin public corpus from Apache.
    Parses ham and spam .tar.bz2 archives into labeled rows.
    """
    BASE = "https://spamassassin.apache.org/old/publiccorpus/"
    ARCHIVES = [
        ("20030228_easy_ham.tar.bz2",    0),
        ("20030228_hard_ham.tar.bz2",    0),
        ("20030228_spam.tar.bz2",         1),
        ("20030228_spam_2.tar.bz2",       1),
    ]
    cache_dir = RAW / "spamassassin"
    cache_dir.mkdir(exist_ok=True)
    rows = []
    for fname, label in ARCHIVES:
        local = cache_dir / fname
        if not local.exists():
            url = BASE + fname
            print(f"  Downloading {fname}...")
            try:
                r = requests.get(url, timeout=30, stream=True)
                r.raise_for_status()
                with open(local, "wb") as f:
                    for chunk in r.iter_content(8192):
                        f.write(chunk)
            except Exception as e:
                print(f"  [WARN] Failed to download {fname}: {e}")
                continue
        print(f"  Parsing {fname}...")
        try:
            with tarfile.open(local, "r:bz2") as tar:
                for member in tar.getmembers():
                    if member.isfile():
                        f = tar.extractfile(member)
                        if f:
                            try:
                                text = f.read().decode("utf-8", errors="ignore")
                                rows.append({"email_text": _clean_email_text(text), "label": label, "source": "spamassassin"})
                            except Exception:
                                pass
        except Exception as e:
            print(f"  [WARN] Failed to parse {fname}: {e}")
    result = pd.DataFrame(rows).dropna().query("email_text != ''") if rows else pd.DataFrame()
    if not result.empty:
        print(f"  SpamAssassin: {len(result):,} rows ({result['label'].sum():,} spam)")
    return result


# ── Dataset 4: Ling-Spam ──────────────────────────────────────────────────────

def load_lingspam() -> pd.DataFrame:
    """
    Expects data/raw/lingspam/ directory extracted from:
    https://www.kaggle.com/datasets/mandygu/lingspam-dataset
    Or data/raw/lingspam.csv with columns: label, text
    """
    csv_path = RAW / "lingspam.csv"
    dir_path  = RAW / "lingspam"

    if csv_path.exists():
        print(f"  Loading Ling-Spam from {csv_path}...")
        df = pd.read_csv(csv_path)
        cols = {c.lower(): c for c in df.columns}
        text_col  = next((cols[k] for k in cols if k in ("text","body","message","email")), None)
        label_col = next((cols[k] for k in cols if k in ("label","spam","class","category")), None)
        if text_col and label_col:
            rows = [{"email_text": _clean_email_text(_safe_str(r[text_col])), "label": int(r[label_col]), "source": "lingspam"}
                    for _, r in df.iterrows()]
            result = pd.DataFrame(rows).dropna().query("email_text != ''")
            print(f"  Ling-Spam: {len(result):,} rows ({result['label'].sum():,} spam)")
            return result

    if dir_path.exists():
        rows = []
        for fpath in dir_path.rglob("*.txt"):
            label = 1 if "spmsg" in fpath.name or "spam" in str(fpath) else 0
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                rows.append({"email_text": _clean_email_text(text), "label": label, "source": "lingspam"})
            except Exception: pass
        result = pd.DataFrame(rows).dropna().query("email_text != ''") if rows else pd.DataFrame()
        if not result.empty:
            print(f"  Ling-Spam: {len(result):,} rows ({result['label'].sum():,} spam)")
        return result

    print(f"  [SKIP] Ling-Spam not found. Download from Kaggle: mandygu/lingspam-dataset")
    print(f"         Save CSV as: {RAW}/lingspam.csv  OR  extract directory to: {RAW}/lingspam/")
    return pd.DataFrame()


# ── Dataset 5: Nazario phishing emails ───────────────────────────────────────

def load_nazario() -> pd.DataFrame:
    """
    Expects data/raw/nazario/ directory with .eml files, OR
    data/raw/nazario.csv with columns: email_text, label
    from: https://github.com/clair-ot/phishing-dataset
    """
    csv_path = RAW / "nazario.csv"
    dir_path  = RAW / "nazario"

    if csv_path.exists():
        print(f"  Loading Nazario from {csv_path}...")
        df = pd.read_csv(csv_path)
        cols = {c.lower(): c for c in df.columns}
        text_col = next((cols[k] for k in cols if "text" in k or "body" in k or "email" in k), None)
        if text_col:
            rows = [{"email_text": _clean_email_text(_safe_str(r[text_col])), "label": 1, "source": "nazario"}
                    for _, r in df.iterrows()]
            result = pd.DataFrame(rows).dropna().query("email_text != ''")
            print(f"  Nazario: {len(result):,} phishing emails")
            return result

    if dir_path.exists():
        rows = []
        for fpath in dir_path.rglob("*.eml"):
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
                rows.append({"email_text": _clean_email_text(text), "label": 1, "source": "nazario"})
            except Exception: pass
        result = pd.DataFrame(rows).dropna().query("email_text != ''") if rows else pd.DataFrame()
        if not result.empty:
            print(f"  Nazario: {len(result):,} phishing emails")
        return result

    print(f"  [SKIP] Nazario not found.")
    print(f"         Clone: git clone https://github.com/clair-ot/phishing-dataset {RAW}/nazario")
    print(f"         OR place CSV at: {RAW}/nazario.csv")
    return pd.DataFrame()


# ── Dataset 6: Nigerian Fraud ────────────────────────────────────────────────

def load_nigerian() -> pd.DataFrame:
    """
    Expects data/raw/nigerian_fraud.csv
    from Kaggle: ambityga/email-classificaton  OR  monkey-learn spam datasets
    Columns typically: v1 (ham/spam), v2 (text)
    """
    candidates = list(RAW.glob("nigerian*.csv")) + list(RAW.glob("*fraud*.csv")) + list(RAW.glob("*sms*.csv")) + list(RAW.glob("spam*.csv"))
    if not candidates:
        print(f"  [SKIP] Nigerian fraud CSV not found in {RAW}")
        print(f"         Download from Kaggle: ambityga/email-classificaton")
        print(f"         Save as: {RAW}/nigerian_fraud.csv")
        return pd.DataFrame()

    path = candidates[0]
    print(f"  Loading Nigerian fraud from {path}...")
    df = pd.read_csv(path, encoding="latin-1")
    cols_lower = {c.lower().strip(): c for c in df.columns}

    # Common column layouts
    text_col  = next((cols_lower[k] for k in ["v2","text","body","message","email"] if k in cols_lower), None)
    label_col = next((cols_lower[k] for k in ["v1","label","class","category","spam"] if k in cols_lower), None)

    if not text_col or not label_col:
        print(f"  [WARN] Unrecognised columns: {list(df.columns)}")
        return pd.DataFrame()

    rows = []
    for _, r in df.iterrows():
        text  = _safe_str(r[text_col])
        raw_l = _safe_str(r[label_col]).lower()
        label = 1 if "spam" in raw_l or raw_l == "1" else 0
        rows.append({"email_text": _clean_email_text(text), "label": label, "source": "nigerian"})
    result = pd.DataFrame(rows).dropna().query("email_text != ''")
    print(f"  Nigerian: {len(result):,} rows ({result['label'].sum():,} spam/fraud)")
    return result


# ── Combine + balance ─────────────────────────────────────────────────────────

def combine_and_save(dfs: list[pd.DataFrame]) -> pd.DataFrame:
    """
    Merge all datasets, de-duplicate by email_text hash,
    report class balance, and save.
    """
    all_df = pd.concat([d for d in dfs if not d.empty], ignore_index=True)
    before = len(all_df)
    all_df = all_df.drop_duplicates(subset=["email_text"])
    after  = len(all_df)
    print(f"\n  De-duplicated: {before:,} → {after:,} ({before-after:,} removed)")

    n_phish = int(all_df["label"].sum())
    n_legit = len(all_df) - n_phish
    print(f"  Class balance: phish={n_phish:,} ({n_phish/len(all_df):.1%})  legit={n_legit:,}")
    print(f"\n  Source breakdown:")
    for src, grp in all_df.groupby("source"):
        p = int(grp["label"].sum())
        print(f"    {src:<20} {len(grp):>6,} rows  ({p:,} phish)")

    all_df = all_df.sample(frac=1, random_state=42).reset_index(drop=True)
    all_df.to_csv(OUT_CSV, index=False)
    print(f"\n  Saved {len(all_df):,} rows → {OUT_CSV}")
    return all_df


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--all",        action="store_true", help="Load all datasets")
    parser.add_argument("--dataset",    type=str, default=None,
                        choices=["ceas","enron","spamassassin","lingspam","nazario","nigerian"],
                        help="Load a single dataset for testing")
    parser.add_argument("--kaggle-key", type=str, default=None, help="Path to kaggle.json")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE v3 — MULTI-DATASET ACQUISITION")
    print(f"{'═'*60}\n")

    loaders = {
        "ceas":          load_ceas,
        "enron":         load_enron_kaggle,
        "spamassassin":  load_spamassassin,
        "lingspam":      load_lingspam,
        "nazario":       load_nazario,
        "nigerian":      load_nigerian,
    }

    if args.dataset:
        df = loaders[args.dataset]()
        if not df.empty:
            out = COMBINED / f"{args.dataset}_preview.csv"
            df.head(100).to_csv(out, index=False)
            print(f"\n  Preview saved → {out}")
        return

    if args.all:
        print("  Loading all 6 datasets...\n")
        dfs = []
        for name, fn in loaders.items():
            print(f"  ── {name.upper()} ──")
            dfs.append(fn())
        print(f"\n{'─'*60}")
        combine_and_save(dfs)
        print(f"\n  Run training:")
        print(f"  python train/train.py --data data/combined/phishbyte_v3_corpus.csv --skip-spf")
        print(f"{'═'*60}\n")
    else:
        print("  Usage: python train/acquire_datasets.py --all")
        print("         python train/acquire_datasets.py --dataset spamassassin")


if __name__ == "__main__":
    main()