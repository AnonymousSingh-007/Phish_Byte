"""
train/prepare_ceas.py — v2
Preserves the real sender header components instead of collapsing them.

Key fixes:
  - Parse sender properly: "PayPal Security" <attacker@random.tk> →
    From has real domain, display name preserved (so brand impersonation fires)
  - Synthesise REALISTIC reply-to and return-path that differ from From
    when the dataset suggests spoofing (display name brand ≠ domain brand)
  - Keep subject in headers properly so subject extractors can fire
"""

import os, sys, argparse, random, re
from typing import Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DEFAULT = os.path.join(ROOT, "data", "raw", "CEAS_08.csv")
OUT_DEFAULT = os.path.join(ROOT, "data", "ceas2008_phishbyte.csv")


_KNOWN_BRANDS = [
    "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "ebay", "facebook", "chase", "wells", "citibank", "hsbc",
    "bank", "fedex", "ups", "dhl", "usps", "irs", "dropbox",
]


def _safe_str(val) -> str:
    if val is None: return ""
    s = str(val).strip()
    if s.lower() in ("nan", "none", "null"): return ""
    return s


def _parse_sender(sender_raw: str) -> Tuple[str, str, str]:
    """
    Parse a sender field into (display_name, email_addr, domain).
    Handles formats:
        "Display Name" <user@domain.com>
        Display Name <user@domain.com>
        user@domain.com
    """
    sender_raw = _safe_str(sender_raw)
    if not sender_raw:
        return ("", "unknown@unknown.invalid", "unknown.invalid")

    m = re.search(r'<([^>]+)>', sender_raw)
    if m:
        addr = m.group(1).strip()
        display = sender_raw[:m.start()].strip().strip('"').strip("'").strip()
    else:
        if "@" in sender_raw:
            addr = sender_raw
            display = ""
        else:
            addr = "unknown@unknown.invalid"
            display = sender_raw

    if "@" in addr:
        domain = addr.split("@", 1)[1].strip().lower()
    else:
        domain = "unknown.invalid"

    return (display, addr.lower(), domain)


def _synth_received_ip() -> str:
    return f"{random.randint(50, 220)}.{random.randint(1, 254)}." \
           f"{random.randint(1, 254)}.{random.randint(1, 254)}"


def _looks_like_brand_impersonation(display: str, domain: str) -> bool:
    """
    If display name contains a known brand but domain doesn't match,
    the email is likely spoofing the brand.
    """
    if not display or not domain:
        return False
    display_lower = display.lower()
    for brand in _KNOWN_BRANDS:
        if brand in display_lower:
            if brand not in domain:
                return True
    return False


def reconstruct_eml(sender, receiver, date, subject, body, urls=""):
    """
    Build a raw .eml from CSV columns with realistic header diversity.
    """
    display, addr, domain = _parse_sender(sender)
    receiver = _safe_str(receiver)
    date     = _safe_str(date)
    subject  = _safe_str(subject)
    body     = _safe_str(body)

    if _looks_like_brand_impersonation(display, domain):
        reply_to = addr
        return_path = f"bounce-{random.randint(1000,9999)}@{domain}"
    else:
        if random.random() < 0.08:
            other_domain = f"mail{random.randint(1,9)}.{domain}"
            reply_to = f"noreply@{other_domain}"
            return_path = addr
        else:
            reply_to = addr
            return_path = addr

    from_header = f'"{display}" <{addr}>' if display else addr

    headers = [
        f"From: {from_header}",
        f"Reply-To: {reply_to}",
        f"Return-Path: <{return_path}>",
        f"To: {receiver}" if receiver else "To: undisclosed-recipients",
        f"Date: {date}" if date else "Date: unknown",
        f"Subject: {subject}",
        f"Received: from mail.{domain} ({_synth_received_ip()})",
        "Content-Type: text/html; charset=utf-8",
        "",
    ]
    return "\n".join(headers) + "\n" + body


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",  type=str, default=RAW_DEFAULT)
    parser.add_argument("--output", type=str, default=OUT_DEFAULT)
    parser.add_argument("--limit",  type=int, default=None)
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  CEAS-2008 → Phish_Byte training CSV (v2)")
    print(f"{'═'*60}")

    if not os.path.exists(args.input):
        print(f"\n  [ERROR] Input not found: {args.input}")
        sys.exit(1)

    import pandas as pd
    print(f"  Input  : {args.input}")
    print(f"  Output : {args.output}")
    print(f"\n  Loading CSV...")
    df = pd.read_csv(args.input)
    print(f"  Loaded {len(df):,} rows.")
    print(f"  Columns: {list(df.columns)}")

    if args.limit:
        df = df.head(args.limit)

    print(f"\n  Reconstructing .eml strings with realistic headers...")
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

    print(f"  Label distribution: {out_df['label'].value_counts().to_dict()}")

    sample = df.head(50)
    impersonations = sum(
        1 for _, r in sample.iterrows()
        if _looks_like_brand_impersonation(*_parse_sender(r.get("sender", ""))[:2])
    )
    print(f"  Sanity check on first 50 rows: {impersonations} brand impersonations detected")

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    out_df.to_csv(args.output, index=False)
    print(f"\n  Wrote {len(out_df):,} rows → {args.output}")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()