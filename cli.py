"""
cli.py — v2
PhishByte interactive CLI.

Changes from v1
───────────────
  • No more hardcoded fake demo email
  • --demo now pulls a random real sample from data/ceas2008_phishbyte.csv
  • --demo phish / --demo legit lets you pick the class
  • Shows the ground truth label so you can verify the model

Usage
─────
    python cli.py                         # paste raw email
    python cli.py --file suspicious.eml   # analyse .eml file
    python cli.py --demo                  # random sample from CEAS-2008
    python cli.py --demo phish            # known phishing sample
    python cli.py --demo legit            # known legitimate sample
    python cli.py --demo --json           # JSON output
"""

import os, sys, argparse, random

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

CEAS_CSV = os.path.join(ROOT, "data", "ceas2008_phishbyte.csv")

BANNER = r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
██████╔╝███████║██║███████╗███████║    ██████╔╝ ╚████╔╝    ██║   █████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██╗  ╚██╔╝     ██║   ██╔══╝
██║     ██║  ██║██║███████║██║  ██║    ██████╔╝   ██║      ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
                      Email Phishing Analysis Engine
"""


def load_demo_sample(class_filter=None, seed=None):
    """
    Pull a random email from the CEAS-2008 CSV.
    class_filter: 'phish' | 'legit' | None for random.
    Returns (raw_email, true_label).
    """
    if not os.path.exists(CEAS_CSV):
        print(f"  [ERROR] No CEAS-2008 data at {CEAS_CSV}")
        print(f"  Run prepare_ceas.py first.")
        sys.exit(1)

    try:
        import pandas as pd
    except ImportError:
        print(f"  [ERROR] pandas required for --demo mode.")
        sys.exit(1)

    df = pd.read_csv(CEAS_CSV).dropna()

    if class_filter == "phish":
        df = df[df["label"] == 1]
    elif class_filter == "legit":
        df = df[df["label"] == 0]

    if seed is not None:
        random.seed(seed)
    row = df.sample(n=1).iloc[0]
    return row["email_text"], int(row["label"])


def get_email_from_stdin() -> str:
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Paste your raw email below (headers + body).       │")
    print("│  When done: press Enter, then Ctrl+Z (Win)          │")
    print("│             or Enter, then Ctrl+D (Mac/Linux)       │")
    print("└─────────────────────────────────────────────────────┘\n")
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(description="PhishByte CLI.")
    parser.add_argument("--file",    type=str, default=None,
                        help="Path to a .eml file.")
    parser.add_argument("--demo",    nargs="?", const="random",
                        choices=["random", "phish", "legit"],
                        help="Pull random sample from CEAS-2008.")
    parser.add_argument("--seed",    type=int, default=None,
                        help="Seed for --demo selection (reproducible).")
    parser.add_argument("--weights", type=str, default=None)
    parser.add_argument("--json",    action="store_true")
    args = parser.parse_args()

    print(BANNER)

    from phishbyte.engine import PhishByteEngine
    engine = PhishByteEngine(weights_path=args.weights)
    print()

    true_label = None
    if args.demo:
        class_filter = None if args.demo == "random" else args.demo
        print(f"  [DEMO] Pulling {args.demo} sample from CEAS-2008...\n")
        raw_email, true_label = load_demo_sample(class_filter, seed=args.seed)
        truth_text = "PHISHING" if true_label == 1 else "LEGITIMATE"
        print(f"  Ground truth label: {truth_text}\n")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"  [ERROR] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            raw_email = f.read()
        print(f"  [FILE] Loaded {args.file} ({len(raw_email):,} chars)\n")

    else:
        raw_email = get_email_from_stdin()
        if not raw_email.strip():
            print("  [ERROR] No email content received.")
            sys.exit(1)

    print(f"  Analysing...\n")
    verdict = engine.analyze(raw_email)

    if args.json:
        print(verdict.to_json())
    else:
        print(verdict)

    if true_label is not None:
        predicted = 1 if verdict.label == "phishing" else 0
        match = "✓ CORRECT" if predicted == true_label else "✗ WRONG"
        print(f"\n  Prediction vs truth: {match}")
        print(f"  Predicted: {verdict.label}    Actual: {'phishing' if true_label else 'legitimate'}")

    sys.exit(1 if verdict.label == "phishing" else 0)


if __name__ == "__main__":
    main()