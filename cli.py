"""
cli.py — v3
Adds --force-mlp flag to bypass Layer 1 routing for testing.
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
    if not os.path.exists(CEAS_CSV):
        print(f"  [ERROR] No CEAS-2008 data at {CEAS_CSV}")
        sys.exit(1)
    import pandas as pd
    df = pd.read_csv(CEAS_CSV).dropna()
    if class_filter == "phish":  df = df[df["label"] == 1]
    elif class_filter == "legit": df = df[df["label"] == 0]
    if seed is not None: random.seed(seed)
    row = df.sample(n=1).iloc[0]
    return row["email_text"], int(row["label"])


def get_email_from_stdin():
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Paste your raw email below (headers + body).       │")
    print("│  When done: press Enter, then Ctrl+Z (Win)          │")
    print("│             or Enter, then Ctrl+D (Mac/Linux)       │")
    print("└─────────────────────────────────────────────────────┘\n")
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--file",      type=str, default=None)
    parser.add_argument("--demo",      nargs="?", const="random",
                        choices=["random", "phish", "legit"])
    parser.add_argument("--seed",      type=int, default=None)
    parser.add_argument("--weights",   type=str, default=None)
    parser.add_argument("--json",      action="store_true")
    parser.add_argument("--force-mlp", action="store_true",
                        help="Bypass Layer 1 routing — always use MLP.")
    args = parser.parse_args()

    print(BANNER)
    from phishbyte.engine import PhishByteEngine
    engine = PhishByteEngine(weights_path=args.weights, force_mlp=args.force_mlp)
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
        print(f"  [FILE] Loaded {args.file}\n")
    else:
        raw_email = get_email_from_stdin()
        if not raw_email.strip():
            print("  [ERROR] No email content.")
            sys.exit(1)

    print(f"  Analysing...\n")
    verdict = engine.analyze(raw_email)
    print(verdict.to_json() if args.json else verdict)

    if true_label is not None:
        predicted = 1 if verdict.label == "phishing" else 0
        match = "✓ CORRECT" if predicted == true_label else "✗ WRONG"
        print(f"\n  Prediction vs truth: {match}")
        print(f"  Predicted: {verdict.label}    Actual: {'phishing' if true_label else 'legitimate'}")

    sys.exit(1 if verdict.label == "phishing" else 0)


if __name__ == "__main__":
    main()