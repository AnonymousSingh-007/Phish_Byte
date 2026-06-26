"""
cli.py  —  PhishByte interactive command-line interface.
Paste a raw email (headers + body), get a full verdict.

Usage
─────
    python cli.py
    python cli.py --file suspicious.eml
    python cli.py --demo                   # runs on a built-in phishing sample
"""

import os
import sys
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from phishbyte.engine import PhishByteEngine


DEMO_EMAIL = """From: PayPal Security <security@paypa1-alert.tk>
Reply-To: attacker@evil-domain.ru
Return-Path: <bounce@totally-different.com>
Received: from mail.evil-domain.ru (203.45.67.89)
Subject: URGENT: Your account will be suspended immediately

Dear Valued Customer,

URGENT: Your PayPal account has been suspended due to unusual activity.
You must verify your account immediately or it will be closed in 24 hours.

Click here to verify now: http://paypal-login.tk/verify?user=victim
Confirm your details: http://secure-paypal.ml/account/validate

<a href="http://evil-phish.tk/steal">www.paypal.com</a>
<a href="http://another-bad.ml/login">secure.paypal.com</a>

Act now to avoid permanent suspension. Limited time to respond.
Kindly confirm your banking details to restore access immediately.
"""

BANNER = r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
██████╔╝███████║██║███████╗███████║    ██████╔╝ ╚████╔╝    ██║   █████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██╗  ╚██╔╝     ██║   ██╔══╝
██║     ██║  ██║██║███████║██║  ██║    ██████╔╝   ██║      ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
                      Email Phishing Analysis Engine v2.0
"""


def print_banner():
    print(BANNER)


def get_email_from_stdin() -> str:
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Paste your raw email below (headers + body).       │")
    print("│  Include everything — From, Reply-To, Received...   │")
    print("│  When done: press Enter, then Ctrl+Z (Win)          │")
    print("│             or Enter, then Ctrl+D (Mac/Linux)       │")
    print("└─────────────────────────────────────────────────────┘\n")
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(
        description="PhishByte CLI — paste an email, get a verdict."
    )
    parser.add_argument(
        "--file", type=str, default=None,
        help="Path to a .eml file to analyse."
    )
    parser.add_argument(
        "--demo", action="store_true",
        help="Run on a built-in phishing sample."
    )
    parser.add_argument(
        "--weights", type=str, default=None,
        help="Path to custom model weights .pt file."
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Output verdict as JSON instead of formatted display."
    )
    args = parser.parse_args()

    print_banner()

    # ── Load engine ───────────────────────────────────────────────────────────
    engine = PhishByteEngine(weights_path=args.weights)
    print()

    # ── Get email input ───────────────────────────────────────────────────────
    if args.demo:
        print("  [DEMO MODE] Running on built-in phishing sample...\n")
        raw_email = DEMO_EMAIL

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

    # ── Analyse ───────────────────────────────────────────────────────────────
    print("  Analysing...\n")
    verdict = engine.analyze(raw_email)

    # ── Output ────────────────────────────────────────────────────────────────
    if args.json:
        print(verdict.to_json())
    else:
        print(verdict)

    # Exit code: 1 if phishing (useful for scripting/browser ext later)
    sys.exit(1 if verdict.label == "phishing" else 0)


if __name__ == "__main__":
    main()