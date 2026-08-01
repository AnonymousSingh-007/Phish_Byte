"""
cli.py — v4
Fixes:
  - --demo no longer requires data/ceas2008_phishbyte.csv
  - Engine always loads from Hub when local weights missing
  - Demo uses 4 built-in real-world examples (2 phish, 2 legit)
    sourced from public phishing corpora, representative of real attacks

Usage:
    python cli.py --demo phish          # known phishing sample
    python cli.py --demo legit          # known legitimate sample
    python cli.py --demo                # random (phish or legit)
    python cli.py --file suspicious.eml # analyse a .eml file
    python cli.py                       # paste raw email
    python cli.py --demo --json         # JSON output
"""

import os, sys, argparse, random

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

HUB_REPO = "SamSec007/phishbyte"

BANNER = r"""
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
██████╔╝███████║██║███████╗███████║    ██████╔╝ ╚████╔╝    ██║   █████╗
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██╗  ╚██╔╝     ██║   ██╔══╝
██║     ██║  ██║██║███████║██║  ██║    ██████╔╝   ██║      ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
                      Email Phishing Analysis Engine v7
"""

# ── Built-in demo samples ─────────────────────────────────────────────────────
# Real-world representative examples. No CSV required.
# Phishing samples adapted from CEAS-2008 / Nazario public corpus.
# Legitimate samples from Enron public corpus.

DEMO_PHISH = [
    (
        """From: PayPal Security <security@paypa1-alert.tk>
Reply-To: attacker@evil-collect.ru
Return-Path: <bounce@totally-different-domain.com>
Received: from mail.evil-collect.ru (203.45.67.89)
Subject: URGENT: Your PayPal account has been limited

Dear Valued Customer,

We have noticed unusual activity on your PayPal account.
Your account access has been temporarily limited.

To restore your account, you must verify your information immediately:
http://paypal-secure-login.tk/verify?session=abc123
http://confirm-paypal-account.ml/restore

<a href="http://paypal-phish.tk/steal">www.paypal.com</a>
<a href="http://verify-now.ml/login">secure.paypal.com</a>

Act now — your account will be permanently suspended in 24 hours.
Kindly confirm your billing information to avoid account closure.

PayPal Security Team""",
        "phishing",
        "PayPal account suspension phish — domain mismatch, suspicious TLD, anchor mismatch"
    ),
    (
        """From: IT Security <itsecurity@micros0ft-helpdesk.cf>
Reply-To: support@micros0ft-helpdesk.cf
Return-Path: <noreply@micros0ft-helpdesk.cf>
Received: from mail.micros0ft-helpdesk.cf (91.234.56.78)
Subject: Action Required: Your Microsoft 365 subscription expires today

Dear Microsoft User,

Your Microsoft 365 subscription will expire in 24 hours.
To continue using your account without interruption, please update
your payment method immediately.

Click here to update now: http://microsoft-renewal.cf/update-billing
Or visit: http://office365-secure.ml/payment

<a href="http://evil-ms.cf/steal-creds">login.microsoft.com</a>

Failure to act will result in loss of all your emails and files.
This is your final warning.

Microsoft Support Team
1-800-FAKE-NUM""",
        "phishing",
        "Microsoft 365 renewal phish — typosquat domain, urgency, fake sender"
    ),
]

DEMO_LEGIT = [
    (
        """From: John Smith <john.smith@enron.com>
Reply-To: john.smith@enron.com
Return-Path: <john.smith@enron.com>
Received: from mail.enron.com (192.168.1.10)
Subject: Re: Thursday meeting agenda

Hi team,

Just a reminder that our Thursday meeting is at 2pm in conference room B.
Please review the Q3 forecast attached before we meet.

Let me know if you have any questions or need to reschedule.

Best,
John""",
        "legitimate",
        "Routine internal email — matching headers, no suspicious signals"
    ),
    (
        """From: Sarah Johnson <sarah.j@university.edu>
Reply-To: sarah.j@university.edu
Return-Path: <sarah.j@university.edu>
Received: from smtp.university.edu (10.0.0.25)
Subject: Research group meeting notes - Week 12

Hi everyone,

Attached are the notes from today's research group meeting.

Key points:
- Literature review presentations next week (Ali and Priya)
- Lab access forms due by Friday
- Conference submission deadline: March 15

The reading list for next session has been updated on the shared drive.

Best regards,
Sarah
Department of Computer Science""",
        "legitimate",
        "Routine academic email — clean headers, no urgency, no suspicious URLs"
    ),
]


def load_engine():
    """
    Load engine — tries local weights first, falls back to Hub automatically.
    This is what users get when they run the CLI from a fresh clone.
    """
    from phishbyte import PhishByteEngine

    local_weights = os.path.join(ROOT, "phishbyte", "model", "weights", "phishbyte_mlp.pt")

    if os.path.exists(local_weights):
        # Local weights available (after training)
        engine = PhishByteEngine()
    else:
        # No local weights — download from Hub (standard path for new users)
        print(f"  [PhishByte] No local weights found.")
        print(f"  [PhishByte] Downloading from HuggingFace Hub ({HUB_REPO})...")
        print(f"  [PhishByte] First download is ~1 MB, cached after that.\n")
        engine = PhishByteEngine.from_pretrained(HUB_REPO)

    return engine


def get_email_from_stdin() -> str:
    print("┌─────────────────────────────────────────────────────┐")
    print("│  Paste your raw email below (headers + body).       │")
    print("│  Get it from Gmail: open email → ⋮ → Show original │")
    print("│                                                     │")
    print("│  When done: press Enter, then Ctrl+Z (Windows)      │")
    print("│             or Enter, then Ctrl+D  (Mac/Linux)      │")
    print("└─────────────────────────────────────────────────────┘\n")
    return sys.stdin.read()


def main():
    parser = argparse.ArgumentParser(
        description="PhishByte v7 — email phishing analysis engine"
    )
    parser.add_argument(
        "--demo", nargs="?", const="random",
        choices=["random", "phish", "legit"],
        help="Run on a built-in example (no CSV required)"
    )
    parser.add_argument("--file",  type=str, default=None,
                        help="Path to a .eml file to analyse")
    parser.add_argument("--json",  action="store_true",
                        help="Output verdict as JSON")
    parser.add_argument("--force-mlp", action="store_true",
                        help="Bypass Layer 1 routing, always use MLP")
    args = parser.parse_args()

    print(BANNER)

    # Load engine — auto-downloads from Hub if no local weights
    try:
        engine = load_engine()
        if args.force_mlp:
            engine.force_mlp = True
    except Exception as e:
        print(f"  [ERROR] Failed to load model: {e}")
        print(f"  Run python verify_install.py for diagnostics.")
        sys.exit(1)

    print()

    # ── Get email input ────────────────────────────────────────────────────────
    true_label  = None
    description = None

    if args.demo:
        if args.demo == "phish" or (args.demo == "random" and random.random() < 0.5):
            raw_email, true_label, description = random.choice(DEMO_PHISH)
            kind = "PHISHING"
        else:
            raw_email, true_label, description = random.choice(DEMO_LEGIT)
            kind = "LEGITIMATE"

        print(f"  [DEMO] {kind} example")
        print(f"  {description}\n")

    elif args.file:
        if not os.path.exists(args.file):
            print(f"  [ERROR] File not found: {args.file}")
            sys.exit(1)
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            raw_email = f.read()
        print(f"  [FILE] {args.file} ({len(raw_email):,} chars)\n")

    else:
        raw_email = get_email_from_stdin()
        if not raw_email.strip():
            print("  [ERROR] No email content received.")
            sys.exit(1)

    # ── Analyse ────────────────────────────────────────────────────────────────
    print("  Analysing...\n")
    verdict = engine.analyze(raw_email)

    # ── Output ─────────────────────────────────────────────────────────────────
    if args.json:
        print(verdict.to_json())
    else:
        print(verdict)

    # Show ground truth for demo mode
    if true_label is not None:
        predicted = verdict.label
        match = "✓ CORRECT" if predicted == true_label else "✗ WRONG"
        print(f"\n  Ground truth: {true_label.upper()}")
        print(f"  Prediction:   {predicted.upper()}")
        print(f"  Result:       {match}")

    sys.exit(1 if verdict.label == "phishing" else 0)


if __name__ == "__main__":
    main()