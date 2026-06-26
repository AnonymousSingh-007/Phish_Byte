"""
train/synthetic_data.py
Generates synthetic phishing and legitimate emails for pipeline testing.
Not a substitute for CEAS-2008 — just enough to prove Layer 2 trains and runs.
"""

import random
from typing import List, Tuple

random.seed(42)

# ── Vocabulary pools ──────────────────────────────────────────────────────────

_LEGIT_DOMAINS = [
    "gmail.com", "outlook.com", "company.com", "university.edu",
    "github.com", "amazon.com", "microsoft.com", "apple.com",
    "linkedin.com", "dropbox.com"
]

_PHISH_DOMAINS = [
    "paypa1-alert.tk", "secure-login.ml", "account-verify.ga",
    "banking-alert.cf", "update-required.xyz", "login-secure.top",
    "verify-account.click", "security-alert.loan", "confirm-id.win",
    "bank-notification.tk"
]

_LEGIT_SUBJECTS = [
    "Meeting tomorrow at 3pm",
    "Your order has shipped",
    "Monthly newsletter — June 2025",
    "Re: Project update",
    "Invoice attached for review",
    "Welcome to the team!",
    "Your receipt from Amazon",
    "GitHub: New pull request opened",
    "Lunch plans this week?",
    "Quarterly report is ready",
]

_PHISH_SUBJECTS = [
    "URGENT: Your account will be suspended",
    "Action required: Verify your identity immediately",
    "Security alert: Unusual login detected",
    "Your account has been compromised",
    "IMMEDIATE ACTION REQUIRED: Update your details",
    "Important: Your payment method has expired",
    "Final warning: Confirm your account now",
    "Your account access will be revoked in 24 hours",
    "Alert: Suspicious activity on your account",
    "Critical: Verify your information to avoid suspension",
]

_LEGIT_BODIES = [
    "Hi {name},\n\nJust a quick note to confirm our meeting tomorrow at 3pm.\nLet me know if you need to reschedule.\n\nBest,\n{sender}",
    "Hello,\n\nYour order #{order} has been shipped and is on its way.\nExpected delivery: 2-3 business days.\n\nThank you for your purchase.",
    "Hi {name},\n\nPlease find the invoice attached for your review.\nTotal amount due: ${amount}.\n\nKind regards,\n{sender}",
    "Dear {name},\n\nWelcome aboard! We are excited to have you on the team.\nYour onboarding documents are ready.\n\nBest,\nHR Team",
    "Hi {name},\n\nJust checking in on the project status.\nCould you send me an update when you get a chance?\n\nThanks,\n{sender}",
]

_PHISH_BODIES = [
    """Dear Valued Customer,

URGENT: Your account has been suspended due to unusual activity.
You must verify your account immediately or it will be closed within 24 hours.

Click here to verify now: http://paypal-login.{tld}/verify?user=victim
Confirm your details: http://secure-account.{tld}/validate

<a href="http://evil-{tld2}.tk/steal">www.paypal.com</a>
<a href="http://another-bad.ml/login">secure.bank.com</a>

Act now to avoid account suspension. Limited time to respond.
This is your final warning before your account is permanently closed.""",

    """Dear Customer,

We detected unusual sign-in activity on your account.
Immediately verify your identity by clicking the link below:

http://verify-now.{tld}/account?token=xyz123
http://confirm-login.{tld}/validate

<a href="http://phish-site.ml/login">www.microsoft.com</a>

Your account will be locked unless you act now.
Verify immediately: http://urgent-verify.ga/confirm

Limited time offer — act within 24 hours or lose access permanently.""",

    """IMPORTANT SECURITY NOTICE

Your banking credentials need immediate verification.
Multiple failed login attempts have been detected.

Please verify your information at:
http://bank-secure.{tld}/verify
http://account-login.{tld}/confirm

<a href="http://steal-creds.tk/bank">www.yourbank.com</a>
<a href="http://phishing-site.ml/">secure.banking.com</a>

Failure to verify within 24 hours will result in account suspension.
Act now. Click here immediately. Urgent action required.""",
]

_TLDS      = ["tk", "ml", "ga", "cf", "xyz", "top"]
_NAMES     = ["John", "Sarah", "Michael", "Emily", "David", "Customer", "User"]
_SENDERS   = ["Alice", "Bob", "HR Team", "Support", "Accounts"]
_AMOUNTS   = ["250.00", "89.99", "1200.00", "45.50"]


def _random_ip() -> str:
    return f"{random.randint(50,200)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"


def _make_legit_email() -> str:
    domain  = random.choice(_LEGIT_DOMAINS)
    name    = random.choice(_NAMES)
    sender  = random.choice(_SENDERS)
    subject = random.choice(_LEGIT_SUBJECTS)
    body    = random.choice(_LEGIT_BODIES).format(
        name=name, sender=sender,
        order=random.randint(10000, 99999),
        amount=random.choice(_AMOUNTS)
    )
    ip = _random_ip()

    return f"""From: {sender} <{sender.lower().replace(' ', '.')}@{domain}>
Reply-To: {sender.lower().replace(' ', '.')}@{domain}
Return-Path: <{sender.lower().replace(' ', '.')}@{domain}>
Received: from mail.{domain} ({ip})
Subject: {subject}
Content-Type: text/plain

{body}
"""


def _make_phish_email() -> str:
    from_domain  = random.choice(_PHISH_DOMAINS)
    reply_domain = random.choice(_PHISH_DOMAINS)
    ret_domain   = random.choice(_PHISH_DOMAINS)
    subject      = random.choice(_PHISH_SUBJECTS)
    tld          = random.choice(_TLDS)
    tld2         = random.choice(_TLDS)
    body         = random.choice(_PHISH_BODIES).format(tld=tld, tld2=tld2)
    ip           = _random_ip()

    return f"""From: Security Alert <security@{from_domain}>
Reply-To: attacker@{reply_domain}
Return-Path: <bounce@{ret_domain}>
Received: from mail.{from_domain} ({ip})
Subject: {subject}
Content-Type: text/html

{body}
"""


def generate_dataset(
    n_phish: int = 300,
    n_legit: int = 300,
) -> List[Tuple[str, int]]:
    """
    Returns a list of (raw_email_string, label) tuples.
    label: 1 = phishing, 0 = legitimate
    """
    dataset: List[Tuple[str, int]] = []
    for _ in range(n_phish):
        dataset.append((_make_phish_email(), 1))
    for _ in range(n_legit):
        dataset.append((_make_legit_email(), 0))
    random.shuffle(dataset)
    return dataset


if __name__ == "__main__":
    ds = generate_dataset(5, 5)
    for email_str, label in ds[:3]:
        print(f"LABEL: {'PHISH' if label else 'LEGIT'}")
        print(email_str[:300])
        print("─" * 50)