"""
Phish_Byte v2 — Cascading Email Phishing Analysis Engine
Built from scratch. No pretrained weights. No shortcuts.

Usage
-----
    from phishbyte.engine import PhishByteEngine

    engine  = PhishByteEngine()
    verdict = engine.analyze(raw_email_string)
    print(verdict)
"""

from phishbyte.engine  import PhishByteEngine
from phishbyte.verdict import PhishVerdict

__version__ = "2.0.0-dev"
__all__     = ["PhishByteEngine", "PhishVerdict"]