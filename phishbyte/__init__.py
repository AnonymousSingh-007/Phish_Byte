"""
Phish_Byte — Cascading Email Phishing Detection
F1 0.948 · 12,545 parameters · trained from scratch

Quick start:
    from phishbyte import PhishByteEngine

    engine  = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")
    verdict = engine.analyze(raw_email_string)
    print(verdict)
"""

from phishbyte.engine    import PhishByteEngine
from phishbyte.verdict   import PhishVerdict
from phishbyte.model.mlp import PhishByteMLPLayer

__version__ = "1.0.0"
__all__     = ["PhishByteEngine", "PhishVerdict", "PhishByteMLPLayer"]