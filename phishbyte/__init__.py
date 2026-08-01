"""
Phish_Byte — Cascading Email Phishing Detection
v7: 85 features (35 rule + 50 TF-IDF), 254K parameters, trained from scratch

Quick start:
    from phishbyte import PhishByteEngine

    engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
    verdict = engine.analyze(raw_email_string)
    print(verdict)
"""

from phishbyte.engine  import PhishByteEngine
from phishbyte.verdict import PhishVerdict

__version__ = "1.0.0"
__all__     = ["PhishByteEngine", "PhishVerdict"]
