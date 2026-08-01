"""
fix_init_files.py
Writes the two __init__.py files directly to their correct locations.
Run this once from the repo root to fix missing/misnamed __init__.py files.

This exists because file-sharing tools can't deliver a file literally named
"__init__.py" without renaming it, which has caused repeated setup failures.

Usage:
    python fix_init_files.py
"""
import os

ROOT = os.path.dirname(os.path.abspath(__file__))

PHISHBYTE_INIT = '''"""
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
'''

MODEL_INIT = '''from phishbyte.model.mlp import PhishByteMLPLayer, build_feature_vector, INPUT_DIM, INPUT_DIM_STATIC

__all__ = ["PhishByteMLPLayer", "build_feature_vector", "INPUT_DIM", "INPUT_DIM_STATIC"]
'''

EXTRACTORS_INIT = '''from phishbyte.extractors.domain         import score_domain
from phishbyte.extractors.urls           import score_urls
from phishbyte.extractors.spf            import score_spf
from phishbyte.extractors.subject        import score_subject
from phishbyte.extractors.bdi            import score_bdi
from phishbyte.extractors.tfidf_features import TFIDFVocab

__all__ = ["score_domain","score_urls","score_spf",
           "score_subject","score_bdi","TFIDFVocab"]
'''

FILES = {
    "phishbyte/__init__.py":            PHISHBYTE_INIT,
    "phishbyte/model/__init__.py":      MODEL_INIT,
    "phishbyte/extractors/__init__.py": EXTRACTORS_INIT,
}


def main():
    print(f"\n{'═'*56}")
    print(f"  PHISH_BYTE — FIXING __init__.py FILES")
    print(f"{'═'*56}\n")

    for relpath, content in FILES.items():
        full = os.path.join(ROOT, relpath)
        os.makedirs(os.path.dirname(full), exist_ok=True)

        existed = os.path.exists(full)
        with open(full, "w", encoding="utf-8") as f:
            f.write(content)

        status = "overwritten" if existed else "created"
        print(f"  ✅ {relpath}  ({status})")

    print(f"\n  Done. Run: python verify_install.py")
    print(f"{'═'*56}\n")


if __name__ == "__main__":
    main()