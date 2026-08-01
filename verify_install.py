"""
verify_install.py
Run this FIRST after cloning/installing Phish_Byte.
Checks every dependency and every required file exists before you
waste time debugging a broken import chain.

Usage:
    python verify_install.py
"""
import sys, os, importlib

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

PASS, FAIL, WARN = "✅", "❌", "⚠️ "

def check_package(name, pip_name=None, required=True):
    pip_name = pip_name or name
    try:
        importlib.import_module(name)
        print(f"  {PASS} {name}")
        return True
    except ImportError:
        marker = FAIL if required else WARN
        tag = "REQUIRED" if required else "optional"
        print(f"  {marker} {name}  ({tag}) — run: pip install {pip_name}")
        return not required

def check_file(path, required=True):
    full = os.path.join(ROOT, path)
    exists = os.path.exists(full)
    marker = PASS if exists else (FAIL if required else WARN)
    print(f"  {marker} {path}")
    return exists or not required


def main():
    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE — INSTALLATION VERIFIER")
    print(f"{'═'*60}\n")

    ok = True

    print("Python version:")
    v = sys.version_info
    if v.major == 3 and v.minor >= 10:
        print(f"  {PASS} Python {v.major}.{v.minor}.{v.micro}")
    else:
        print(f"  {FAIL} Python {v.major}.{v.minor}.{v.micro} — need 3.10+")
        ok = False

    print("\nRequired packages:")
    ok &= check_package("torch")
    ok &= check_package("huggingface_hub")
    ok &= check_package("safetensors")
    ok &= check_package("dns", "dnspython")
    ok &= check_package("numpy")

    print("\nOptional packages (needed for --demo and training only):")
    check_package("pandas", required=False)
    check_package("shap", required=False)

    print("\nCore source files:")
    ok &= check_file("phishbyte/__init__.py")
    ok &= check_file("phishbyte/engine.py")
    ok &= check_file("phishbyte/verdict.py")
    ok &= check_file("phishbyte/calibration.py")
    ok &= check_file("phishbyte/model/__init__.py")
    ok &= check_file("phishbyte/model/mlp.py")
    ok &= check_file("phishbyte/extractors/__init__.py")
    ok &= check_file("phishbyte/extractors/domain.py")
    ok &= check_file("phishbyte/extractors/urls.py")
    ok &= check_file("phishbyte/extractors/spf.py")
    ok &= check_file("phishbyte/extractors/subject.py")
    ok &= check_file("phishbyte/extractors/bdi.py")
    ok &= check_file("phishbyte/extractors/tfidf_features.py")

    print("\nLocal weights (optional — will auto-download from Hub if missing):")
    check_file("phishbyte/model/weights/phishbyte_mlp.pt", required=False)
    check_file("phishbyte/model/weights/thresholds.json", required=False)
    check_file("phishbyte/model/weights/tfidf_vocab.json", required=False)

    print(f"\n{'─'*60}")
    if not ok:
        print(f"  {FAIL} SETUP INCOMPLETE — fix the items marked {FAIL} above.")
        print(f"{'─'*60}\n")
        sys.exit(1)

    print(f"  All required files and packages present. Testing import...")
    try:
        from phishbyte import PhishByteEngine
        print(f"  {PASS} from phishbyte import PhishByteEngine — works")
    except Exception as e:
        print(f"  {FAIL} Import failed: {e}")
        print(f"{'─'*60}\n")
        sys.exit(1)

    print(f"\n  Testing model load from HuggingFace Hub...")
    try:
        engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
        print(f"  {PASS} Model loaded from Hub successfully")
    except Exception as e:
        print(f"  {WARN} Hub load failed (check internet connection): {e}")
        print(f"  You can still use a locally trained model instead.")

    print(f"\n{'═'*60}")
    print(f"  {PASS} INSTALLATION VERIFIED — you're ready to go.")
    print(f"{'═'*60}")
    print(f"\n  Try it:")
    print(f'  python -c "from phishbyte import PhishByteEngine; e = PhishByteEngine.from_pretrained(\'SamSec007/phishbyte\'); print(e.analyze(open(\'test.eml\').read()))"')
    print(f"  python cli.py --demo phish")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()