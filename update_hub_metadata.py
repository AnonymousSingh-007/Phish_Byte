"""
update_hub_metadata.py
Private deployment script — stays local, never pushed to GitHub.
Updates the HuggingFace model card with full usage instructions.
"""
import os, sys, argparse, tempfile

CARD = '''---
language:
  - en
license: mit
library_name: phishbyte
pipeline_tag: text-classification
tags:
  - phishing-detection
  - email-security
  - cybersecurity
  - security
  - pytorch
  - from-scratch
  - no-pretrained-weights
  - cascading-inference
  - lightweight
  - explainable-ai
  - nlp
  - phishing
  - spam-detection
  - malware-detection
  - threat-detection
  - email-classification
  - text-classification
  - feature-engineering
  - interpretable-ml
  - tfidf
  - residual-network
datasets:
  - ceas-2008
  - enron-email
  - spamassassin
  - ling-spam
  - nazario-phishing
  - nigerian-fraud
metrics:
  - f1
  - precision
  - recall
  - accuracy
model-index:
  - name: phishbyte
    results:
      - task:
          type: text-classification
          name: Phishing Email Detection
        dataset:
          name: 6-corpus benchmark (CEAS, Enron, SpamAssassin, Ling-Spam, Nazario, Nigerian)
          type: ceas-2008
        metrics:
          - type: f1
            value: 0.9503
            name: F1 Score
          - type: accuracy
            value: 0.9494
            name: Accuracy
          - type: precision
            value: 0.9490
            name: Precision
          - type: recall
            value: 0.9516
            name: Recall
widget:
  - text: "From: PayPal Security <security@paypa1-alert.tk>\\nReply-To: attacker@evil-domain.ru\\nSubject: URGENT: Your account will be suspended\\n\\nDear Customer, your PayPal account has been suspended. Verify now at http://paypal-login.tk/verify"
    example_title: "Phishing email example"
  - text: "From: alice@company.com\\nReply-To: alice@company.com\\nSubject: Team lunch tomorrow\\n\\nHi everyone, lunch is at noon in the usual spot. See you there!"
    example_title: "Legitimate email example"
---

# Phish_Byte v7

A from-scratch PyTorch model for **email phishing detection** — no pretrained weights, no transformers, no fine-tuning.

**F1 0.950** · **254K parameters** (260× smaller than DistilBERT) · **995 emails/sec** on a laptop GPU · **85 engineered features** · every verdict explains itself.

---

## What makes this different

Every other phishing detection model on HuggingFace fine-tunes a transformer (DistilBERT, BERT, RoBERTa). Phish_Byte is the only one built from scratch:

| | Phish_Byte v7 | DistilBERT fine-tuned |
|---|:---:|:---:|
| F1 score | 0.950 | ~0.967 |
| Parameters | **254K** | 66,000,000 |
| Model size | **~1 MB** | ~263 MB |
| Throughput (GPU) | **995/sec** | ~50/sec |
| GPU required | **No** | Practically yes |
| Header + SPF analysis | **Yes** | No |
| Explainability | **85 features** | Token-level SHAP |
| Pretrained weights | **None** | DistilBERT |

The F1 gap is ~1.7 points. The size and throughput advantage is 260× and 20× respectively. The header analysis (SPF, display-name spoofing, most-common link domain) is unique to Phish_Byte.

---

## ⚠️ Install — read this first

**`pip install phishbyte` does not work.** There is no PyPI package yet (it is on the roadmap). The only working path is cloning the source repository.

### Step 1 — Clone

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte
```

### Step 2 — Create environment

```bash
python -m venv venv

# Windows:
.\\venv\\Scripts\\Activate.ps1

# Mac / Linux:
source venv/bin/activate
```

### Step 3 — Install dependencies

```bash
pip install -r requirements.txt
```

Minimal deps: `torch`, `huggingface_hub`, `safetensors`, `dnspython`, `numpy`, `pandas`.

For GPU acceleration (RTX 50-series / Blackwell):
```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

### Step 4 — Verify everything works

```bash
python verify_install.py
```

This checks every dependency and every source file, then does a live test-download from this Hub repo. **Run this before reporting any issue** — it tells you exactly what is missing.

Expected output (all green):
```
✅ Python 3.11.x
✅ torch
✅ huggingface_hub
✅ safetensors
✅ dns
✅ numpy
✅ pandas
✅ phishbyte/__init__.py
... (all source files)
✅ from phishbyte import PhishByteEngine — works
✅ Model loaded from Hub successfully
✅ INSTALLATION VERIFIED
```

---

## Usage

### Run from Python (inside the cloned folder)

```python
from phishbyte import PhishByteEngine

# Downloads ~1 MB of weights from this Hub repo on first call
# Cached locally after that — instant on every subsequent call
engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")

# Analyze any raw email string (headers + body)
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # "phishing" or "legitimate"
print(verdict.probability)       # P(phish) in [0.0, 1.0]
print(verdict.confidence)        # "high" / "medium" / "low"
print(verdict.layer_used)        # 1 = rules decided, 2 = MLP decided
print(verdict.feature_weights)   # dict of 85 feature scores
print(verdict)                   # formatted terminal display
```

### CLI

```bash
# Demo on a known phishing sample from training data
python cli.py --demo phish

# Demo on a known legitimate sample
python cli.py --demo legit

# Analyze a .eml file
python cli.py --file suspicious.eml

# Paste raw email interactively
python cli.py

# JSON output (for scripting)
python cli.py --demo --json
```

### Analyze a real email from Gmail

1. Open the email in Gmail
2. Click **⋮** → **Show original**
3. Select all (Ctrl+A), copy (Ctrl+C)
4. Run `python cli.py`, paste when prompted
5. Press Enter then **Ctrl+Z** (Windows) or **Ctrl+D** (Mac/Linux) to submit

### Understanding the verdict

```python
PhishVerdict(
    label           = "phishing",
    probability     = 0.9735,      # how confident the model is
    confidence      = "high",      # high ≥ 0.795, low ≤ 0.695, medium in-between
    layer_used      = 2,           # 1 = rules veto, 2 = MLP decision
    feature_weights = {
        # Which signals fired and how strongly
        "display_name_mismatch":    1.00,  # "PayPal" in name, attacker domain
        "mcld_mismatch":            1.00,  # most common link domain ≠ sender
        "spf_fail":                 1.00,  # SPF DNS check failed
        "tfidf_verify":             0.82,  # high TF-IDF score for "verify"
        "external_link_ratio":      0.90,  # 90% of links go to external domains
        "urgency_score":            0.65,  # urgency keywords in body
        ...
    },
    detail = "MLP probability: 97.35%. Layer 1 score: 19.76%.",
)
```

---

## Architecture

```
raw email
    │
    ▼
Layer 1 — 6 rule scorers (~1 ms)
  domain · URL+body · SPF · subject · BDI · TF-IDF
  → 85-dimensional feature vector
  → composite score ≥ 0.85? → fast PHISHING verdict (obvious cases)
    │
    ▼ (everything else — ~100% of real traffic)
Layer 2 — residual MLP (~3 ms)
  85 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1 (sigmoid)
  254K parameters · randomly initialized · trained from scratch
  + input-to-output skip connection
    │
    ▼
PhishVerdict
  { label · probability · confidence · layer_used · feature_weights }
```

The Layer 1 → Layer 2 routing is intentional: cheap signals handle the clear cases, the neural network handles the ambiguous ones. `layer_used` tells you which path ran for each email — useful for latency auditing and cost accounting at scale.

---

## Feature groups (85 total)

| Group | Count | What it captures |
|-------|:-----:|-----------------|
| Domain | 7 | From/Reply-To/Return-Path mismatch, freemail, brand impersonation, display name spoof, suspicious domain pattern |
| URL + Body | 10 | HTTPS ratio, anchor mismatch, suspicious TLD, urgency (normalized per 100 words), link density, caps ratio, digit ratio, special chars, avg word length, HTML/text ratio |
| SPF | 3 | SPF fail, no record, no sending IP |
| Subject | 7 | urgency, security theme, brand name, currency, all caps, fake RE prefix, fake transaction ID |
| BDI | 3 | Most common link domain mismatch, form action domain mismatch, external link ratio |
| TF-IDF | 50 | Top-50 discriminative unigrams learned from training corpus (no pretrained embeddings) |
| Composite | 5 | Per-module layer scores |

---

## Training data

| Dataset | Emails | Era |
|---------|-------:|-----|
| CEAS-2008 | 39,154 | 2008 |
| Enron | ~29K | 1999–2002 |
| SpamAssassin | ~10K | 2002–2003 |
| Nigerian Fraud | ~3.3K | 2000s |
| Nazario | ~1.5K | 2000s |
| Ling-Spam | ~2.8K | 1990s–2000s |
| **Total (after dedup)** | **~83K** | **balanced ~50/50** |

---

## Limitations — read before deploying

- **Training data is 15+ years old.** These corpora predate OAuth phishing, QR code lures, redirect chains through Google Docs / Dropbox / OneDrive, and modern adversarial HTML. Recall on 2020s-era attacks is untested and likely degraded.
- **TF-IDF vocabulary is era-locked.** Learned from 2000s corpora. Modern phishing vocabulary is not represented.
- **No adversarial robustness testing has been performed.** An attacker aware of the feature set could craft bypasses. Use as one signal in a defence-in-depth stack, not a standalone gate.
- **F1 0.950 is self-reported** on a held-out split of the training corpus, not independently verified.
- **English-language only.**

---

## Troubleshooting

Run `python verify_install.py` first — it catches nearly every issue below automatically.

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError: No module named 'phishbyte'` | Not in cloned folder or venv not activated |
| `ImportError: cannot import name 'X'` | `git pull origin main` |
| `pip install phishbyte` fails | No PyPI package yet — clone the repo |
| `NameError: save_model_as_safetensor` | `pip install safetensors` |
| Windows symlink warning | Harmless — ignore or enable Developer Mode |

---

## Roadmap

- [ ] Retrain on 2020–2024 phishing data (PhishTank, OpenPhish, APWG eCrime)
- [ ] Adversarial robustness test suite
- [ ] HuggingFace Space demo (zero-install browser trial)
- [ ] PyPI package (`pip install phishbyte`)
- [ ] arXiv preprint

## Citation

```bibtex
@software{phishbyte2026,
  author = {Singh, Samratth},
  title  = {Phish_Byte: Cascading from-scratch PyTorch phishing detection},
  year   = {2026},
  url    = {https://github.com/AnonymousSingh-007/Phish_Byte}
}
```

## License

MIT
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-id", required=True)
    args = parser.parse_args()

    print(f"\n{'═'*56}")
    print(f"  PHISH_BYTE — FINAL HUB MODEL CARD UPDATE")
    print(f"{'═'*56}")

    try:
        from huggingface_hub import HfApi, upload_file
        api = HfApi()
        whoami = api.whoami()
        print(f"  Logged in as: {whoami['name']}")
    except Exception:
        print(f"  [ERROR] Not logged in. Run: hf auth login")
        sys.exit(1)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(CARD)
        tmppath = f.name

    try:
        upload_file(
            path_or_fileobj=tmppath,
            path_in_repo="README.md",
            repo_id=args.repo_id,
            commit_message="Final model card: full install guide, usage, features, limitations, troubleshooting",
        )
        print(f"  Model card updated.")
    finally:
        os.unlink(tmppath)

    req = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if os.path.exists(req):
        upload_file(
            path_or_fileobj=req,
            path_in_repo="requirements.txt",
            repo_id=args.repo_id,
            commit_message="Add requirements.txt to Hub repo",
        )
        print(f"  requirements.txt uploaded.")

    print(f"\n  View at: https://huggingface.co/{args.repo_id}")
    print(f"{'═'*56}\n")


if __name__ == "__main__":
    main()