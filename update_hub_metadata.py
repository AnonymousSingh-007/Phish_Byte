"""
update_hub_metadata.py — v8
Fixes the broken install instructions on the HuggingFace model card.
Makes explicit: no PyPI package yet, clone required.
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
    example_title: "Phishing email"
  - text: "From: alice@company.com\\nReply-To: alice@company.com\\nSubject: Team lunch tomorrow\\n\\nHi everyone, lunch is at noon tomorrow. See you there!"
    example_title: "Legitimate email"
---

# Phish_Byte v7

A from-scratch PyTorch model for **email phishing detection**.

**F1 0.950** on 5,000 held-out samples from a 6-corpus benchmark (self-reported — see Limitations).
**254K parameters** (≈260x smaller than DistilBERT).
**995 emails/sec** on a laptop GPU.
**85 engineered features** (35 rule-based + 50 TF-IDF learned from the training corpus).
Every verdict explains itself with full per-feature attribution.

> The only non-transformer phishing detection model on HuggingFace.

## ⚠️ Installation — no PyPI package yet

**This model is NOT installable via `pip install phishbyte`.** That package does not exist yet (it's on the roadmap). The only working install path today is cloning the source repository:

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte
python -m venv venv && source venv/bin/activate   # or .\\venv\\Scripts\\Activate.ps1 on Windows
pip install -r requirements.txt
python verify_install.py    # confirms everything works before you start
```

Then, from inside the cloned folder:

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # "phishing"
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # "high"
print(verdict.layer_used)        # 2
print(verdict.feature_weights)   # 85-feature attribution
```

`from_pretrained()` downloads ~1 MB of weights, thresholds, and the TF-IDF vocabulary from this Hub repo automatically — no manual file management needed once the package is set up.

## Analyse a real email from Gmail

1. Open the email → ⋮ menu → **Show original**
2. Copy all (Ctrl+A, Ctrl+C)
3. Paste into `python cli.py` when prompted, or save as `.eml` and run `python cli.py --file suspicious.eml`

## Architecture

```
raw email
  → Layer 1 (6 rule scorers, ~1ms) → veto gate (obvious phishing only)
  → Layer 2 (residual MLP, ~3ms)
      85 → 360 → 180 (x2 ResBlock) → 90 → 48 → 1 (sigmoid)
      + input-to-output skip connection
  → PhishVerdict {label, probability, confidence, layer_used, feature_weights}
```

## Benchmarks (5,000 held-out, self-reported on 6-corpus split)

| Metric | Phish_Byte v7 | DistilBERT fine-tuned |
|--------|:------------:|:---------------------:|
| F1 score | 0.950 | ~0.967 |
| Accuracy | 94.94% | ~97% |
| Parameters | 254K | 66,000,000 |
| Model size on disk | ~1 MB | ~263 MB |
| Throughput (GPU) | 995/sec | ~50/sec |
| GPU required | No | Practically yes |
| Header + SPF analysis | Yes | No |
| Per-feature attribution | 85 features | Token-level SHAP |

**Note on comparability:** the DistilBERT figure is self-reported by a different author on a different data split. This is not an apples-to-apples benchmark — treat both numbers as directional, not authoritative. A head-to-head evaluation on a shared held-out set is planned (see Roadmap).

## Feature groups (85 total)

| Group | Count | Examples |
|-------|:-----:|---------|
| Domain | 7 | mismatch, Reply-To diff, brand impersonation, display name spoof, suspicious pattern |
| URL + Body | 10 | HTTPS ratio, anchor mismatch, urgency (normalized), caps ratio, digit ratio |
| SPF | 3 | fail, no record, no IP |
| Subject | 7 | urgency, security theme, brand, currency, all caps, fake RE, fake txn ID |
| BDI | 3 | most common link domain mismatch, form action mismatch, external link ratio |
| TF-IDF | 50 | top-50 discriminative unigrams from training corpus |
| Composite | 5 | per-module layer scores |

## Training data

CEAS-2008 + Enron + SpamAssassin + Ling-Spam + Nazario + Nigerian Fraud = ~83K emails (balanced ~50/50).

**All source corpora are from 2003–2008.** This is a material limitation — see below.

## Limitations — read before deploying

- **Training data is 15+ years old.** The corpora (Enron, Nazario, SpamAssassin, etc.) predate modern phishing techniques: OAuth phishing, QR code lures, redirect chains through legitimate services (Google Docs, Dropbox, OneDrive), and adversarial HTML obfuscation. Recall on 2020s-era attacks is untested and likely degraded. Retraining on modern corpora (PhishTank, OpenPhish, APWG eCrime) is planned.
- **TF-IDF vocabulary is era-locked.** The 50 learned terms reflect 2003–2008 phishing language ("click here," "verify account"). Modern phishing vocabulary ("access your document," "complete verification") is not represented and won't be caught by this signal.
- **No adversarial robustness testing has been performed.** An attacker aware of the feature set (rule-based signals + fixed TF-IDF vocabulary) could plausibly craft inputs that evade detection — e.g., avoiding known TF-IDF terms, spoofing SPF-adjacent signals, or using benign-looking redirect infrastructure. This model has not been red-teamed. Treat it as one signal in a defence-in-depth stack, not a standalone gate.
- **F1 0.950 is self-reported** on a held-out split of the training corpus, not an independently verified benchmark. Numbers should be treated as directional.
- **Not production-hardened.** No retry logic, rate limiting, or async SPF handling.
- **English-language only.**

## Install

```bash
pip install -r requirements.txt
```

Minimal deps: `torch`, `huggingface_hub`, `safetensors`, `dnspython`, `numpy`, `pandas`.

## Citation

No peer-reviewed paper exists yet for this model — an arXiv preprint is planned. Until then, cite the repository directly:

```bibtex
@software{phishbyte2026,
  author = {Singh, Samratth},
  title  = {Phish_Byte: Cascading from-scratch PyTorch phishing detection},
  year   = {2026},
  url    = {https://github.com/AnonymousSingh-007/Phish_Byte}
}
```

## Roadmap

- [ ] Retrain on 2020–2024 phishing data (PhishTank, OpenPhish, APWG eCrime)
- [ ] Adversarial robustness test suite + documented known bypasses
- [ ] Head-to-head benchmark vs DistilBERT on a shared held-out set
- [ ] HuggingFace Space demo
- [ ] PyPI package (`pip install phishbyte`)
- [ ] arXiv preprint

## License

MIT
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-id", required=True)
    args = parser.parse_args()

    print(f"\n{'═'*56}")
    print(f"  PHISH_BYTE — HUB MODEL CARD FIX (install + honesty pass)")
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
            path_or_fileobj=tmppath, path_in_repo="README.md", repo_id=args.repo_id,
            commit_message="Fix broken install instructions, add honest limitations section",
        )
        print(f"  Model card updated.")
    finally:
        os.unlink(tmppath)

    # Also push requirements.txt to the Hub repo itself
    req_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "requirements.txt")
    if os.path.exists(req_path):
        upload_file(
            path_or_fileobj=req_path, path_in_repo="requirements.txt", repo_id=args.repo_id,
            commit_message="Add requirements.txt to Hub repo",
        )
        print(f"  requirements.txt uploaded to Hub repo.")

    print(f"\n  Fixed:")
    print(f"  - Removed implied 'pip install phishbyte' — now explicit clone instructions")
    print(f"  - Added verify_install.py reference")
    print(f"  - Added honest limitations: data age, TF-IDF staleness, no adversarial testing")
    print(f"  - Flagged F1 as self-reported, benchmark as non-comparable")
    print(f"  - Citation now says 'no paper yet' instead of implying one exists")
    print(f"  - Roadmap added directly to card")
    print(f"\n  View at: https://huggingface.co/{args.repo_id}")
    print(f"{'═'*56}\n")


if __name__ == "__main__":
    main()