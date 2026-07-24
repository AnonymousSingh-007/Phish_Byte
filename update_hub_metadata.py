"""
update_hub_metadata.py — v7
Updates HuggingFace model card with v7 benchmarks, 85 features, 254K params.
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

**F1 0.950** on 5,000 held-out samples from a 6-corpus benchmark.
**254K parameters** (≈260× smaller than DistilBERT).
**995 emails/sec** on a laptop GPU.
**85 engineered features** (35 rule-based + 50 TF-IDF learned from corpus).
Every verdict explains itself with full per-feature attribution.

> **The only non-transformer phishing detection model on HuggingFace.**

## Quick start

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

## Analyse a real email from Gmail

1. Open the email in Gmail
2. Click ⋮ → **Show original**
3. Copy all (Ctrl+A, Ctrl+C)

```python
engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(pasted_raw_email)
print(verdict)
```

Or save as `.eml` and run:

```bash
python cli.py --file suspicious.eml
```

## What changed in v7

- **85 features** (was 29) — added 50 TF-IDF unigrams + 3 BDI features + 2 domain features + 1 composite
- **254K parameters** (was 12K) — deeper residual MLP with two ResBlocks and input skip connection
- **6-dataset training** (was CEAS-2008 only) — Enron, SpamAssassin, Ling-Spam, Nazario, Nigerian Fraud
- **TF-IDF vocabulary** — 50 most discriminative unigrams learned from training corpus. No pretrained LM.
- **Body Domain Identification** — most common link domain mismatch, form action mismatch, external link ratio
- **Display name spoofing** — catches "PayPal Security" \\<attacker@evil.com\\>
- **Calibrated training metrics** — F1 at Youden-optimal threshold, not naive 0.5 cutoff

## Architecture

```
raw email
  → Layer 1 (6 rule scorers, ~1ms) → veto gate (obvious phishing only)
  → Layer 2 (residual MLP, ~3ms)
      85 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1 (sigmoid)
      + input-to-output skip connection
  → PhishVerdict {label, probability, confidence, layer_used, feature_weights}
```

## Benchmarks (5,000 held-out, 6-corpus)

| Metric | Phish_Byte v7 | DistilBERT fine-tuned |
|--------|:------------:|:---------------------:|
| F1 score | **0.950** | ~0.967 |
| Accuracy | **94.94%** | ~97% |
| Parameters | **254K** | 66,000,000 |
| Model size | **~1 MB** | ~263 MB |
| Throughput (GPU) | **995/sec** | ~50/sec |
| GPU required | **No** | Practically yes |
| Header + SPF analysis | **Yes** | No |
| Per-feature attribution | **85 features** | Token-level SHAP |

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

CEAS-2008 + Enron + SpamAssassin + Ling-Spam + Nazario + Nigerian Fraud = **~83K emails** (balanced 50/50).

Same 6-corpus benchmark used by the top DistilBERT model on HuggingFace.

## Install

```bash
pip install huggingface_hub safetensors dnspython
```

## Limitations

- ~5% error rate. Use as one signal in defence-in-depth.
- Trained on English-language phishing (2003–2008 era). Modern attacks and non-English emails will degrade recall.
- SPF validation skipped for training (historical domains). Re-enables at inference on live emails.
- TF-IDF vocabulary is corpus-specific. Retrain on your own data for best domain fit.

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
    print(f"  PHISH_BYTE v7 — HUB MODEL CARD UPDATE")
    print(f"{'═'*56}")

    try:
        from huggingface_hub import HfApi, upload_file
        api = HfApi()
        whoami = api.whoami()
        print(f"  Logged in as: {whoami['name']}")
    except Exception as e:
        print(f"  [ERROR] Not logged in. Run: hf auth login")
        sys.exit(1)

    print(f"  Uploading v7 model card to {args.repo_id}...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(CARD)
        tmppath = f.name

    try:
        upload_file(
            path_or_fileobj=tmppath,
            path_in_repo="README.md",
            repo_id=args.repo_id,
            commit_message="Update model card — v7: 85 features, 254K params, F1 0.950, 6-dataset",
        )
        print(f"  Model card updated.")
    finally:
        os.unlink(tmppath)

    print(f"\n  What changed:")
    print(f"  + F1 updated to 0.950 (was 0.948)")
    print(f"  + Parameters updated to 254K (was 12K)")
    print(f"  + 85 features documented (was 29)")
    print(f"  + 6-dataset training documented")
    print(f"  + TF-IDF + BDI features explained")
    print(f"  + Gmail 'Show original' usage guide added")
    print(f"  + v7 changelog section added")
    print(f"  + 21 tags (was 19) — added tfidf, residual-network")
    print(f"  + 6 datasets listed in metadata")
    print(f"\n  View at: https://huggingface.co/{args.repo_id}")
    print(f"{'═'*56}\n")


if __name__ == "__main__":
    main()