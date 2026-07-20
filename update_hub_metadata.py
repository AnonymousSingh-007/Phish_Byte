"""
update_hub_metadata.py
Updates the HuggingFace model card tags, metrics, and widget
to improve search discoverability without retraining anything.

Run this any time — takes ~30 seconds and can meaningfully boost
where the model appears in Hub search results.

Usage:
    python update_hub_metadata.py --repo-id SamSec007/phishbyte
"""

import os, sys, argparse, tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

EXPANDED_CARD = '''---
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
datasets:
  - ceas-2008
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
          name: CEAS-2008
          type: ceas-2008
        metrics:
          - type: f1
            value: 0.948
            name: F1 Score
          - type: accuracy
            value: 0.944
            name: Accuracy
          - type: precision
            value: 0.9537
            name: Precision
          - type: recall
            value: 0.9432
            name: Recall
widget:
  - text: "From: PayPal Security <security@paypa1-alert.tk>\\nReply-To: attacker@evil-domain.ru\\nSubject: URGENT: Your account will be suspended\\n\\nDear Customer, your PayPal account has been suspended. Verify now at http://paypal-login.tk/verify"
    example_title: "Phishing email example"
  - text: "From: alice@company.com\\nReply-To: alice@company.com\\nSubject: Team lunch tomorrow\\n\\nHi everyone, lunch is at noon tomorrow in the usual spot. See you there!"
    example_title: "Legitimate email example"
---

# Phish_Byte

A from-scratch PyTorch model for **email phishing detection**.
**F1 0.948** on CEAS-2008. **12,545 parameters** (≈9,000× smaller than DistilBERT).
**1,500+ emails/sec** on a laptop GPU. Every verdict explains itself.

> **v3 in progress:** expanding to 50K parameters + 6-dataset corpus training.

## Quick start

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 2
print(verdict.feature_weights)   # per-feature attribution
```

## Why this exists

Every phishing detection model on HuggingFace is a fine-tuned transformer —
DistilBERT, BERT, RoBERTa. 65–110M parameters. ~250 MB on disk. ~50 ms/email.

Phish_Byte is different:
- Custom MLP trained **from scratch** — no pretrained weights
- **29 engineered features** across domain, URL, SPF, subject, and character-level signals
- **Cascading inference** — cheap rules handle obvious cases, MLP handles the rest
- **Full email header analysis** including live SPF validation
- Runs on **CPU without a GPU**
- Every verdict includes **which signals fired and why**

## Benchmarks (CEAS-2008, n=2,000 held-out)

| Metric | Phish_Byte | DistilBERT fine-tuned |
|--------|:----------:|:---------------------:|
| F1 score | **0.948** | ~0.967 |
| Parameters | **12,545** | 66,000,000 |
| Model size | **52 KB** | ~250 MB |
| Throughput (GPU) | **1,527/sec** | ~50/sec |
| GPU required | **No** | Practically yes |
| Header analysis | **Yes (SPF, DKIM)** | No |
| Explainability | **29-feature attribution** | Token-level SHAP |

## Feature signals (29 inputs)

| Category | Features |
|----------|----------|
| Domain (5) | mismatch, Reply-To diff, Return-Path diff, freemail flag, brand impersonation |
| URL (5) | HTTPS ratio, anchor mismatch, suspicious TLD, urgency, link density |
| SPF (3) | fail, no record, no sending IP |
| Subject (7) | urgency, security theme, brand name, currency, all-caps, fake RE, fake transaction ID |
| Character-level (5) | caps ratio, digit ratio, special density, word length, HTML ratio |
| Composite (4) | per-layer normalized scores |

## Architecture

```
raw email
  → Layer 1 (rule scorers, ~1ms) → confidence gate
  → Layer 2 (custom MLP, ~3ms) → PhishVerdict
    {label, probability, confidence, layer_used, feature_weights}
```

## Install

```bash
pip install huggingface_hub safetensors dnspython
```

```python
from phishbyte import PhishByteEngine
engine = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)
```

## Limitations

- ~5% error rate (F1 0.948). Use as one signal in defence-in-depth.
- Trained on CEAS-2008 (English, 2008-era phishing). Modern attack patterns may reduce recall.
- SPF validation skipped during training on historical data — re-enables at inference time.

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
    parser.add_argument("--repo-id", required=True,
                        help='HuggingFace repo e.g. "SamSec007/phishbyte"')
    args = parser.parse_args()

    print(f"\n{'═'*56}")
    print(f"  PHISH_BYTE — HUB METADATA UPDATE")
    print(f"{'═'*56}")

    try:
        from huggingface_hub import HfApi, upload_file
        api = HfApi()
        whoami = api.whoami()
        print(f"  Logged in as: {whoami['name']}")
    except Exception as e:
        print(f"\n  [ERROR] Not logged in. Run: hf auth login")
        sys.exit(1)

    print(f"\n  Uploading expanded model card to {args.repo_id}...")
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(EXPANDED_CARD)
        tmppath = f.name

    try:
        upload_file(
            path_or_fileobj=tmppath,
            path_in_repo="README.md",
            repo_id=args.repo_id,
            commit_message="Expand tags, add widget examples, add metrics block",
        )
        print(f"  Model card updated.")
    finally:
        os.unlink(tmppath)

    print(f"\n  What changed:")
    print(f"  + 19 tags (was ~5) — more Hub search surfaces")
    print(f"  + Metrics block — F1, accuracy, precision, recall in sidebar")
    print(f"  + Widget examples — people can try it from the model page")
    print(f"  + Benchmark table vs DistilBERT")
    print(f"\n  View at: https://huggingface.co/{args.repo_id}")
    print(f"{'═'*56}\n")


if __name__ == "__main__":
    main()