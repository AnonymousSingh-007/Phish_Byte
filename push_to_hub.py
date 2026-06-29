"""
push_to_hub.py
Push trained Phish_Byte model to HuggingFace Hub.

Setup (one-time):
    pip install huggingface_hub
    hf auth login              # paste your token from https://huggingface.co/settings/tokens

Run:
    python push_to_hub.py --repo-id AnonymousSingh-007/phishbyte
    python push_to_hub.py --repo-id AnonymousSingh-007/phishbyte --private
"""

import os, sys, argparse, json
from pathlib import Path

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)

from phishbyte.engine import PhishByteEngine


MODEL_CARD = """---
language: en
license: mit
library_name: phishbyte
pipeline_tag: text-classification
tags:
  - phishing-detection
  - email-security
  - pytorch
  - from-scratch
  - no-pretrained-weights
  - cascading-inference
  - lightweight
  - explainable-ai
datasets:
  - CEAS-2008
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
          - type: accuracy
            value: 0.944
          - type: precision
            value: 0.954
          - type: recall
            value: 0.943
---

# Phish_Byte

A from-scratch PyTorch model for **email phishing detection**.
**F1 0.948** on CEAS-2008. **12,545 parameters** (≈9,000× smaller than DistilBERT).
**1,500+ emails/sec** on a laptop GPU. Every verdict explains itself.

## Why this exists

Every phishing detection model on HuggingFace is currently a fine-tuned
transformer (DistilBERT, BERT, RoBERTa) — 65 to 110 million parameters,
~250 MB on disk, ~50 ms per email on GPU. Phish_Byte takes a different
bet: a small custom MLP trained from scratch, fed by 29 carefully chosen
features, routed through a cascading inference pipeline. The model is
**9,000× smaller** than DistilBERT, performs competitively, deploys
without a GPU, and explains every decision.

## Usage

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 2 — MLP made this call
print(verdict.feature_weights)   # full per-feature attribution
```

## Architecture

```
Layer 1 — rule scorers (~1 ms): domain + URL + SPF + subject
            │
            ├──► obvious phishing? short-circuit verdict
            │
            └──► otherwise route to MLP
                       │
Layer 2 — MLP (~3 ms): 29 → 96 → 48 → 1 (sigmoid)
            │
            ▼
        PhishVerdict {label, probability, confidence, layer_used, feature_weights}
```

## Performance (CEAS-2008, n=2000 held-out)

| Metric           | Value     |
|------------------|----------:|
| F1 score         | **0.948** |
| Accuracy         | 94.40%    |
| Precision        | 0.9537    |
| Recall           | 0.9432    |
| Parameters       | 12,545    |
| Model size       | ~50 KB    |
| Throughput (GPU) | 1,527 /s  |
| Throughput (CPU) | ~800 /s   |

## Features (29 inputs)

- **Domain (5)**: From/Reply-To/Return-Path mismatch, freemail flag, brand impersonation
- **URL (5)**: HTTPS ratio, anchor mismatch, suspicious TLD, urgency, link density
- **SPF (3)**: SPF fail, no record, no sending IP
- **Subject (7)**: urgency, security theme, brand name, currency, all caps, fake RE, fake transaction ID
- **Character-level (5)**: caps ratio, digit ratio, special chars, avg word length, HTML/text ratio
- **Composite (4)**: per-layer normalized scores

## Limitations

- ~5% of decisions are wrong (F1 0.948, not 1.0). Use as one signal in defence-in-depth, not the only gate.
- Trained on CEAS-2008 — English-language phishing from 2008. Modern attack patterns and non-English emails will degrade performance.
- SPF validation is bypassed for training (historical domains don't resolve) but runs live at inference time.
- Adversarial emails crafted specifically to game these features will get through.

## Citation

```bibtex
@software{phishbyte2026,
  author  = {Singh, Samratth},
  title   = {Phish_Byte: A cascading from-scratch PyTorch model for email phishing detection},
  year    = {2026},
  url     = {https://github.com/AnonymousSingh-007/Phish_Byte}
}
```

## License

MIT
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-id", required=True,
                        help='HuggingFace repo, e.g. "AnonymousSingh-007/phishbyte"')
    parser.add_argument("--private", action="store_true",
                        help="Create as private repo.")
    parser.add_argument("--commit-message", type=str,
                        default="Upload Phish_Byte v1.0")
    args = parser.parse_args()

    print(f"\n{'═'*60}")
    print(f"  PHISH_BYTE — PUSH TO HUGGINGFACE HUB")
    print(f"{'═'*60}")
    print(f"  Repo : {args.repo_id}")
    print(f"  Privacy : {'private' if args.private else 'public'}")
    print()

    try:
        from huggingface_hub import HfApi
        api = HfApi()
        whoami = api.whoami()
        print(f"  Logged in as: {whoami['name']}")
    except Exception as e:
        print(f"\n  [ERROR] Not logged in to HuggingFace.")
        print(f"  Run: hf auth login")
        print(f"  Then paste a token from https://huggingface.co/settings/tokens")
        print(f"  Need write access. Error: {e}")
        sys.exit(1)

    print(f"\n  Loading engine from local weights...")
    engine = PhishByteEngine()
    if not engine._model_loaded:
        print(f"\n  [ERROR] No trained weights found locally.")
        print(f"  Run training first: python train/train.py --data data/ceas2008_phishbyte.csv --skip-spf")
        sys.exit(1)

    try:
        api.create_repo(
            repo_id=args.repo_id,
            private=args.private,
            exist_ok=True,
        )
        print(f"  Repo ready: https://huggingface.co/{args.repo_id}")
    except Exception as e:
        print(f"  Repo creation: {e}")

    print(f"\n  Pushing weights + thresholds...")
    engine.push_to_hub(args.repo_id)

    print(f"\n  Uploading model card...")
    from huggingface_hub import upload_file
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".md", delete=False, encoding="utf-8") as f:
        f.write(MODEL_CARD)
        tmppath = f.name
    upload_file(
        path_or_fileobj=tmppath,
        path_in_repo="README.md",
        repo_id=args.repo_id,
        commit_message="Upload model card",
    )
    os.unlink(tmppath)
    print(f"  Model card uploaded.")

    print(f"\n{'═'*60}")
    print(f"  DEPLOYED")
    print(f"{'═'*60}")
    print(f"  View at: https://huggingface.co/{args.repo_id}")
    print(f"\n  Test install:")
    print(f"  >>> from phishbyte import PhishByteEngine")
    print(f"  >>> engine = PhishByteEngine.from_pretrained('{args.repo_id}')")
    print(f"  >>> verdict = engine.analyze(raw_email)")
    print(f"{'═'*60}\n")


if __name__ == "__main__":
    main()