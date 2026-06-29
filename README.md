<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=PHISH_BYTE;Cascading+phishing+detection;PyTorch+%C2%B7+12K+params+%C2%B7+F1+0.948" alt="Phish_Byte" />

<br/>

[![Model on HuggingFace](https://img.shields.io/badge/🤗_Model-HuggingFace_Hub-FFD21E?style=for-the-badge)](https://huggingface.co/AnonymousSingh-007/phishbyte)
![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![F1](https://img.shields.io/badge/F1_score-0.948-00FF88?style=flat-square)
![Accuracy](https://img.shields.io/badge/Accuracy-94.4%25-00FF88?style=flat-square)
![Throughput](https://img.shields.io/badge/Throughput-1,500+_emails%2Fsec-00FF88?style=flat-square)
![Parameters](https://img.shields.io/badge/Parameters-12,545-blue?style=flat-square)
![Stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=flat-square&color=yellow)

</div>

---

A PyTorch model for **email phishing detection** built from scratch on the CEAS-2008 corpus.

**F1 0.948** on 2,000 held-out samples. **12,545 parameters** (≈9,000× smaller than DistilBERT). **1,500+ emails/sec** on a laptop GPU. Every verdict explains itself — which signals fired, which layer decided, how confident the model is.

```python
from phishbyte import PhishByteEngine

# Pull from HuggingFace Hub (one line install)
engine  = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 2 — MLP made this call
print(verdict.feature_weights)   # {'spf_fail': 1.0, 'special_density': 1.0, ...}
```

---

## Why this exists

Every phishing detection model on HuggingFace today is a fine-tuned transformer — DistilBERT, BERT, RoBERTa. They work well but are heavyweight: 65–110 million parameters, ~250 MB on disk, ~50 ms per email on GPU. For organizations processing millions of messages per day, that's expensive compute on email volume where most cases are decided by simple rules.

Phish_Byte takes a different bet. Build a small custom MLP from scratch (no pretrained weights, no transformers), feed it 29 carefully chosen features extracted by lightweight rule scorers, and route inference through a cascade so cheap signals handle the obvious cases. The result is a model 9,000× smaller than DistilBERT that performs competitively, deploys without a GPU, and explains every decision.

**Phish_Byte is the first non-transformer phishing detection model on HuggingFace.**

---

## Quickstart

### Install from HuggingFace Hub (recommended)

```bash
pip install phishbyte huggingface_hub
```

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")
verdict = engine.analyze(raw_email_string)
print(verdict)
```

### Install from source

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte

py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate          # Linux / Mac

pip install -r requirements.txt
```

For GPU acceleration on RTX 50-series (Blackwell):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

---

## Benchmarks

Evaluated on a held-out 2,000-sample slice of CEAS-2008 (39,154 labelled emails total, 55.8% phishing). SPF disabled for historical-dataset training; re-enables at inference time on fresh emails.

| Metric | Phish_Byte | DistilBERT (fine-tuned)\* | Rule-based baseline |
|--------|-----------:|--------------------------:|---------------------:|
| Accuracy | **94.40%** | ~97% | ~85% |
| Precision | **0.9537** | ~0.97 | ~0.88 |
| Recall | **0.9432** | ~0.97 | ~0.82 |
| F1 score | **0.948** | ~0.97 | ~0.85 |
| Parameters | **12,545** | 66,000,000 | 0 |
| Model size on disk | **~50 KB** | ~263 MB | 0 |
| Throughput (laptop GPU) | **1,527 emails/sec** | ~50 emails/sec | n/a |
| Throughput (laptop CPU) | **~800 emails/sec** | ~3 emails/sec | n/a |
| GPU required? | **No** | Practically yes | No |

\* DistilBERT numbers are reported by `dima806/phishing-email-detection` on HuggingFace and similar baselines in the literature.

**The trade-off in one line:** Phish_Byte gives up ~2 F1 points against DistilBERT and gains 30× throughput, 5,000× smaller model size, and no GPU requirement.

---

## Architecture

```
   raw email
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 1 — rule scorers          ~1 ms per email          │
│   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│   │ domain   │  │   URL    │  │   SPF    │  │ subject │ │
│   │ + brand  │  │ + body   │  │   DNS    │  │ patterns│ │
│   │ checks   │  │ + chars  │  │  lookup  │  │         │ │
│   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬────┘ │
│        └──────────────┴──────────────┴────────────┘      │
│                       │                                   │
│              composite score  ≥ 0.85                      │
│                       │      ────────► fast phish verdict │
│                       │                                   │
│                       ▼ otherwise                         │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 2 — MLP (29 → 96 → 48 → 1)   ~3 ms per email       │
│                                                          │
│   12,545 parameters · trained from scratch · sigmoid     │
│   + post-hoc per-feature attribution                     │
└───────────────────────┬──────────────────────────────────┘
                        │
                        ▼
                  PhishVerdict
        ┌──────────────────────────────────────┐
        │ label · probability · confidence     │
        │ layer_used · feature_weights         │
        └──────────────────────────────────────┘
```

Layer 1 acts as a fast veto for obvious phishing only. Almost everything else routes through the MLP, which has learned a much sharper decision boundary than the handcrafted rules can express (Youden J = 0.89 for Layer 2 vs 0.10 for Layer 1 on CEAS-2008).

---

## Feature signals (29 total)

| Category | Features |
|----------|----------|
| **Domain** (5) | domain mismatch, Reply-To differs, Return-Path differs, freemail flag, brand impersonation |
| **URL** (5) | HTTPS ratio, anchor text/href mismatch, suspicious TLD, urgency keywords, link density |
| **SPF** (3) | SPF fail, no SPF record, no sending IP |
| **Subject** (7) | urgency words, security theme, brand name, currency mentions, all caps, fake `RE:` prefix, fake transaction IDs |
| **Character-level** (5) | caps ratio, digit ratio, special char density, avg word length, HTML-to-text ratio |
| **Composite scores** (4) | per-layer normalized scores fed back as features |

Character-level features are vocabulary-agnostic — they catch Nigerian-prince scams from 2008 and modern PayPal phishing equally well, without keyword lists.

---

## Usage

### Python API

```python
from phishbyte import PhishByteEngine

# Load pretrained model (from HuggingFace Hub)
engine = PhishByteEngine.from_pretrained("AnonymousSingh-007/phishbyte")

# Or load from local weights after training your own
engine = PhishByteEngine()

# Analyse a raw email (with headers)
with open("suspicious.eml") as f:
    verdict = engine.analyze(f.read())

if verdict.label == "phishing" and verdict.confidence == "high":
    quarantine(email)
```

### CLI

```bash
python cli.py --demo phish          # try a known phishing sample from CEAS-2008
python cli.py --demo legit          # try a known legitimate sample
python cli.py --file suspicious.eml # analyse a .eml file
python cli.py                       # paste raw email, Ctrl+Z to submit
python cli.py --demo --json         # JSON output for scripting
```

### Verdict object

```python
PhishVerdict(
    label           = "phishing",                # "phishing" | "legitimate"
    probability     = 0.9735,                    # P(phish) in [0, 1]
    confidence      = "high",                    # "high" | "medium" | "low"
    layer_used      = 2,                         # 1 | 2 | 3
    feature_weights = {                          # which signals fired
        "spf_fail":         1.0,
        "special_density":  1.0,
        "caps_ratio":       0.59,
        ...
    },
    detail          = "MLP probability: 97.35%. Layer 1 score: 19.76%.",
)
```

---

## Training your own

```bash
python train/prepare_ceas.py                                              # convert Kaggle CSV → training CSV
python train/train.py --data data/ceas2008_phishbyte.csv --skip-spf       # train MLP (~2 minutes on GPU)
python train/calibrate_thresholds.py --data data/ceas2008_phishbyte.csv   # learn confidence gates
python eval.py --n 2000                                                   # batch evaluation
python push_to_hub.py --repo-id YOUR_HF_USERNAME/phishbyte                # publish to Hub
```

First-time feature extraction takes ~30 seconds on 39K emails. Cached after that.

Dataset: [CEAS 2008 via Kaggle](https://www.kaggle.com/datasets/naserabdullahalam/phishing-email-dataset). Not included in repo — download separately.

---

## What this is not

- **Not a transformer.** No BERT, no fine-tuning, no pretrained weights of any kind. The MLP is randomly initialised and trained from scratch.
- **Not a spam filter.** Phish_Byte targets credential theft, impersonation, and account compromise — not promotional bulk mail.
- **Not infallible.** F1 of 0.948 means ~5% of decisions are wrong. Novel attack patterns and adversarial emails crafted to game these specific features will get through. Use as one signal in defence-in-depth, not the only gate.
- **Not a research paper.** This is a deployable model with measurable engineering trade-offs — small size, low latency, no GPU requirement, full explainability.

---

## Repository layout

```
Phish_Byte/
├── phishbyte/
│   ├── engine.py            # cascading engine, threshold gates, Hub integration
│   ├── verdict.py           # PhishVerdict dataclass
│   ├── calibration.py       # ROC-based threshold learning
│   ├── extractors/
│   │   ├── domain.py        # domain consistency + brand impersonation
│   │   ├── urls.py          # URLs, anchors, body urgency, char-level
│   │   ├── spf.py           # SPF DNS validation (live or skipped)
│   │   └── subject.py       # subject line patterns
│   └── model/
│       ├── mlp.py           # PyTorch MLP w/ PyTorchModelHubMixin
│       └── weights/         # trained weights + thresholds.json
├── train/
│   ├── prepare_ceas.py
│   ├── train.py
│   └── calibrate_thresholds.py
├── cli.py                   # interactive command-line interface
├── eval.py                  # batch evaluation
├── push_to_hub.py           # one-command HuggingFace deployment
└── requirements.txt
```

---

## Roadmap

- [x] Layer 1 rule scorers (4 modules, 20 sub-features)
- [x] PyTorch MLP at Layer 2 (29 inputs, 12K parameters)
- [x] ROC-based threshold calibration with Youden J sanity check
- [x] Verdict object with per-feature attribution
- [x] GPU support (CUDA 12.8 / Blackwell)
- [x] CEAS-2008 training + benchmark table
- [x] CLI with real-sample demo mode + batch evaluation
- [x] **HuggingFace Hub publish (`PyTorchModelHubMixin`)**
- [ ] PyTorch Hub publish
- [ ] Layer 3 deep structural checks (redirect chains, WHOIS, ASN)
- [ ] Temperature-scaled calibrated probabilities
- [ ] Browser extension wrapper
- [ ] Multilingual phishing support
- [ ] PyPI package release

---

## Citation

```bibtex
@software{phishbyte2026,
  author  = {Singh, Samratth},
  title   = {Phish_Byte: A cascading from-scratch PyTorch model for email phishing detection},
  year    = {2026},
  url     = {https://github.com/AnonymousSingh-007/Phish_Byte},
  note    = {HuggingFace: https://huggingface.co/AnonymousSingh-007/phishbyte}
}
```

---

## License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>