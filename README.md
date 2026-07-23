<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=PHISH_BYTE;Cascading+phishing+detection;PyTorch+%C2%B7+53K+params+%C2%B7+No+pretrained+LM" alt="Phish_Byte" />

<br/>

[![Model on HuggingFace](https://img.shields.io/badge/🤗_Model-SamSec007%2Fphishbyte-FFD21E?style=for-the-badge)](https://huggingface.co/SamSec007/phishbyte)
![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![F1](https://img.shields.io/badge/F1_score-0.948-00FF88?style=flat-square)
![Accuracy](https://img.shields.io/badge/Accuracy-94.4%25-00FF88?style=flat-square)
![Throughput](https://img.shields.io/badge/Throughput-1,500+_emails%2Fsec-00FF88?style=flat-square)
![Parameters](https://img.shields.io/badge/Parameters-53K-blue?style=flat-square)
![Datasets](https://img.shields.io/badge/Training_data-6_datasets_%C2%B783K_emails-orange?style=flat-square)
![Stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=flat-square&color=yellow)
![Downloads](https://img.shields.io/badge/HuggingFace_downloads-63%2Fmo-00FF88?style=flat-square)

</div>

---

A PyTorch model for **email phishing detection** trained from scratch on 6 public phishing datasets.

**F1 0.948** on 2,000 held-out samples. **53K parameters** (≈1,200× smaller than DistilBERT). **1,500+ emails/sec** on a laptop GPU. Every verdict explains itself — which signals fired, which layer decided, how confident the model is.

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 2 — MLP made this call
print(verdict.feature_weights)   # per-feature attribution
```

---

## Why this exists

Every phishing detection model on HuggingFace is a fine-tuned transformer — DistilBERT, BERT, RoBERTa. They work well but come with costs: 65–110 million parameters, ~250 MB on disk, and GPU-dependent throughput. For organizations scanning millions of emails per day, that's a heavy tax on volume where most cases are decided by simple signals.

Phish_Byte takes a different architectural bet:

- **Custom MLP trained from scratch** — no pretrained weights, no fine-tuned LM
- **31 engineered features** covering domain, URL, SPF, subject, and character-level signals
- **Cascading inference** — cheap rule scorers handle obvious cases first, MLP handles the rest
- **Full email header analysis** including live SPF validation and display-name spoofing detection
- **Runs on CPU** — no GPU requirement for deployment
- **Every verdict explains itself** — 31-feature attribution on every prediction

**Phish_Byte is the only non-transformer phishing detection model on HuggingFace.**

---

## Benchmarks

Evaluated on a held-out slice of the 6-dataset training corpus (83K emails total, balanced ~50/50).

| Metric | Phish_Byte | DistilBERT fine-tuned\* | Rule-based only |
|--------|:----------:|:-----------------------:|:---------------:|
| F1 score | **0.948** | ~0.967 | ~0.85 |
| Parameters | **53K** | 66,000,000 | 0 |
| Model size on disk | **~200 KB** | ~263 MB | 0 |
| Throughput (GPU) | **1,527/sec** | ~50/sec | — |
| Throughput (CPU) | **~800/sec** | ~3/sec | — |
| GPU required | **No** | Practically yes | No |
| Header analysis | **Yes — SPF, display name** | No | Partial |
| Explainability | **31-feature attribution** | Token-level SHAP | — |

\* Baseline from `dima806/phishing-email-detection` and similar Hub models.

**The engineering trade-off:** Phish_Byte trades ~2 F1 points against DistilBERT for 30× throughput, a 1,200× smaller footprint, and no GPU requirement.

---

## Training data — 6 public datasets

| Dataset | Emails | Source |
|---------|-------:|--------|
| CEAS-2008 | 39,154 | CEAS Email Detection Challenge |
| Enron | ~29K | Enron email corpus (labeled) |
| SpamAssassin | ~10K | Apache SpamAssassin public corpus |
| Nigerian Fraud | ~3.3K | Nigerian fraud email dataset |
| Nazario | ~1.5K | Nazario phishing corpus |
| Ling-Spam | ~2.8K | Ling-Spam benchmark |
| **Total (after dedup)** | **~83K** | balanced 50/50 phish/legit |

---

## Architecture

```
   raw email
       │
       ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 1 — 4 rule scorers         ~1 ms per email         │
│  domain · URL · SPF · subject   → 31-feature vector      │
│                                                          │
│  composite score ≥ 0.85  ──────────►  fast phish verdict │
│  (obvious spoofing / TLD / header mismatch)              │
└───────────────────────────┬──────────────────────────────┘
                            │ everything else
                            ▼
┌──────────────────────────────────────────────────────────┐
│ Layer 2 — residual MLP        ~3 ms per email            │
│  31 → 192 → ResBlock(96) → 48 → 1   (sigmoid)           │
│  53K parameters · trained from scratch · no pretrained LM│
│  + post-hoc per-feature attribution on every verdict     │
└───────────────────────────┬──────────────────────────────┘
                            │
                            ▼
                    PhishVerdict
          { label · probability · confidence
            layer_used · feature_weights }
```

---

## Feature signals (31 inputs)

| Category | Features |
|----------|----------|
| **Domain** (7) | domain mismatch, Reply-To differs, Return-Path differs, freemail flag, brand impersonation, **display name mismatch**, **suspicious domain pattern** |
| **URL** (5) | HTTPS ratio, anchor text/href mismatch, suspicious TLD, urgency keywords (normalized), link density (normalized) |
| **SPF** (3) | SPF fail, no SPF record, no sending IP |
| **Subject** (7) | urgency, security theme, brand name, currency, all caps, fake `RE:` prefix, fake transaction IDs |
| **Character-level** (5) | caps ratio, digit ratio, special char density, avg word length, HTML/text ratio |
| **Composite scores** (4) | per-layer normalized scores |

Display name mismatch catches `"PayPal Security" <attacker@random.com>` — the most common spoofing pattern invisible to body-only models. Character-level features are vocabulary-agnostic, catching Nigerian prince scams from 2008 and modern PayPal phishing equally.

---

## Quickstart

### Load from HuggingFace Hub

```bash
pip install huggingface_hub safetensors dnspython
```

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)
print(verdict)
```

### Install from source

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte

py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1           # Windows
# source venv/bin/activate              # Linux / Mac

pip install -r requirements.txt
```

GPU (RTX 50-series / Blackwell):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

### CLI

```bash
python cli.py --demo phish          # known phishing sample from training data
python cli.py --demo legit          # known legitimate sample
python cli.py --file suspicious.eml # analyse a .eml file
python cli.py                       # paste raw email
python cli.py --demo --json         # JSON output
```

### Verdict object

```python
PhishVerdict(
    label           = "phishing",
    probability     = 0.9735,          # P(phish) in [0, 1]
    confidence      = "high",          # high | medium | low
    layer_used      = 2,               # 1 = rules, 2 = MLP
    feature_weights = {
        "spf_fail":                1.0,
        "display_name_mismatch":   1.0,
        "suspicious_domain_pattern": 0.75,
        "http_ratio":              1.0,
        ...
    },
    detail = "MLP probability: 97.35%. Layer 1 score: 19.76%.",
)
```

---

## Train your own

```bash
# 1. Get CEAS-2008 from Kaggle: naserabdullahalam/phishing-email-dataset
#    Place all CSVs in data/raw/

# 2. Build the combined 6-dataset corpus
python train/acquire_datasets.py --all

# 3. Train (2-6 minutes on GPU, fully cached after first run)
python train/train.py --data data/combined/phishbyte_v3_corpus.csv --skip-spf

# 4. Calibrate confidence gates from validation ROC
python train/calibrate_thresholds.py --data data/combined/phishbyte_v3_corpus.csv --n-val 5000

# 5. Evaluate
python eval.py --n 5000

# 6. Push to Hub
python push_to_hub.py --repo-id YOUR_HF_USERNAME/phishbyte
```

Feature extraction is cached — 83K emails extract in ~2 minutes first time, then instant.

---

## What this is not

- **Not a transformer.** No BERT, no fine-tuning, no pretrained weights. The MLP is randomly initialised and trained from scratch.
- **Not a spam filter.** Phish_Byte targets credential theft, impersonation, and account compromise — not promotional mail.
- **Not infallible.** F1 0.948 means ~5% of decisions are wrong. Use as one signal in defence-in-depth.
- **Not production-hardened.** No retry logic, rate limiting, or async SPF. Intended as a detection model, not a production email gateway.

---

## Repository layout

```
Phish_Byte/
├── phishbyte/
│   ├── engine.py              # cascading engine, Hub integration
│   ├── verdict.py             # PhishVerdict dataclass
│   ├── calibration.py         # ROC-based threshold learning
│   ├── extractors/
│   │   ├── domain.py          # domain + brand + display-name analysis
│   │   ├── urls.py            # URLs, anchors, body urgency, char-level
│   │   ├── spf.py             # SPF DNS validation
│   │   └── subject.py         # subject line patterns
│   └── model/
│       ├── mlp.py             # residual MLP, PyTorchModelHubMixin
│       └── weights/           # .gitignored — download from Hub
├── train/
│   ├── acquire_datasets.py    # 6-dataset acquisition + combine
│   ├── prepare_ceas.py        # Kaggle CSV → training CSV
│   ├── train.py               # training loop
│   └── calibrate_thresholds.py
├── cli.py                     # interactive CLI
├── eval.py                    # batch evaluation
├── push_to_hub.py             # one-command Hub deployment
├── update_hub_metadata.py     # update model card tags + metrics
└── requirements.txt
```

---

## Roadmap

- [x] Layer 1 rule scorers (4 modules, 31 features)
- [x] Residual MLP at Layer 2 (53K parameters, from scratch)
- [x] 6-dataset training corpus (83K emails, balanced)
- [x] ROC-based threshold calibration with Youden J sanity check
- [x] Verdict with 31-feature attribution
- [x] GPU support (CUDA 12.8 / Blackwell sm_120)
- [x] HuggingFace Hub publish
- [x] Batch evaluation script + CLI with real sample demo
- [ ] HuggingFace Space demo (try without installing)
- [ ] PyPI package — `pip install phishbyte`
- [ ] PyTorch Hub publish
- [ ] Full SHAP attribution (replace input-magnitude proxy)
- [ ] Temperature-scaled calibrated probabilities
- [ ] Layer 3 deep checks (WHOIS, redirect chains, ASN)
- [ ] Browser extension (Chrome/Firefox)
- [ ] URL-only detection mode

---

## Citation

```bibtex
@software{phishbyte2026,
  author  = {Singh, Samratth},
  title   = {Phish\_Byte: A cascading from-scratch PyTorch model for email phishing detection},
  year    = {2026},
  url     = {https://github.com/AnonymousSingh-007/Phish_Byte},
  note    = {HuggingFace: https://huggingface.co/SamSec007/phishbyte}
}
```


---

<div align="center">

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>