<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=PHISH_BYTE+v7;85+features+%C2%B7+254K+params+%C2%B7+F1+0.950;No+pretrained+LM+%C2%B7+No+transformers" alt="Phish_Byte" />

<br/>

[![Model on HuggingFace](https://img.shields.io/badge/🤗_Model-SamSec007%2Fphishbyte-FFD21E?style=for-the-badge)](https://huggingface.co/SamSec007/phishbyte)
![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![F1](https://img.shields.io/badge/F1_score-0.950-00FF88?style=flat-square)
![Accuracy](https://img.shields.io/badge/Accuracy-94.9%25-00FF88?style=flat-square)
![Throughput](https://img.shields.io/badge/Throughput-995_emails%2Fsec-00FF88?style=flat-square)
![Parameters](https://img.shields.io/badge/Parameters-254K-blue?style=flat-square)
![Features](https://img.shields.io/badge/Features-85_(35_rule+50_TF--IDF)-orange?style=flat-square)
![Datasets](https://img.shields.io/badge/Training-6_datasets_%C2%B783K_emails-orange?style=flat-square)
![Stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=flat-square&color=yellow)

</div>

---

A PyTorch model for **email phishing detection** trained entirely from scratch on 6 public datasets.

**F1 0.950** on 5,000 held-out samples. **254K parameters** (≈260× smaller than DistilBERT). **995 emails/sec** on a laptop GPU. **85 engineered features** including TF-IDF vocabulary learned from the training corpus — no pretrained language model, no transformer, no fine-tuning.

Every verdict explains itself: which signals fired, which layer decided, how confident the model is.

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9735
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 2 — MLP made this call
print(verdict.feature_weights)   # 85-feature attribution
```

---

## What changed in v7

| | v2 (original) | v7 (current) |
|---|:---:|:---:|
| Features | 29 | **85** (35 rule + 50 TF-IDF) |
| Parameters | 12,545 | **253,987** |
| Architecture | 29→128→64→1 | **85→360→180(×2 ResBlock)→90→48→1** |
| Training data | CEAS-2008 only (39K) | **6 datasets (83K emails)** |
| F1 score | 0.948 | **0.950** |
| New extractors | — | **TF-IDF vocab, Body Domain ID** |
| Skip connections | None | **Input-to-output residual** |
| Training F1 metric | Naive 0.5 cutoff | **Youden-optimal threshold** |

Key additions in v7:
- **TF-IDF vocabulary** — 50 most discriminative unigrams learned from training corpus (no pretrained embeddings)
- **Body Domain Identification (BDI)** — most common link domain mismatch, form action domain mismatch, external link ratio (inspired by BDI 2025 paper achieving 99.7% with 3 features)
- **Display name spoofing** — catches `"PayPal Security" <attacker@evil.com>`
- **Suspicious domain pattern** — heuristic for auto-generated phishing domains
- **Two residual blocks** — deeper feature interaction learning at the 180-dim bottleneck
- **Calibrated training metrics** — F1 at Youden-optimal threshold during training, no more misleading numbers

---

## Why this exists

Every phishing detection model on HuggingFace is a fine-tuned transformer — DistilBERT, BERT, RoBERTa. They work well but come with costs: 65–110M parameters, ~250 MB on disk, GPU-dependent throughput. For organizations scanning millions of emails per day, that's expensive for volume where most cases trip simple signals.

Phish_Byte takes a different bet:

- **Custom MLP trained from scratch** — no pretrained weights, no fine-tuned LM
- **85 engineered features** covering domain, URL, SPF, subject, body, character-level, BDI, and learned TF-IDF signals
- **Cascading inference** — cheap rule scorers veto obvious cases, MLP handles the rest
- **Full email header analysis** including live SPF validation and display-name spoofing detection
- **Runs on CPU** — no GPU requirement for deployment
- **Every verdict explains itself** — 85-feature attribution on every prediction

**Phish_Byte is the only non-transformer phishing detection model on HuggingFace.**

---

## Benchmarks

Evaluated on 5,000 held-out samples from the 6-dataset corpus (83K emails total, balanced ~50/50).

| Metric | Phish_Byte v7 | DistilBERT fine-tuned\* | Rule-based only |
|--------|:------------:|:-----------------------:|:---------------:|
| F1 score | **0.950** | ~0.967 | ~0.85 |
| Accuracy | **94.94%** | ~97% | ~85% |
| Precision | **0.9490** | ~0.97 | ~0.88 |
| Recall | **0.9516** | ~0.97 | ~0.82 |
| Parameters | **254K** | 66,000,000 | 0 |
| Model size on disk | **~1 MB** | ~263 MB | 0 |
| Throughput (GPU) | **995/sec** | ~50/sec | — |
| GPU required | **No** | Practically yes | No |
| Header analysis | **Yes — SPF, display name, BDI** | No | Partial |
| Explainability | **85-feature attribution** | Token-level SHAP | — |

\* Baseline from `dima806/phishing-email-detection` and similar Hub models.

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
| **Total (after dedup)** | **~83K** | balanced ~50/50 phish/legit |

---

## Architecture

```
   raw email (.eml / raw headers+body / Gmail "Show Original")
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│ Layer 1 — 6 rule scorers                        ~1 ms per email │
│                                                                 │
│  domain    URL+body    SPF       subject     BDI      TF-IDF    │
│  (7 feat)  (10 feat)   (3 feat)  (7 feat)   (3 feat) (50 feat) │
│                                                                 │
│  composite score ≥ 0.85  ──────────►  fast phish verdict        │
│  (obvious spoofing / domain mismatch)                           │
└────────────────────────────┬────────────────────────────────────┘
                             │ everything else (~100% of traffic)
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ Layer 2 — residual MLP                          ~3 ms per email │
│                                                                 │
│  85 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1  (sigmoid)        │
│  + input-to-output skip connection                              │
│  254K parameters · trained from scratch · no pretrained LM      │
│  + post-hoc per-feature attribution on every verdict            │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                       PhishVerdict
            { label · probability · confidence
              layer_used · feature_weights }
```

---

## Feature signals (85 total)

| Category | Count | Features |
|----------|:-----:|----------|
| **Domain** | 7 | domain mismatch, Reply-To differs, Return-Path differs, freemail flag, brand impersonation, **display name mismatch**, **suspicious domain pattern** |
| **URL + Body** | 10 | HTTPS ratio, anchor mismatch, suspicious TLD, urgency keywords (normalized/100 words), link density (normalized/100 words), caps ratio, digit ratio, special char density, avg word length, HTML/text ratio |
| **SPF** | 3 | SPF fail, no SPF record, no sending IP |
| **Subject** | 7 | urgency, security theme, brand name, currency, all caps, fake `RE:` prefix, fake transaction IDs |
| **BDI** | 3 | **most common link domain mismatch**, **form action domain mismatch**, **external link ratio** |
| **TF-IDF** | 50 | **top-50 discriminative unigrams learned from training corpus** (no pretrained embeddings — vocabulary fitted on your data) |
| **Composite** | 5 | per-module normalized layer scores |

**Bold = new in v7.** Display name mismatch catches `"PayPal Security" <attacker@random.com>`. BDI features detect when the most common link domain in the email body doesn't match the claimed sender — the strongest structural signal for phishing (BDI paper: 99.7% accuracy with just 3 features). TF-IDF features are vocabulary-agnostic — they learn the 50 most discriminative words from whatever training corpus you provide. No pretrained model needed.

---

## Quickstart

### From HuggingFace Hub

```bash
pip install huggingface_hub safetensors dnspython
```

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)
print(verdict)
```

### From source

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

---

## Usage

### Analyse a live email from Gmail

1. Open any email in Gmail
2. Click ⋮ menu → **Show original**
3. Copy all text (Ctrl+A, Ctrl+C)
4. Run:

```bash
python cli.py
# Paste the raw email, press Enter, then Ctrl+Z (Windows)
```

Or save a `.eml` file:

```bash
python cli.py --file suspicious.eml
```

### Demo mode (from training data)

```bash
python cli.py --demo phish          # known phishing sample
python cli.py --demo legit          # known legitimate sample
python cli.py --demo --json         # JSON output
```

### Python API

```python
from phishbyte import PhishByteEngine

engine = PhishByteEngine()

with open("suspicious.eml") as f:
    verdict = engine.analyze(f.read())

if verdict.label == "phishing" and verdict.confidence == "high":
    quarantine(email)

# Inspect what fired
for feature, score in sorted(verdict.feature_weights.items(), key=lambda x: -x[1]):
    if score > 0.1:
        print(f"  {feature}: {score:.2f}")
```

### Verdict object

```python
PhishVerdict(
    label           = "phishing",
    probability     = 0.9735,          # P(phish) in [0, 1]
    confidence      = "high",          # high | medium | low
    layer_used      = 2,               # 1 = rules veto, 2 = MLP
    feature_weights = {
        "display_name_mismatch":     1.0,
        "mcld_mismatch":             1.0,
        "spf_fail":                  1.0,
        "tfidf_verify":              0.82,
        "tfidf_account":             0.74,
        "urgency_score":             0.65,
        "external_link_ratio":       0.90,
        ...
    },
    detail = "MLP probability: 97.35%. L1 score: 19.76%.",
)
```

---

## Train your own

```bash
# 1. Place all CSVs from Kaggle (naserabdullahalam) in data/raw/
python train/acquire_datasets.py --all

# 2. Train (fits TF-IDF vocab automatically on first run)
python train/train.py --data data/combined/phishbyte_v3_corpus.csv --skip-spf

# 3. Calibrate confidence gates
python train/calibrate_thresholds.py --data data/combined/phishbyte_v3_corpus.csv --n-val 5000

# 4. Evaluate
python eval.py --n 5000

# 5. Push to Hub
python push_to_hub.py --repo-id YOUR_HF_USERNAME/phishbyte
```

Feature extraction is cached — 83K emails extract in ~3 minutes first time, then instant.

---

## What this is not

- **Not a transformer.** No BERT, no fine-tuning, no pretrained weights. The MLP is randomly initialised and trained from scratch. TF-IDF vocabulary is learned from the training corpus, not from any external LM.
- **Not a spam filter.** Phish_Byte targets credential theft, impersonation, and account compromise — not promotional mail.
- **Not infallible.** F1 0.950 means ~5% of decisions are wrong. Use as one signal in defence-in-depth.
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
│   │   ├── domain.py          # domain + brand + display-name + suspicious pattern
│   │   ├── urls.py            # URLs, anchors, body urgency (normalized), char-level
│   │   ├── spf.py             # SPF DNS validation
│   │   ├── subject.py         # subject line patterns
│   │   ├── bdi.py             # Body Domain Identification (MCLD, form action, ext ratio)
│   │   └── tfidf_features.py  # TF-IDF vocabulary fitting + transform
│   └── model/
│       ├── mlp.py             # residual MLP (85→360→180×2→90→48→1), Hub mixin
│       └── weights/           # .gitignored — download from Hub or train locally
├── train/
│   ├── acquire_datasets.py    # 6-dataset acquisition + combine
│   ├── train.py               # training loop with calibrated F1 metric
│   └── calibrate_thresholds.py
├── cli.py                     # interactive CLI with Gmail support
├── eval.py                    # batch evaluation
├── push_to_hub.py             # one-command Hub deployment
└── requirements.txt
```

---

## Roadmap

- [x] 6-extractor Layer 1 pipeline (domain, URL, SPF, subject, BDI, TF-IDF)
- [x] Residual MLP at Layer 2 (254K params, 85 features, from scratch)
- [x] 6-dataset training corpus (83K emails, balanced)
- [x] TF-IDF vocabulary learned from training corpus (50 terms)
- [x] Body Domain Identification (BDI) features
- [x] ROC-based threshold calibration with Youden J sanity check
- [x] 85-feature attribution on every verdict
- [x] GPU support (CUDA 12.8 / Blackwell sm_120)
- [x] HuggingFace Hub publish
- [x] Calibrated F1 in training loop (Youden-optimal threshold)
- [ ] HuggingFace Space demo (try without installing)
- [ ] PyPI package — `pip install phishbyte`
- [ ] URL-only detection mode
- [ ] Full SHAP attribution (replace input-magnitude proxy)
- [ ] Layer 3 deep checks (WHOIS, redirect chains, ASN)
- [ ] Browser extension (Chrome/Firefox)
- [ ] Multilingual phishing support

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

## License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>