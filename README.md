<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&pause=1000&color=00FF88&center=true&vCenter=true&width=600&lines=PHISH_BYTE;Email+Phishing+Detection;PyTorch+%C2%B7+No+pretrained+LMs" alt="Phish_Byte" />

<br/>

![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![CUDA](https://img.shields.io/badge/CUDA-12.8-76B900?style=for-the-badge&logo=nvidia&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![GitHub stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=social)
![GitHub last commit](https://img.shields.io/github/last-commit/AnonymousSingh-007/Phish_Byte?color=00FF88)
![GitHub repo size](https://img.shields.io/github/repo-size/AnonymousSingh-007/Phish_Byte)

</div>

---

A PyTorch model for **email phishing detection**. Three-stage cascading inference: cheap rule scorers handle the obvious cases, a small MLP handles the uncertain ones, deep structural analysis handles the hardest. The model is randomly initialised and trained from scratch on phishing datasets — no pretrained language models.

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine()
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing'
print(verdict.probability)       # 0.9412
print(verdict.confidence)        # 'high'
print(verdict.layer_used)        # 1 — decided at the cheap layer
print(verdict.feature_weights)   # {'domain_mismatch': 1.0, 'spf_fail': 1.0, ...}
```

---

## Why a cascade, not a single classifier

Most production email security systems process millions of messages per day. Running a neural network on every single one is wasteful when 80% of phishing attempts trip obvious rules (mismatched sender domain, SPF failure, suspicious TLD). Phish_Byte routes those to a fast path. The MLP only fires on the harder fraction.

This means two things you can verify in the output:

- **`verdict.layer_used`** tells you whether the rules alone decided, or whether the neural network had to run. Useful for cost reporting.
- **`verdict.feature_weights`** shows exactly which signals fired. Not a black box.

Thresholds between layers are not hardcoded. They're calibrated on a held-out validation set via ROC analysis — the phish gate is set to the lowest threshold that maintains ≥95% precision, the clean gate to the highest threshold that maintains ≥95% recall on legitimate emails. Run `python train/calibrate_thresholds.py` after training to regenerate them for your own dataset.

---

## Architecture

```
   raw email
       │
       ▼
┌──────────────────────────────────┐
│ Layer 1 — rule scorers           │   always runs
│   • domain consistency           │   ~1ms per email
│   • SPF validation               │
│   • URL / anchor analysis        │
│   • body urgency + obfuscation   │
└──────────────┬───────────────────┘
               │
       calibrated gate
               │
        uncertain ─► ┌──────────────────────────────────┐
                     │ Layer 2 — MLP                    │   only when uncertain
                     │   15-d feature vector            │   ~5ms per email on GPU
                     │   2 hidden layers, sigmoid       │   trained from scratch
                     │   + post-hoc SHAP attribution    │
                     └──────────────┬───────────────────┘
                                    │
                            calibrated gate
                                    │
                             uncertain ─► ┌──────────────────────────────────┐
                                          │ Layer 3 — deep structural        │   rare path
                                          │   • redirect chain depth         │   network calls
                                          │   • WHOIS domain age             │   ~200ms+
                                          │   • ASN / geo reputation         │
                                          └──────────────────────────────────┘
                                    │
                                    ▼
                              PhishVerdict
```

---

## Install

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte

py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1                                            # Windows
# source venv/bin/activate                                              # Linux / Mac

pip install -r requirements.txt

# GPU users: install CUDA-enabled PyTorch (RTX 50 series / Blackwell)
pip install torch --index-url https://download.pytorch.org/whl/cu128
```

Verify GPU is detected:

```bash
python -c "import torch; print(torch.cuda.is_available(), torch.cuda.get_device_name(0))"
# Expected: True NVIDIA GeForce RTX 5050 Laptop GPU
```

---

## Usage

### CLI

```bash
python cli.py --demo                       # built-in phishing sample
python cli.py --file suspicious.eml        # analyse a .eml file
python cli.py                              # paste raw email, Ctrl+Z to submit
python cli.py --demo --json                # JSON output for scripting
```

### Python API

```python
from phishbyte import PhishByteEngine

engine = PhishByteEngine()

# Load a raw email (with headers)
with open("suspicious.eml") as f:
    verdict = engine.analyze(f.read())

if verdict.label == "phishing" and verdict.confidence == "high":
    quarantine(email)
```

### Output schema

```python
PhishVerdict(
    label           = "phishing",        # "phishing" | "legitimate"
    probability     = 0.94,              # P(phish) in [0, 1]
    confidence      = "high",            # "high" | "medium" | "low"
    layer_used      = 1,                 # 1 | 2 | 3 — which layer decided
    feature_weights = {                  # which signals fired
        "domain_mismatch":  1.0,
        "spf_fail":         1.0,
        "http_ratio":       0.8,
    },
    detail          = "...",             # human-readable summary
)
```

---

## Training your own

```bash
# 1. Train the MLP
python train/train.py

# 2. Calibrate confidence thresholds on the validation set
python train/calibrate_thresholds.py

# 3. Verify the engine loads everything
python cli.py --demo
```

The default `train.py` runs on synthetic data to prove the pipeline. For real performance, point it at a labelled CSV:

```bash
python train/train.py --data data/ceas2008.csv
```

CSV format: two columns, `email_text` (full raw email including headers) and `label` (`0` legitimate, `1` phishing). CEAS-2008 and the Enron spam corpus are not included in the repo — see `train/README.md` for download instructions.

---

## Benchmarks

Pending real-dataset evaluation on CEAS-2008. The table below will be populated once training completes:

| Metric | Synthetic | CEAS-2008 |
|--------|-----------|-----------|
| Accuracy | TBD | TBD |
| Precision (phish) | TBD | TBD |
| Recall (phish) | TBD | TBD |
| F1 score | TBD | TBD |
| ROC-AUC | TBD | TBD |
| Layer 1 coverage | TBD | TBD |
| Avg inference latency | TBD | TBD |
| Throughput (emails/sec) | TBD | TBD |

Layer 1 coverage is the percentage of emails decided without invoking the MLP. Higher is better — it means less compute spent per email at deployment.

---

## What this is not

- **Not a language model.** No transformer, no embedding lookup, no pretrained weights of any kind. The MLP at Layer 2 is randomly initialised and trained from scratch on the 15-dimensional feature vector produced by Layer 1.
- **Not a spam filter.** Spam and phishing overlap but are distinct problems. Phish_Byte targets credential theft, account compromise, and impersonation attacks.
- **Not infallible.** Confidence is calibrated on a validation set, but novel attack patterns and adversarial emails crafted to game these specific features will get through. Use it as one signal in a defence-in-depth stack, not as the only gate.

---

## Repo layout

```
Phish_Byte/
├── phishbyte/
│   ├── engine.py            # cascading engine, threshold gates
│   ├── verdict.py           # PhishVerdict dataclass
│   ├── calibration.py       # ROC-based threshold learning
│   ├── extractors/          # Layer 1 rule scorers
│   │   ├── domain.py
│   │   ├── urls.py
│   │   └── spf.py
│   └── model/
│       ├── mlp.py           # Layer 2 PyTorch MLP
│       └── weights/         # trained weights + thresholds.json
├── train/
│   ├── train.py             # MLP training loop
│   ├── calibrate_thresholds.py
│   └── synthetic_data.py    # synthetic emails for pipeline testing
├── cli.py                   # command-line interface
└── requirements.txt
```

---

## Roadmap

- [x] Layer 1 rule scorers
- [x] PyTorch MLP at Layer 2
- [x] ROC-based threshold calibration
- [x] Verdict object with per-feature attribution
- [x] GPU support (CUDA 12.8 / Blackwell)
- [ ] CEAS-2008 training + benchmark table
- [ ] Temperature-scaled calibrated probabilities
- [ ] Layer 3 deep structural checks (with retry / timeout / fallback)
- [ ] Feature vector caching (skip re-extraction across training runs)
- [ ] PyTorch Hub publish
- [ ] HuggingFace Hub publish (`PyTorchModelHubMixin`)
- [ ] Browser extension wrapper

---

## License

MIT — see [`LICENSE`](LICENSE).

---

<div align="center">

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>