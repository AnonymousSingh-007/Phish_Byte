<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=PHISH_BYTE+v7;85+features+%C2%B7+254K+params+%C2%B7+F1+0.950;No+pretrained+LM+%C2%B7+No+transformers" alt="Phish_Byte" />

<br/>

[![Model on HuggingFace](https://img.shields.io/badge/🤗_Try_it_on-HuggingFace-FFD21E?style=for-the-badge)](https://huggingface.co/SamSec007/phishbyte)
![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![F1](https://img.shields.io/badge/F1_score-0.950-00FF88?style=flat-square)
![Accuracy](https://img.shields.io/badge/Accuracy-94.9%25-00FF88?style=flat-square)
![Throughput](https://img.shields.io/badge/Throughput-995_emails%2Fsec-00FF88?style=flat-square)
![Parameters](https://img.shields.io/badge/Parameters-254K-blue?style=flat-square)
![Features](https://img.shields.io/badge/Features-85_(35_rule+50_TF--IDF)-orange?style=flat-square)
![Stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=flat-square&color=yellow)

</div>

---

A PyTorch model for **email phishing detection** trained entirely from scratch on 6 public datasets.

**F1 0.950** on 5,000 held-out samples (self-reported — see [Limitations](#limitations)). **254K parameters** (≈260× smaller than DistilBERT). **995 emails/sec** on a laptop GPU. **85 engineered features** including a TF-IDF vocabulary learned directly from the training corpus — no pretrained language model, no transformer, no fine-tuning.

**👉 [Try it on the HuggingFace model page](https://huggingface.co/SamSec007/phishbyte)** — full model card, weights, and usage examples live there.

---

## Get started in 4 commands

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte
python -m venv venv && source venv/bin/activate   # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Then verify everything works before doing anything else:

```bash
python verify_install.py
```

This checks every dependency, every source file, and does a live test-download from HuggingFace Hub. If anything's wrong, it tells you exactly what — not a cryptic traceback. **Every install issue reported so far has been caught by this script.** Run it first.

Once it's green:

```bash
python cli.py --demo phish
```

Or in Python, from inside the cloned folder:

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

The first `from_pretrained()` call downloads ~1 MB of weights, thresholds, and the TF-IDF vocabulary from [huggingface.co/SamSec007/phishbyte](https://huggingface.co/SamSec007/phishbyte) and caches them locally. Every call after that is instant.

**No PyPI package yet.** `pip install phishbyte` does not work — cloning is the only supported path right now (see [Roadmap](#roadmap)).

---

## Analyse a real email from Gmail

1. Open the email → click **⋮** menu → **Show original**
2. Select all (Ctrl+A), copy (Ctrl+C)
3. Run `python cli.py`, paste when prompted, press Enter then Ctrl+Z (Windows) or Ctrl+D (Mac/Linux)

Or save as `.eml` and run:

```bash
python cli.py --file suspicious.eml
```

---

## Troubleshooting

Run `python verify_install.py` first — it catches nearly everything below automatically with a specific fix.

| Error | Fix |
|-------|-----|
| `ModuleNotFoundError: No module named 'phishbyte'` | Not running from inside the cloned repo, or venv not activated. `cd Phish_Byte`, reactivate venv. |
| `ImportError: cannot import name 'X'` | Clone is out of date. `git pull origin main`. |
| `pip install phishbyte` fails | Package doesn't exist on PyPI yet. Clone the repo instead (see above). |
| `NameError: save_model_as_safetensor is not defined` | Missing `safetensors`. `pip install safetensors`. |
| Model download hangs | Check internet. Hub: [huggingface.co/SamSec007/phishbyte](https://huggingface.co/SamSec007/phishbyte) |
| Windows symlink warning during download | Harmless. Uses slightly more disk space. Ignore, or enable Windows Developer Mode to silence it. |

Still stuck? [Open an issue](https://github.com/AnonymousSingh-007/Phish_Byte/issues) with your `verify_install.py` output attached.

---

## Why this exists

Every phishing detection model on HuggingFace is a fine-tuned transformer — DistilBERT, BERT, RoBERTa. They work well but come with costs: 65–110M parameters, ~250 MB on disk, GPU-dependent throughput. For organizations scanning millions of emails per day, that's expensive for volume where most cases trip simple signals.

Phish_Byte takes a different bet:

- **Custom MLP trained from scratch** — no pretrained weights, no fine-tuned LM
- **85 engineered features** covering domain, URL, SPF, subject, body, character-level, Body Domain Identification (BDI), and learned TF-IDF signals
- **Cascading inference** — cheap rule scorers veto obvious cases, MLP handles the rest
- **Runs on CPU** — no GPU requirement for deployment
- **Every verdict explains itself** — 85-feature attribution on every prediction

**Phish_Byte is the only non-transformer phishing detection model on HuggingFace.**

---

## Benchmarks

Evaluated on 5,000 held-out samples from the 6-dataset training corpus (83K emails, balanced ~50/50).

| Metric | Phish_Byte v7 | DistilBERT fine-tuned\* |
|--------|:------------:|:-----------------------:|
| F1 score | **0.950** | ~0.967 |
| Accuracy | **94.94%** | ~97% |
| Parameters | **254K** | 66,000,000 |
| Model size on disk | **~1 MB** | ~263 MB |
| Throughput (GPU) | **995/sec** | ~50/sec |
| GPU required | **No** | Practically yes |
| Header + SPF analysis | **Yes** | No |
| Explainability | **85-feature attribution** | Token-level SHAP |

\* Self-reported by a different author on a different data split (`dima806/phishing-email-detection`). **This is not an apples-to-apples benchmark** — treat both F1 numbers as directional. A shared-split head-to-head comparison is planned (see Roadmap).

**Where the trade-off actually favors Phish_Byte:** 260× smaller model, 20× higher throughput, zero GPU requirement, full header/SPF analysis that body-only transformer models skip entirely.

---

## Feature signals (85 total)

| Category | Count | Features |
|----------|:-----:|----------|
| **Domain** | 7 | domain mismatch, Reply-To differs, Return-Path differs, freemail flag, brand impersonation, display name mismatch, suspicious domain pattern |
| **URL + Body** | 10 | HTTPS ratio, anchor mismatch, suspicious TLD, urgency (normalized), link density (normalized), caps ratio, digit ratio, special char density, avg word length, HTML/text ratio |
| **SPF** | 3 | SPF fail, no SPF record, no sending IP |
| **Subject** | 7 | urgency, security theme, brand name, currency, all caps, fake `RE:` prefix, fake transaction IDs |
| **BDI** | 3 | most common link domain mismatch, form action domain mismatch, external link ratio |
| **TF-IDF** | 50 | top-50 discriminative unigrams learned from training corpus (no pretrained embeddings) |
| **Composite** | 5 | per-module normalized layer scores |

---

## Architecture

```
   raw email
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│ Layer 1 — 6 rule scorers                        ~1 ms per email │
│  domain · URL+body · SPF · subject · BDI · TF-IDF               │
│  composite score ≥ 0.85 → fast phish verdict (obvious cases)    │
└────────────────────────────┬────────────────────────────────────┘
                             │ everything else
                             ▼
┌──────────────────────────────────────────────────────────────────┐
│ Layer 2 — residual MLP                          ~3 ms per email │
│  85 → 360 → 180 (×2 ResBlock) → 90 → 48 → 1  (sigmoid)         │
│  254K parameters · trained from scratch · no pretrained LM      │
│  + input-to-output skip connection                               │
│  + post-hoc per-feature attribution                              │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                       PhishVerdict
            { label · probability · confidence
              layer_used · feature_weights }
```

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

**All source corpora predate 2010.** See Limitations — this is the model's biggest known weakness, and retraining on modern data is the top roadmap item.

---

## Limitations

Read this before deploying anywhere real.

- **Training data is 15+ years old.** These corpora predate OAuth phishing, QR code lures, redirect chains through legitimate services (Google Docs, Dropbox, OneDrive), and modern adversarial HTML tricks. **Recall on 2020s-era phishing is untested and likely degraded.** Retraining on PhishTank, OpenPhish, and APWG eCrime datasets is the top roadmap priority.
- **TF-IDF vocabulary is era-locked.** The 50 learned terms reflect 2000s phishing language. Modern phrasing ("access your document," "complete two-step verification") isn't represented.
- **No adversarial robustness testing has been done.** An attacker aware of the fixed feature set could plausibly craft bypasses. This model has not been red-teamed. Use as one signal in defence-in-depth, not a standalone gate.
- **F1 0.950 is self-reported** on a held-out split of the training data — not an independently verified or peer-reviewed benchmark.
- **Not production-hardened** — no retry logic, rate limiting, or async SPF handling.
- **English-language only.**

---

## Repository layout

```
Phish_Byte/
├── phishbyte/
│   ├── __init__.py
│   ├── engine.py               # cascading engine, Hub integration
│   ├── verdict.py              # PhishVerdict dataclass
│   ├── calibration.py          # ROC-based threshold learning
│   ├── extractors/
│   │   ├── __init__.py
│   │   ├── domain.py           # domain + brand + display-name + suspicious pattern
│   │   ├── urls.py             # URLs, anchors, body urgency, char-level
│   │   ├── spf.py              # SPF DNS validation
│   │   ├── subject.py          # subject line patterns
│   │   ├── bdi.py              # Body Domain Identification
│   │   └── tfidf_features.py   # TF-IDF vocabulary fitting + transform
│   └── model/
│       ├── __init__.py
│       ├── mlp.py              # residual MLP, Hub mixin
│       └── weights/            # .gitignored — auto-downloaded from Hub
├── train/                      # training pipeline, dataset acquisition
├── cli.py                      # interactive CLI with Gmail support
├── eval.py                     # batch evaluation
├── push_to_hub.py              # one-command Hub deployment
├── verify_install.py           # run this before reporting any issue
├── fix_init_files.py           # repairs missing __init__.py files
└── requirements.txt
```

---

## Roadmap

- [x] 85-feature, 254K-parameter cascading model
- [x] 6-dataset training corpus (83K emails)
- [x] TF-IDF vocabulary + Body Domain Identification features
- [x] HuggingFace Hub publish with working install
- [x] `verify_install.py` diagnostic tool
- [ ] **Retrain on 2020–2024 phishing data** (PhishTank, OpenPhish, APWG eCrime) — top priority
- [ ] Adversarial robustness test suite + documented known bypasses
- [ ] Head-to-head benchmark vs DistilBERT on a shared held-out set
- [ ] HuggingFace Space demo (try in-browser, zero install)
- [ ] PyPI package (`pip install phishbyte`)
- [ ] arXiv preprint
- [ ] URL-only detection mode
- [ ] Browser extension

---

## Citation

No peer-reviewed paper exists yet — an arXiv preprint is planned. Until then, cite the repository:

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

**[🤗 Try it on HuggingFace](https://huggingface.co/SamSec007/phishbyte)** · **[📦 View source](https://github.com/AnonymousSingh-007/Phish_Byte)**

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>