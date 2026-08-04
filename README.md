<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=26&pause=1000&color=00FF88&center=true&vCenter=true&width=700&lines=PHISH_BYTE+v8;104+features+%C2%B7+716K+params;Cross-signal+fusion+%C2%B7+No+pretrained+LM" alt="Phish_Byte" />

<br/>

[![Model on HuggingFace](https://img.shields.io/badge/🤗_Try_it_on-HuggingFace-FFD21E?style=for-the-badge)](https://huggingface.co/SamSec007/phishbyte)
[![License: MIT](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)](LICENSE)
![PyTorch](https://img.shields.io/badge/PyTorch-2.11+cu128-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)

<br/>

![Parameters](https://img.shields.io/badge/Parameters-716K-blue?style=flat-square)
![Features](https://img.shields.io/badge/Features-104_(54_rule%2Fcross--signal+50_TF--IDF)-orange?style=flat-square)
![Training data](https://img.shields.io/badge/Training-166K+_emails_%C2%B7_7_datasets-orange?style=flat-square)
![Calibrated](https://img.shields.io/badge/Confidence-temperature--calibrated-brightgreen?style=flat-square)
![Stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=flat-square&color=yellow)

</div>

---

A PyTorch model for **email phishing detection**, built entirely from scratch — no pretrained language model, no transformer, no fine-tuning.

Every signal comes from features we compute ourselves: domain analysis, URL structure, SPF validation, subject-line patterns, link-domain forensics, character-level lexical analysis, and a small neural network that learns how those signals interact. **716K parameters** — about 90× smaller than DistilBERT — with calibrated probability outputs and full per-feature attribution on every verdict.

**👉 [Try it on the HuggingFace model page](https://huggingface.co/SamSec007/phishbyte)**

---

## What it actually does, in plain language

When an email comes in, Phish_Byte doesn't read it the way a person does. It runs eight small, independent analyses on different parts of the email — the sender's domain, the links in the body, the SPF record, the subject line — and turns each one into a handful of numbers between 0 and 1. Those numbers get combined into one long list (104 numbers total) and fed into a small neural network that has learned, from 166,000+ real emails, what combinations of numbers tend to mean "phishing" versus "legitimate."

The important design decision: those eight analyses don't just sit side by side. A separate step looks at *how they agree or disagree with each other* — because a domain that legitimately fails one check (like using a different Reply-To address for routing) but passes SPF and has consistent link patterns is a very different case from a domain that fails everything at once. That "do the signals agree" layer is what stops the model from flagging routine notification emails (GitHub, Jira, AWS) just because they look unusual to any single rule in isolation.

---

## How a raw email becomes a verdict

```
                              raw email string
                                    │
                                    ▼
                  email.message_from_string() splits it into
                  headers (From, Reply-To, Subject...) + body
                                    │
        ┌───────────┬───────────┬──┴────────┬───────────┬──────────────┐
        ▼           ▼           ▼            ▼           ▼              ▼
     domain       urls         spf        subject       bdi          tfidf
    analysis     analysis    DNS check    analysis    link/form     vocabulary
   (7 numbers) (10 numbers) (3 numbers) (7 numbers)  forensics       match
                                                       (5 numbers)  (50 numbers)
        └───────────┴───────────┴──┬────────┴───────────┘              │
                                    ▼                                  │
                    lexical analysis on 2 domains                      │
                 (sender domain + most-linked domain)                  │
                          12 more numbers                              │
                                    │                                  │
                                    ▼                                  │
                        cross-signal layer:                            │
              "do these six analyses agree with each other?"           │
                          5 more numbers                                │
                                    │◄─────────────────────────────────┘
                                    ▼
                 all 104 numbers concatenated into one vector
                                    │
                                    ▼
              ┌─────────────────────────────────────────┐
              │   neural network (716K learned weights)  │
              │   looks for patterns across all 104       │
              │   numbers at once — including patterns    │
              │   no single rule could see alone          │
              └─────────────────────┬─────────────────────┘
                                    │
                                    ▼
                    calibrated confidence score (0–100%)
                                    │
                                    ▼
                   PhishVerdict: label, confidence,
                   and which of the 104 signals fired
```

---

## The eight analysis modules, explained simply

**Domain analysis** — checks whether the "From" address, the "Reply-To" address, and the "Return-Path" address are all consistent with each other, whether the sender's display name claims to be a known brand (like "PayPal Security") while the actual email address is unrelated, and whether the domain itself looks auto-generated (lots of digits, excessive hyphens, unusually long).

**URL and body analysis** — counts how many links use secure `https://` versus insecure `http://`, checks whether clickable link text matches where the link actually goes (a link that says "www.paypal.com" but points somewhere else is a red flag), scans for urgency language ("verify now," "account suspended"), and looks at formatting patterns like unusual capitalization density.

**SPF validation** — does a real, live DNS lookup to check whether the server that actually sent the email is authorized to send on behalf of that domain. This is the one module that checks the network rather than just the email's own content.

**Subject line analysis** — the same kind of pattern-matching as the body, but scoped just to the subject: urgency words, currency symbols, brand names, ALL-CAPS shouting.

**Link and form forensics (BDI)** — looks at every link in the email and finds the single most common destination domain. If that domain doesn't match who the email claims to be from, that's one of the strongest phishing signals we have. Also checks whether any form on the page submits directly to a raw IP address (legitimate sites essentially never do this) and whether links contain "open redirect" patterns.

**Lexical domain analysis** — a character-by-character look at domain names. Measures things like: does the domain have an unusual run of digits? An excessive number of hyphens? Does it read like a real word or like a randomly generated string? Is it a near-miss spelling of a known brand (`micros0ft` instead of `microsoft`)? This runs twice per email — once on the sender's domain, once on whichever domain got the most links.

**Cross-signal fusion** — the newest and most important piece. After the six modules above have all run, this layer asks questions *about* their answers: did SPF pass **and** are all the domains internally consistent **and** does the most-linked domain match the sender? If so, that's strong evidence of legitimacy that should discount minor red flags elsewhere. Conversely, if three or more independent modules all raise concerns at once, that agreement is treated as much stronger evidence than any one module alone.

**TF-IDF vocabulary matching** — the only module that looks at word choice. Rather than using a fixed dictionary, this vocabulary of 50 words was *learned directly from the training data* — the model figured out which specific words appear disproportionately in phishing versus legitimate email in this dataset, and checks for those.

---

## The neural network

All 104 numbers get concatenated into one vector and fed through a network with this shape:

```
104 inputs
   → 620 → 310 (two residual blocks) → 155 → 76 → 1 output
```

A "residual block" lets the network skip a transformation if it isn't useful for a particular email, rather than being forced through every layer regardless. There's also a direct shortcut from the very first 104 numbers straight to the final layer — so even if the deep part of the network gets confused, the raw signals are never completely lost.

The final output isn't just squashed into a 0–1 range with a plain sigmoid — it passes through a **learned temperature parameter** first. This is a calibration step: after the main network finishes training, a short second pass adjusts this single number so that "70% confident" actually corresponds to being right about 70% of the time on held-out data, rather than the network being systematically over- or under-confident.

**716,322 parameters total.** For comparison, DistilBERT-based phishing detectors on HuggingFace use 66,000,000+ parameters — about 90× more.

---

## Quickstart

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte
python -m venv venv && source venv/bin/activate   # Windows: .\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python verify_install.py
```

`verify_install.py` checks every dependency and source file, then does a live test download from the Hub. Run it before anything else — it catches nearly every setup problem with a specific fix, not a cryptic traceback.

```python
from phishbyte import PhishByteEngine

engine  = PhishByteEngine.from_pretrained("SamSec007/phishbyte")
verdict = engine.analyze(raw_email_string)

print(verdict.label)             # 'phishing' or 'legitimate'
print(verdict.probability)       # calibrated confidence, 0.0–1.0
print(verdict.confidence)        # 'high' / 'medium' / 'low'
print(verdict.layer_used)        # 1 = fast rule veto, 2 = full neural network
print(verdict.feature_weights)   # all 104 signal values for this email
```

**No PyPI package yet.** `pip install phishbyte` does not work — cloning is the only supported install path (see Roadmap).

### Analyze a real email from Gmail

Open the email → **⋮** menu → **Show original** → copy all → run `python cli.py` and paste when prompted. Or save as `.eml` and run `python cli.py --file suspicious.eml`.

---

## Feature groups (104 total)

| Group | Count | What it measures |
|-------|:-----:|-------------------|
| Domain | 7 | header consistency, brand impersonation, display-name spoofing |
| URL + body | 10 | link security, anchor/href mismatch, urgency language |
| SPF | 3 | live DNS-based sender authorization check |
| Subject | 7 | urgency, brand mentions, currency, formatting |
| BDI (link/form forensics) | 5 | most-common-link-domain mismatch, IP-address form targets, open redirects |
| Lexical — sender domain | 6 | digit runs, hyphen runs, entropy, typosquat distance |
| Lexical — most-linked domain | 6 | same six checks, applied to the dominant link destination |
| Cross-signal fusion | 5 | agreement/disagreement between all the above modules |
| TF-IDF | 50 | 50 words learned directly from the training corpus |
| Composite | 5 | per-module summary scores |

---

## Training data

| Dataset | Source |
|---------|--------|
| CEAS-2008, Enron, SpamAssassin, Ling-Spam, Nazario, Nigerian Fraud | Kaggle (naserabdullahalam/phishing-email-dataset) |
| farshad72/spam_email | HuggingFace (83K rows) |
| puyang2025/seven-phishing-email-datasets | HuggingFace (203K rows, 7-source unified) |
| **Combined, after deduplication** | **166,000+ emails, ~56% phishing / 44% legitimate** |

---

## Limitations

Read this before deploying anywhere real.

- **Most training data predates 2010.** Modern phishing techniques (OAuth abuse, QR code lures, redirect chains through legitimate cloud services) are underrepresented, even after adding modern HuggingFace datasets. Recall on cutting-edge 2020s attack patterns is not independently verified.
- **No adversarial robustness testing has been performed.** An attacker aware of the exact feature set could craft targeted bypasses. Use as one signal in defence-in-depth, not a standalone gate.
- **Benchmark numbers are self-reported** on a held-out split of the training data, not an independently verified or peer-reviewed evaluation.
- **Not production-hardened** — no retry logic, rate limiting, or async SPF handling.
- **English-language only.**

---

## Repository layout

```
Phish_Byte/
├── phishbyte/
│   ├── __init__.py
│   ├── engine.py                 # orchestrates all 8 modules, produces verdicts
│   ├── verdict.py                # PhishVerdict result object
│   ├── calibration.py            # threshold learning from validation data
│   ├── extractors/
│   │   ├── domain.py             # sender/reply-to/return-path consistency
│   │   ├── urls.py               # link + body analysis
│   │   ├── spf.py                # live DNS SPF validation
│   │   ├── subject.py            # subject-line patterns
│   │   ├── bdi.py                # link/form domain forensics
│   │   ├── lexical.py            # character-level domain analysis
│   │   ├── cross_signal.py       # inter-module agreement features
│   │   └── tfidf_features.py     # learned vocabulary matching
│   └── model/
│       ├── mlp.py                # the neural network + Hub integration
│       └── weights/               # gitignored — auto-downloaded from Hub
├── train/                        # training pipeline + dataset acquisition
├── cli.py                        # command-line interface
├── eval.py                       # batch evaluation
├── verify_install.py             # run this first, always
└── requirements.txt
```

---

## Roadmap

- [x] Cross-signal fusion layer (inter-module agreement features)
- [x] Character-level lexical domain analysis
- [x] Extended link/form forensics (IP-target forms, redirect detection)
- [x] Temperature-calibrated confidence scores
- [x] Multi-source training corpus (166K+ emails, 7 datasets)
- [ ] Retrain on dedicated 2020–2024 phishing datasets (PhishTank, OpenPhish)
- [ ] Adversarial robustness test suite with documented known bypasses
- [ ] Head-to-head benchmark vs transformer models on a shared held-out set
- [ ] HuggingFace Space demo (try in-browser, zero install)
- [ ] PyPI package (`pip install phishbyte`)
- [ ] arXiv preprint

---

## Citation

No peer-reviewed paper exists yet. Until then, cite the repository:

```bibtex
@software{phishbyte2026,
  author  = {Singh, Samratth},
  title   = {Phish\_Byte: A cascading from-scratch PyTorch model for email phishing detection},
  year    = {2026},
  url     = {https://github.com/AnonymousSingh-007/Phish_Byte}
}
```

---

## License

MIT — see [`LICENSE`](LICENSE).

<div align="center">

**[🤗 Try it on HuggingFace](https://huggingface.co/SamSec007/phishbyte)** · **[📦 View source](https://github.com/AnonymousSingh-007/Phish_Byte)**

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

</div>