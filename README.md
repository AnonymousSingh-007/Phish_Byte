# Phish_Byte

<div align="center">

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.12.1-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange?style=for-the-badge)
![Target](https://img.shields.io/badge/Target-HuggingFace%20Hub-FFD21E?style=for-the-badge&logo=huggingface&logoColor=black)
![Stage](https://img.shields.io/badge/Engine-Cascading%20Analyser-purple?style=for-the-badge)

<br/>

> **The only email phishing detection model built entirely from scratch in PyTorch —**  
> **no pretrained weights, no fine-tuning. Every signal, every layer, every weight: ours.**

</div>

---

## What Phish_Byte is becoming

Phish_Byte started as a rule-based email analyser. It's being rebuilt as a **cascading analysis engine** — a staged reasoning system that only does expensive work when cheap work is uncertain.

```
Email input
    │
    ▼
[Layer 1] Fast static rules  ──── high confidence ──▶  Verdict
    │ uncertain
    ▼
[Layer 2] Learned MLP scorer ──── high confidence ──▶  Verdict  
    │ uncertain
    ▼
[Layer 3] Deep structural analysis              ──▶  Verdict
    │
    ▼
Verdict object: { label, P(phish), confidence, layer_used, feature_weights }
```

Every verdict tells you **what fired, why, and how certain the engine is.** Not a black box.

---

## Architecture

| Layer | What it does | When it runs |
|-------|-------------|--------------|
| **Layer 1** — Static rules | Domain consistency, SPF validation, URL/anchor analysis | Always — your original Phish_Byte logic, refactored |
| **Confidence gate** | Checks if score is above threshold | After Layer 1 |
| **Layer 2** — MLP scorer | 15-feature vector → learned phishing probability | Only when Layer 1 is uncertain |
| **Layer 3** — Deep analysis | Redirect chains, WHOIS age, ASN reputation | Only when Layer 2 is uncertain |

**Output — `VerdictObject`**

```python
{
    "label":           "phishing",       # or "legitimate"
    "probability":     0.94,             # P(phish) from 0.0 to 1.0
    "confidence":      "high",           # low / medium / high
    "layer_used":      1,                # which layer made the call
    "feature_weights": {                 # what signals drove the verdict
        "domain_mismatch": 1.0,
        "spf_fail": 1.0,
        "http_ratio": 0.8,
        ...
    }
}
```

---

## Current status

- [x] Original rule-based analyser (v1)
- [ ] Layer 1 — extractor refactor (scored feature dicts)
- [ ] Verdict dataclass
- [ ] Engine skeleton with confidence gates
- [ ] Layer 2 — MLP training on CEAS-2008
- [ ] SHAP explainability head
- [ ] Layer 3 — deep structural checks
- [ ] PyTorch Hub publish
- [ ] HuggingFace Hub publish
- [ ] Browser extension wrapper

---

## Checks implemented

| Signal | Source | Output |
|--------|--------|--------|
| Domain consistency | From / Reply-To / Return-Path headers | score 0–1 |
| SPF validation | DNS TXT lookup vs Received IP | 0 or 1 |
| URL security ratio | HTTPS vs HTTP count in body | score 0–1 |
| Anchor mismatch | href domain vs visible text domain | score 0–1 |
| Urgency keywords | Body text scan | score 0–1 *(Layer 1 new)* |
| Link density | Links per text ratio | score 0–1 *(Layer 1 new)* |
| Redirect depth | Hop count, domain switches | score 0–1 *(Layer 3)* |
| WHOIS domain age | Registration recency | score 0–1 *(Layer 3)* |

---

## Quickstart

```bash
# Clone
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte

# Environment (Python 3.11 required)
py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1       # Windows
# source venv/bin/activate         # Linux/Mac

# Install
pip install -r requirements.txt
```

```python
from phishbyte.engine import PhishByteEngine

engine = PhishByteEngine()
verdict = engine.analyze(raw_email_string)
print(verdict)
```

---

## Dataset

Training uses **CEAS-2008** (public, ~39K labelled emails) and the **Enron spam corpus**.  
Neither dataset is included in this repo — see `train/README.md` for download instructions.

---

## Research context

Phish_Byte is a companion artifact to ongoing research in adversarial analysis of intelligent systems. The cascading engine architecture — deterministic rule signals feeding a learned scorer with staged escalation — is the contribution, not the weights.

Target publication venues: IEEE TIFS, IEEE S&P.

---

## License

MIT — see `LICENSE`.

---

<div align="center">
<sub>Built from scratch. No pretrained weights. No shortcuts.</sub><br/>
<sub>Phish_Byte v2 — by <a href="https://github.com/AnonymousSingh-007">AnonymousSingh-007</a></sub>
</div>