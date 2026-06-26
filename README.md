<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=32&pause=1000&color=00FF88&center=true&vCenter=true&width=600&lines=PHISH_BYTE+v2.0;Email+Threat+Engine;Built+from+scratch.+No+shortcuts." alt="Phish_Byte" />

<br/>

![Python](https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white)
![PyTorch](https://img.shields.io/badge/PyTorch-2.12.1-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![Status](https://img.shields.io/badge/Status-Active%20Development-00FF88?style=for-the-badge&logo=git&logoColor=black)
![Target](https://img.shields.io/badge/Target-HuggingFace%20Hub-FFD21E?style=for-the-badge&logo=huggingface&logoColor=black)
![PyTorch Hub](https://img.shields.io/badge/Target-PyTorch%20Hub-EE4C2C?style=for-the-badge&logo=pytorch&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blueviolet?style=for-the-badge)

<br/>

![GitHub stars](https://img.shields.io/github/stars/AnonymousSingh-007/Phish_Byte?style=social)
![GitHub forks](https://img.shields.io/github/forks/AnonymousSingh-007/Phish_Byte?style=social)
![GitHub issues](https://img.shields.io/github/issues/AnonymousSingh-007/Phish_Byte?color=red)
![GitHub last commit](https://img.shields.io/github/last-commit/AnonymousSingh-007/Phish_Byte?color=00FF88)
![GitHub repo size](https://img.shields.io/github/repo-size/AnonymousSingh-007/Phish_Byte)

</div>

---

<div align="center">

```
██████╗ ██╗  ██╗██╗███████╗██╗  ██╗    ██████╗ ██╗   ██╗████████╗███████╗
██╔══██╗██║  ██║██║██╔════╝██║  ██║    ██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
██████╔╝███████║██║███████╗███████║    ██████╔╝ ╚████╔╝    ██║   █████╗  
██╔═══╝ ██╔══██║██║╚════██║██╔══██║    ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  
██║     ██║  ██║██║███████║██║  ██║    ██████╔╝   ██║      ██║   ███████╗
╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
```

> **The only email phishing detection engine on PyTorch Hub / HuggingFace built entirely from scratch.**  
> No pretrained weights. No fine-tuning. No shortcuts. Every signal, every layer, every weight: ours.

</div>

---

## Repository stats

<div align="center">

[![GitHub Stats](https://github-readme-stats.vercel.app/api?username=AnonymousSingh-007&show_icons=true&theme=radical&title_color=00FF88&icon_color=00FF88&text_color=ffffff&bg_color=0d0d0d&border_color=00FF88&include_all_commits=true&count_private=true)](https://github.com/AnonymousSingh-007)

[![Top Languages](https://github-readme-stats.vercel.app/api/top-langs/?username=AnonymousSingh-007&layout=compact&theme=radical&title_color=00FF88&text_color=ffffff&bg_color=0d0d0d&border_color=00FF88)](https://github.com/AnonymousSingh-007)

[![GitHub Streak](https://streak-stats.demolab.com?user=AnonymousSingh-007&theme=dark&ring=00FF88&fire=00FF88&currStreakLabel=00FF88&sideLabels=00FF88&dates=ffffff&border=00FF88&background=0d0d0d)](https://github.com/AnonymousSingh-007)

</div>

### Code frequency

![Contribution chart](https://ghchart.rshah.org/00FF88/AnonymousSingh-007)

---

## Mission

```python
# Phish_Byte v1 — what it was
print("Phishing?", "Yes" if domain_mismatch else "No")   # deterministic. binary. no score.

# Phish_Byte v2 — what it's becoming
verdict = engine.analyze(raw_email)
# PhishVerdict(
#   label          = "phishing",
#   probability    = 0.94,
#   confidence     = "high",
#   layer_used     = 1,          # only ran what it needed to
#   feature_weights = {          # shows every signal that fired
#       "domain_mismatch":  1.0,
#       "spf_fail":         1.0,
#       "http_ratio":       0.8,
#       "anchor_mismatch":  0.6,
#   }
# )
```

A **cascading analysis engine** — reasons in stages, only escalates when uncertain, explains every verdict, ships as a real PyTorch model you can `torch.hub.load()`.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      EMAIL INPUT                            │
│              .eml  /  raw headers  /  string                │
└──────────────────────────┬──────────────────────────────────┘
                           │
                           ▼
┌─────────────────────────────────────────────────────────────┐
│  LAYER 1 — Static rule scorer            [always runs]      │
│                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────┐    │
│  │  Domain     │  │    URL      │  │  Body scorer     │    │
│  │  scorer     │  │  scorer     │  │  (new)           │    │
│  │  0.0 – 1.0  │  │  0.0 – 1.0  │  │  0.0 – 1.0       │    │
│  └─────────────┘  └─────────────┘  └──────────────────┘    │
└──────────────────────────┬──────────────────────────────────┘
                           │
              ┌────────────▼────────────┐
              │   CONFIDENCE GATE 1     │
              │   score > 0.85?         │
              └──────┬──────────┬───────┘
               YES   │          │  NO — escalate
                     │          ▼
                     │  ┌──────────────────────────────────────┐
                     │  │  LAYER 2 — Learned MLP scorer        │
                     │  │  15-feature vec → sigmoid → P(phish) │
                     │  │  + SHAP explainability head          │
                     │  └──────────────┬───────────────────────┘
                     │                 │
                     │    ┌────────────▼────────────┐
                     │    │   CONFIDENCE GATE 2     │
                     │    └──────┬──────────┬───────┘
                     │     YES   │          │  NO — escalate
                     │           │          ▼
                     │           │  ┌───────────────────────────┐
                     │           │  │  LAYER 3 — Deep scan      │
                     │           │  │  redirect chains          │
                     │           │  │  WHOIS domain age         │
                     │           │  │  ASN / geo reputation     │
                     │           │  └──────────┬────────────────┘
                     │           │             │
                     └───────────┴─────────────┘
                                               │
                                               ▼
                    ┌──────────────────────────────────────────┐
                    │            VERDICT OBJECT                │
                    │  label  ·  probability  ·  confidence    │
                    │  layer_used  ·  feature_weights          │
                    └──────────────────────────────────────────┘
```

---

## Feature signals

| Signal | Layer | Type | Source |
|--------|-------|------|--------|
| Domain consistency — From / Reply-To / Return-Path | 1 | rule | Original Phish_Byte |
| SPF validation — DNS + IP range check | 1 | rule | Original Phish_Byte |
| HTTPS ratio in email body | 1 | rule | Original Phish_Byte |
| Anchor text ↔ href domain mismatch | 1 | rule | Original Phish_Byte |
| Urgency keyword density | 1 | rule | **New** |
| Link-to-text ratio | 1 | rule | **New** |
| HTML obfuscation score | 1 | rule | **New** |
| Learned phishing probability | 2 | MLP | **New — trained from scratch** |
| SHAP per-feature attribution | 2 | explainability | **New** |
| Redirect hop count + domain switches | 3 | deep | **New** |
| WHOIS domain registration age | 3 | deep | **New** |
| ASN / geolocation reputation | 3 | deep | **New** |

---

## Quickstart

```bash
git clone https://github.com/AnonymousSingh-007/Phish_Byte.git
cd Phish_Byte

py -3.11 -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate          # Linux / Mac

pip install -r requirements.txt
```

```python
from phishbyte.engine import PhishByteEngine

engine = PhishByteEngine()

with open("suspicious.eml", "r") as f:
    raw = f.read()

verdict = engine.analyze(raw)
print(verdict)
# PhishVerdict(label='phishing', probability=0.94, confidence='high', layer_used=1, ...)
```

---

## Build status

| Milestone | Status |
|-----------|--------|
| Original rule-based analyser (v1) | ✅ Done |
| Repo restructure + venv | ✅ Done |
| Layer 1 — extractor refactor (scored dicts) | 🔨 In progress |
| Verdict dataclass | ⬜ Next |
| Engine skeleton + confidence gates | ⬜ Planned |
| Layer 2 — MLP training on CEAS-2008 | ⬜ Planned |
| SHAP explainability head | ⬜ Planned |
| Layer 3 — deep structural checks | ⬜ Planned |
| PyTorch Hub publish | ⬜ Planned |
| HuggingFace Hub publish | ⬜ Planned |
| Browser extension wrapper | ⬜ Planned |

---

## Dataset

Training uses **CEAS-2008** (~39K labelled emails, public) and the **Enron spam corpus**.  
Neither is included in the repo — see `train/README.md` for download links and preprocessing steps.

---

## Research context

Phish_Byte is a companion artifact to ongoing research in adversarial analysis of AI-driven systems. The cascading engine architecture — deterministic rule signals feeding a learned scorer with staged escalation and full explainability — is the contribution, not just the weights.

Target venues: **IEEE TIFS** · **IEEE S&P**

---

<div align="center">

![Visitor Count](https://komarev.com/ghpvc/?username=AnonymousSingh-007&label=PROFILE+VIEWS&color=00FF88&style=for-the-badge)

```
Built from scratch. No pretrained weights. No shortcuts.
Phish_Byte v2 — AnonymousSingh-007
```

</div>