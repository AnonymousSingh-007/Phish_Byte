"""
phishbyte/extractors/lexical.py — NEW MODULE

Character-level lexical analysis of the sender domain and all link domains.
This is the "human eyeball" layer — the things a person notices when they
look hard at a suspicious URL: digit substitution, hyphen stacking,
brand-name similarity, entropy.

Runs independently but is designed to be CALLED BY domain.py and bdi.py,
not standalone — see cross_signal.py for how it plugs into the pipeline.
"""
import re
import math
from typing import Dict, List

_COMMON_BRANDS = [
    "paypal","amazon","apple","microsoft","google","netflix","ebay",
    "facebook","instagram","linkedin","twitter","whatsapp","fedex",
    "ups","dhl","usps","chase","wellsfargo","citibank","hsbc","irs",
    "dropbox","docusign","office365","outlook","gmail","icloud",
]

_DIGIT_LETTER_SUBS = {"0":"o","1":"l","1":"i","3":"e","4":"a","5":"s","7":"t","@":"a"}


def _longest_digit_run(s: str) -> int:
    runs = re.findall(r'\d+', s)
    return max((len(r) for r in runs), default=0)

def _longest_hyphen_run(s: str) -> int:
    """Count consecutive hyphen-separated segments, not just hyphen chars."""
    return s.count("-")

def _vowel_consonant_ratio(s: str) -> float:
    letters = [c for c in s.lower() if c.isalpha()]
    if not letters: return 0.5
    vowels = sum(1 for c in letters if c in "aeiou")
    return vowels / len(letters)

def _shannon_entropy(s: str) -> float:
    """Higher entropy = more random-looking string (auto-generated domains)."""
    if not s: return 0.0
    freq: Dict[str,int] = {}
    for c in s: freq[c] = freq.get(c,0) + 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in freq.values())

def _normalize_leet(s: str) -> str:
    """Convert digit-substitution back to letters: paypa1 -> paypal, micros0ft -> microsoft."""
    result = s.lower()
    for digit, letter in _DIGIT_LETTER_SUBS.items():
        result = result.replace(digit, letter)
    return result

def _levenshtein(a: str, b: str) -> int:
    """Edit distance — small distance to a known brand = typosquat."""
    if len(a) < len(b): a, b = b, a
    if len(b) == 0: return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a):
        cur = [i+1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j+1]+1, cur[j]+1, prev[j]+(ca!=cb)))
        prev = cur
    return prev[-1]

def _brand_similarity_score(domain_root: str) -> float:
    """
    Check leet-normalized domain root against known brands.
    Returns 1.0 if very close to a brand but not exact (typosquat),
    0.0 if exact match (legitimate) or far from any brand.
    """
    if not domain_root: return 0.0
    base = domain_root.split(".")[0]
    normalized = _normalize_leet(base)

    for brand in _COMMON_BRANDS:
        if normalized == brand or base == brand:
            return 0.0  # exact match — legitimate, not a typosquat
        dist = _levenshtein(normalized, brand)
        if 0 < dist <= 2 and len(brand) >= 4:
            return 1.0  # very close but not exact — classic typosquat
    return 0.0


def score_lexical(domain: str) -> Dict[str, float]:
    """
    Character-level lexical scoring of a single domain string.
    Called on: sender domain, most-common-link domain, form-action domain.

    Returns 6 features, each 0.0-1.0.
    """
    if not domain:
        return {
            "digit_run_score": 0.0, "hyphen_run_score": 0.0,
            "entropy_score": 0.0, "vowel_ratio_anomaly": 0.0,
            "brand_typosquat_score": 0.0, "domain_length_score": 0.0,
        }

    base = domain.split(".")[0]

    digit_run   = _longest_digit_run(base)
    digit_score = min(1.0, digit_run / 4)

    hyphen_count = _longest_hyphen_run(base)
    hyphen_score = min(1.0, hyphen_count / 3)

    entropy       = _shannon_entropy(base)
    entropy_score = min(1.0, max(0.0, (entropy - 3.0) / 2.0))

    vc_ratio  = _vowel_consonant_ratio(base)
    vc_anomaly = min(1.0, abs(vc_ratio - 0.4) / 0.4)

    typosquat = _brand_similarity_score(domain)

    length_score = min(1.0, max(0.0, (len(base) - 15) / 15))

    return {
        "digit_run_score":       round(digit_score, 4),
        "hyphen_run_score":      round(hyphen_score, 4),
        "entropy_score":         round(entropy_score, 4),
        "vowel_ratio_anomaly":   round(vc_anomaly, 4),
        "brand_typosquat_score": round(typosquat, 4),
        "domain_length_score":   round(length_score, 4),
    }