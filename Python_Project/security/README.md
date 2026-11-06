# Security: attack and defence on the Link Check URL model

This folder holds the **security evaluation** for the phishing-URL detector: an
evasion **attack** against the trained model, an impersonation **defence**, and
an honest measurement of both, including the defence's cost. It reuses the
team's trained model (`../models/classifier.joblib`) and never retrains it.

Nothing here contacts a website. Every input is a URL *string*; the attack
rewrites strings, the defence reads strings.

```
security/
  defense.py              impersonation layer (pure functions) + CLI
  attack.py               label-preserving evasion transforms + CLI
  impersonation_suite.py  controlled brand-impersonation / benign test vectors
  evaluate.py             runs everything, writes results/
  results/                metrics (JSON/CSV) and charts (PNG)
```

Reproduce:

```bash
.venv/bin/python security/evaluate.py          # ~3.5 min, writes results/
.venv/bin/python security/defense.py "http://paypa1.com"   # try one URL
```

---

## 1. Threat model

The detector is a depth-6 decision tree over 11 **structural** URL features
(length, dot count, hyphens, `@`, digit ratio, path depth, query length, raw-IP
host, common TLD, host hyphens — see `../features.py`). It reads the URL string
only.

We assume a realistic attacker who knows the detector is lexical — a safe
assumption, since these are the standard features in published URL classifiers,
so the attacker need not see our exact model. The attacker's goal is **evasion**:
get a phishing URL past the detector while it still functions as phishing.

---

## 2. The attack: label-preserving evasion

`attack.py` applies transformations that each correspond to a real move an
attacker can make, while keeping the URL a phishing URL (label preserving):

| Transform | Real-world action | Feature it lowers |
|---|---|---|
| `use_common_tld` | register the look-alike on a `.com` | `common_tld` |
| `remove_hyphens` | register a no-hyphen variant | `hyphen_count`, `host_hyphens` |
| `remove_at` | drop the `user@host` credential trick | `at_count` |
| `drop_query` / `shorten_path` | use a short landing path | `query_length`, `path_depth`, `url_length` |
| `reduce_digits` | strip digits from the path | `digit_ratio` |
| `collapse_subdomains` | put the real domain up front | `dot_count` |
| `ip_to_domain` | swap a raw IP for a short domain | `has_ip` |

The attacker's **effort budget** = how many transforms they apply. We measure
evasion as a **distribution**: for each budget we run the random attack **30
times** with different seeds and record the spread (not a single run).

### Results (real held-out test set: 3,000 phishing, 3,000 benign)

| Attacker effort | Model recall (mean of 30 runs) |
|---|---|
| 0 (untouched) | **0.730** |
| 2 transforms | 0.671 |
| 4 transforms | 0.621 |
| 6 transforms | 0.576 |
| 8 (all) | **0.538** |

The attack removes **~19 points of recall** (0.730 → 0.538): at full effort the
model misses nearly half of phishing it used to catch. See
`results/detection_vs_budget.png` and `results/attack_distribution.png`.

---

## 3. The defence: impersonation-signal layer

`defense.py` adds a second, independent check. The idea is the attacker's
**dilemma**: to fool a *person*, a phishing URL must still look like a brand,
and that leaves fingerprints the structural features ignore:

- **Punycode / IDN** homographs (`xn--pypal-4ve.com`)
- **Non-ASCII** look-alike characters in the host
- A **brand token outside its real registrable domain** (`paypal.secure-login.com`)
- **Typosquats** within one edit (after folding look-alikes) of a brand (`paypa1.com`)

It is deliberately **strict** — it fires only on *strong* signals — to keep
false positives low. Weak signals (abused TLD, deep subdomains) are reported but
never flag on their own. The combined detector is `model OR defence`.

The same logic runs live in the browser (`../static/defense.js`) so users get an
instant warning; `defense.py` is the copy we measure here.

---

## 4. Does the defence work? — two honest halves

### Part 1 — on the real dataset, the defence barely helps

On the real test set the combined detector recovers essentially **nothing**
(full-evasion recall 0.538 → 0.538; +0.2pp across the curve). This is an honest
negative: this dataset is almost all **generic** phishing (compromised hosts,
random domains) with no brand to anchor on. An impersonation defence has nothing
to grab. We report it rather than hide it. *(This is why the two lines in
`detection_vs_budget.png` sit on top of each other.)*

### Part 2 — on brand impersonation, the defence recovers the model's blind spot

Real phishing that steals credentials is dominated by brand impersonation
(PayPal, Microsoft, banks), which the dataset under-represents. So we built a
controlled suite (`impersonation_suite.py`): brand-impersonation URLs shaped into
the model's blind spot — we verified the model treats a **bare `.com` domain** as
benign but flags almost anything with a path or extra subdomain (even
`login.paypal.com`), so every vector is a bare domain.

Controlled suite (95 impersonation URLs, 36 benign):

| Detector | Impersonation caught | Benign wrongly flagged |
|---|---|---|
| Structural model only | **0.26** | 0.00 |
| Model + token defence (shipped) | **0.75** | **0.00** |
| Flag any visible brand (stricter) | 0.97 | 0.17 |

Per technique (`results/impersonation_breakdown.csv`):

| Pattern | Example | Model | Defence |
|---|---|---|---|
| hyphen | `paypal-account.com` | 0.08 | **1.00** |
| typosquat | `paypa1.com` | 0.00 | **1.00** |
| punycode | `xn--...com` | 1.00 | **1.00** |
| concatenation | `paypallogin.com` | 0.00 | **0.00** |

The defence turns the model's 0.26 into 0.75 **at zero false positives** on the
benign set — see `results/impersonation_recovery.png`.

### Honest limitations (reported, not hidden)

1. **Concatenation is a blind spot.** `paypallogin.com` glues the brand into one
   label, so the token-based defence misses it (0.00). The stricter "flag any
   visible brand substring" variant catches it (0.97) — but it also flags
   `pineapple.com`, `amazonaws.com`, `microsoftonline.com`… costing **17% false
   positives**. We measured that and chose to ship the zero-FP token version.
2. **The model "catches" punycode for the wrong reason.** It flags `xn--…` hosts
   because the `xn--` prefix adds hyphens (a feature it uses), not because it
   understands homographs — an attacker picking a hyphen-free homograph would slip
   past the model but not the defence.
3. **The defence does nothing for generic phishing** (Part 1). It is a targeted
   layer for the highest-harm class, not a general fix.

---

## 5. Cost of the defence

| Cost | Value |
|---|---|
| Added false positives on real benign URLs | **+0.5pp** (0.320 → 0.326) |
| False positives on the controlled benign set | **0.0** |
| Runtime per URL | **0.23 ms** (pure string ops, no network) |

The defence is cheap: sub-millisecond, no model retraining, and it only *adds*
detections, so it can never lower the model's own recall.

---

## 6. One-line conclusion

A lexical phishing model is easy to evade by flattening URL structure
(−19pp recall). A strict impersonation layer closes the model's worst blind spot
— bare-domain brand look-alikes — recovering 0.26 → 0.75 detection at zero false
positives and 0.23 ms/URL, while honestly leaving concatenated squats and
generic phishing unsolved.
