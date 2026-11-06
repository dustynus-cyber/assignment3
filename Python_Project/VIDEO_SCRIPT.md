# Video script — Phishing URL: frontend & security (my part)

This is the part I own: the **web interface** and the **attack → defence
security evaluation**. The ML training pipeline is my teammates' backend part.

The grading rubric wants four things, and this script hits each one:
1. **Attack implemented + measured convincingly** (distributions, many runs).
2. **Defence implemented + re-measured**, showing the attack's success fall.
3. **Honest interpretation** (including where an obvious defence does *not* work).
4. **Cost of the defence** measured or clearly explained.

Keep the app running for the live demo: `./.venv/bin/python app.py` → open
http://localhost:5050. Charts and numbers: `security/results/`.

---

## 0. Opening (20s)

> "I built the frontend and the security evaluation. The idea of the product is
> simple: paste a link, and before you click it we tell you how risky it looks —
> reading only the URL, never opening the site. My security work asks the harder
> question: **how easily can an attacker fool this detector, and can we defend
> it?**"

Show the landing page. Point out the one honest promise: *we read the address
only.*

---

## 1. The detector and its weakness (30s)

> "The backend model is a decision tree over 11 structural features of the URL —
> length, number of dots, hyphens, digits, whether it uses a `.com`, and so on.
> That's cheap and explainable, but it's also the weakness: **every one of those
> features is something an attacker controls.**"

Show `security/results/tree_rules.txt` or just name a couple of features.

---

## 2. The attack — evasion (45s)  → rubric #1

> "My attack reshapes a real phishing URL so it looks structurally ordinary,
> without changing what it is. Each move is something a real attacker does:
> register the look-alike on a `.com`, drop the hyphens, use a short path, put the
> domain up front instead of a raw IP."

Show `security/attack.py` briefly, then run:

```bash
.venv/bin/python security/attack.py
```

> "I measured this as a **distribution, not a single run**: for each level of
> attacker effort I ran the random attack **30 times**. Here's the result on
> 3,000 held-out phishing URLs the model never trained on."

Show **`results/detection_vs_budget.png`** and **`results/attack_distribution.png`**.

> "Detection falls from **73% to 54%** — the attack makes the model miss nearly
> half the phishing it used to catch, just by tidying up the URL string."

---

## 3. The defence — impersonation layer (45s)  → rubric #2

> "The attacker has a dilemma, though. To fool a *person*, the URL still has to
> look like a real brand — PayPal, Microsoft, a bank. That leaves fingerprints the
> structural model ignores: punycode homographs, typosquats like `paypa1.com`, or
> a brand name sitting outside its real domain. My defence is a strict layer that
> looks for exactly those."

Show `security/defense.py`, then run:

```bash
.venv/bin/python security/defense.py "http://paypa1.com" "https://paypal.secure-login.com" "https://www.google.com"
```

**Live demo in the app** (the strongest moment):
- Click the **`paypa1.com`** example under the input. Instantly (no request
  yet) the "Real destination" card opens, the domain turns red and the warning
  *Look-alike of "paypal"* appears — that's the same logic running in the browser.
- Submit it. Point at the two columns: *"Layer 1, the model, only says
  'be careful' — about 50/100. Layer 2 found the typosquat and is marked
  **'Decided the verdict'**, so the combined result is high risk."*
- Then click **`paypal.com@account-review.net`**. Point at "Real destination":
  *"Everything before the @ is struck through — browsers ignore it. The real
  owner is account-review.net."* Submit: here **Layer 1** catches it (the `@`
  feature) and Layer 2 finds nothing. The two layers cover different tricks.

> "This is the two-layer defence: `model OR impersonation`, the exact rule I
> measured."

---

## 4. Re-measuring + honest interpretation (50s)  → rubric #2 & #3

Show **`results/impersonation_recovery.png`**.

> "On my controlled impersonation test set the structural model catches only
> **26%** — bare look-alike domains walk right past it. Adding the defence takes
> that to **75%**, at **zero** false positives on legit domains."

Now be honest (this is where marks live):

> "Two things I want to be upfront about.
>
> **First**, on the *real* dataset the defence barely helps — you can see the two
> lines sitting on top of each other in the first chart. That dataset is almost
> all generic phishing with no brand to imitate, so there's nothing for an
> impersonation layer to grab. I'm not going to pretend otherwise.
>
> **Second**, my defence has a blind spot: `paypallogin.com`, where the brand is
> glued into one word, slips past it. I *could* catch that by flagging any URL
> containing a brand substring — and that version gets 97% — but I measured its
> cost: it then wrongly flags `pineapple.com`, `amazonaws.com`, `microsoftonline.com`…
> a **17% false-positive rate**. So I deliberately shipped the stricter, zero-FP
> version."

---

## 5. Cost of the defence (20s)  → rubric #4

> "The cost is small and I measured it: on real benign URLs the defence adds only
> **half a percentage point** of false positives, it runs in **0.23 milliseconds**
> per URL with no network call, and because it only *adds* detections it can never
> lower the model's own recall. No retraining needed."

---

## 6. Frontend & wrap-up (30s)

> "On the interface side, the key idea is the **Real destination** line. Browsers
> highlight the registered domain because that's who owns the site; we do the
> same, so the user learns to read URLs, not just trust a score. The impersonation
> check runs client-side with no debounce, so the warning appears as you type and
> nothing leaves your browser. Every pasted URL is written as text, never as a
> clickable link, so the tool can't become an attack vector itself."

> "Design-wise I followed Emil Kowalski's and Apple's fluid-interface rules:
> motion uses one critically damped spring (no bounce), only transform and
> opacity animate, buttons react on press, the loading page only appears if the
> answer is slow — no artificial waiting — and everything respects the
> reduced-motion setting. It works in dark mode and on mobile."

Quickly show: the trust ring filling, the sliding underline on History filters,
dark mode, mobile width.

> "So: the attack cuts detection from 73% to 54%; the defence recovers the model's
> worst blind spot — look-alike brand domains — from 26% to 75% at basically no
> cost; and I've been honest about what it still can't do."

---

## Numbers cheat-sheet (say these confidently)

| Thing | Number |
|---|---|
| Model recall, no attack | 73% |
| Model recall, full evasion | 54% (−19pp) |
| Attack repetitions per effort level | 30 |
| Impersonation caught: model alone | 26% |
| Impersonation caught: model + defence | 75% |
| False positives added (real benign) | +0.5pp |
| False positives, "catch any brand" variant | 17% (why we didn't ship it) |
| Defence runtime | 0.23 ms/URL |

## Likely questions

- **"Is the attack realistic?"** Every transform is a real registration/hosting
  choice; it's label-preserving (still phishing), measured on held-out data.
- **"Why not retrain the model on attacked URLs?"** That's adversarial training —
  a backend change my teammates own. My defence is a complementary layer that
  needs no retraining and can't reduce existing recall.
- **"Why does the defence fail on the real set?"** It's a *targeted* defence for
  brand impersonation; that dataset is mostly generic phishing. Honest scope.
