"""Measure the attack and the defence, then write every number and chart used
in the report and the video.

The evaluation has two honest halves:

  PART 1 - Real held-out data (does this generalise?)
     The model never trained on these URLs. We run the evasion attack as a
     DISTRIBUTION (many effort budgets x 30 repetitions) and show how detection
     falls. We add the impersonation defence and re-measure. On this dataset the
     defence barely helps -- it is almost all generic phishing with no brand to
     anchor on -- and we report that plainly.

  PART 2 - Controlled impersonation suite (does the defence work where it should?)
     Purpose-built brand-impersonation URLs, each already shaped to look
     structurally ordinary, plus matched benign URLs. Here the structural model
     is blind and the defence does the work -- except for one pattern
     (concatenation) that it misses, which we show rather than hide. We also
     measure a stricter "flag any visible brand" variant and its false-positive
     cost, to justify shipping the token-based version.

Outputs (security/results/): attack_defense.json, four PNG charts,
evasion_examples.csv, impersonation_breakdown.csv.
"""
import sys
import json
import time
import random
from pathlib import Path

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent        # Python_Project/
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from features import make_features                    # noqa: E402  (team's module)
import attack                                         # noqa: E402
import defense                                        # noqa: E402
import impersonation_suite as suite                   # noqa: E402

OUT = Path(__file__).resolve().parent / 'results'
TRIALS = 30
SEED = 42
BUDGETS = list(range(0, len(attack.TRANSFORMS) + 1))


# --- detectors ---------------------------------------------------------------
def model_flags(model, feats, urls):
    if not urls:
        return np.array([], dtype=int)
    return model.predict(make_features(urls)[feats]).astype(int)


def defense_flags(urls):
    return np.array([int(defense.flags_as_phishing(u)) for u in urls], dtype=int)


def brand_visible_flags(urls):
    return np.array([int(defense.brand_visible(u)) for u in urls], dtype=int)


def rate(flags):
    return float(np.mean(flags)) if len(flags) else 0.0


# --- PART 1: real held-out data ---------------------------------------------
def part1_real_data(model, feats, phishing, benign):
    base_model = model_flags(model, feats, phishing)
    baseline_recall = rate(base_model)

    model_curve, defended_curve = {}, {}
    for budget in BUDGETS:
        trials = 1 if budget in (0, len(attack.TRANSFORMS)) else TRIALS
        m_rates, d_rates = [], []
        for trial in range(trials):
            rng = random.Random(SEED + trial)
            evaded = [attack.random_attack(u, rng, budget) for u in phishing]
            m = model_flags(model, feats, evaded)
            d = np.maximum(m, defense_flags(evaded))
            m_rates.append(rate(m))
            d_rates.append(rate(d))
        model_curve[budget] = m_rates
        defended_curve[budget] = d_rates
        print(f'  budget {budget}: model {np.mean(m_rates):.3f}  defended {np.mean(d_rates):.3f}')

    evaded_full = [attack.evade(u) for u in phishing]
    full_model = model_flags(model, feats, evaded_full)
    full_def = np.maximum(full_model, defense_flags(evaded_full))

    # Cost on real benign URLs + runtime of the defence check.
    bm = model_flags(model, feats, benign)
    bd = defense_flags(benign)
    start = time.perf_counter()
    for u in phishing + benign:
        defense.flags_as_phishing(u)
    per_url_ms = 1000 * (time.perf_counter() - start) / (len(phishing) + len(benign))

    save_examples(phishing, evaded_full, full_model)
    plot_curve(model_curve, defended_curve)
    plot_distribution(model_curve)

    return {
        'baseline_model_recall': baseline_recall,
        'full_evasion_model_recall': rate(full_model),
        'full_evasion_defended_recall': rate(full_def),
        'recall_lost_to_attack': baseline_recall - rate(full_model),
        'recall_recovered_by_defense': rate(full_def) - rate(full_model),
        'cost': {
            'model_false_positive_rate': rate(bm),
            'defended_false_positive_rate': rate(np.maximum(bm, bd)),
            'added_false_positives': rate(np.maximum(bm, bd)) - rate(bm),
            'defense_runtime_ms_per_url': round(per_url_ms, 4),
        },
        'curve_model_mean': {str(b): float(np.mean(model_curve[b])) for b in BUDGETS},
        'curve_defended_mean': {str(b): float(np.mean(defended_curve[b])) for b in BUDGETS},
    }, model_curve


# --- PART 2: controlled impersonation suite ---------------------------------
def part2_impersonation(model, feats):
    rows = suite.impersonation_urls()
    imp_urls = [r[0] for r in rows]
    patterns = [r[2] for r in rows]
    benign = suite.benign_urls()

    m = model_flags(model, feats, imp_urls)              # structural model alone
    d = defense_flags(imp_urls)                          # token-based defence
    a = brand_visible_flags(imp_urls)                    # stricter "any brand" variant
    combined = np.maximum(m, d)

    # Per-pattern breakdown so we can name exactly what is caught and missed.
    breakdown = []
    for pattern in sorted(set(patterns)):
        idx = [i for i, p in enumerate(patterns) if p == pattern]
        breakdown.append({
            'pattern': pattern, 'count': len(idx),
            'model_recall': rate(m[idx]),
            'defense_recall': rate(d[idx]),
            'brand_visible_recall': rate(a[idx]),
        })
    pd.DataFrame(breakdown).to_csv(OUT / 'impersonation_breakdown.csv', index=False)

    bm = model_flags(model, feats, benign)
    bd = defense_flags(benign)
    ba = brand_visible_flags(benign)

    plot_impersonation(m, d, a, bm, bd, ba)

    return {
        'impersonation_count': len(imp_urls),
        'benign_count': len(benign),
        'model_recall': rate(m),
        'defense_recall': rate(d),
        'defended_recall': rate(combined),
        'brand_visible_recall': rate(a),
        'false_positives': {
            'model': rate(bm),
            'token_defense': rate(bd),
            'brand_visible_defense': rate(ba),
        },
        'by_pattern': breakdown,
    }


# --- examples ----------------------------------------------------------------
def save_examples(phishing, evaded_full, full_model, n=12):
    before = None  # computed lazily only for rows we keep (keeps this cheap)
    rows = []
    for orig, ev, after in zip(phishing, evaded_full, full_model):
        if after == 0:                        # model now misses the evaded URL
            rows.append({'original': orig, 'evaded': ev, 'model_after': int(after),
                         'defense_catches_evaded': int(defense.flags_as_phishing(ev))})
        if len(rows) >= n:
            break
    pd.DataFrame(rows).to_csv(OUT / 'evasion_examples.csv', index=False)


# --- plotting ----------------------------------------------------------------
INK, GRID, MODEL_C, DEF_C, AGG_C = '#1c1f23', '#e6e9ec', '#c0392b', '#1f7a4d', '#b7791f'


def _style(ax):
    ax.spines[['top', 'right']].set_visible(False)
    ax.spines[['left', 'bottom']].set_color(GRID)
    ax.tick_params(colors=INK, labelsize=10)
    ax.yaxis.grid(True, color=GRID, linewidth=1)
    ax.set_axisbelow(True)


def plot_curve(model_curve, defended_curve):
    b = sorted(model_curve)
    mm = np.array([np.mean(model_curve[x]) for x in b])
    ms = np.array([np.std(model_curve[x]) for x in b])
    dm = np.array([np.mean(defended_curve[x]) for x in b])
    fig, ax = plt.subplots(figsize=(7.2, 4.4)); _style(ax)
    ax.fill_between(b, mm - ms, mm + ms, color=MODEL_C, alpha=0.12)
    ax.plot(b, mm, color=MODEL_C, marker='o', lw=2.2, label='Structural model only')
    ax.plot(b, dm, color=DEF_C, marker='s', lw=2.2, label='Model + impersonation defence')
    ax.set_xlabel('Attacker effort (transformations applied)')
    ax.set_ylabel('Phishing detection rate (recall)')
    ax.set_ylim(0, 1)
    ax.set_title('Real data: evasion erodes detection; the defence adds little here',
                 color=INK, fontsize=11.5, pad=12)
    ax.legend(frameon=False, fontsize=10)
    fig.tight_layout(); fig.savefig(OUT / 'detection_vs_budget.png', dpi=160); plt.close(fig)


def plot_distribution(model_curve):
    b = [x for x in sorted(model_curve) if len(model_curve[x]) > 1]
    fig, ax = plt.subplots(figsize=(7.2, 4.4)); _style(ax)
    bp = ax.boxplot([model_curve[x] for x in b], positions=b, widths=0.6,
                    patch_artist=True, medianprops=dict(color=INK, lw=1.5))
    for box in bp['boxes']:
        box.set(facecolor=MODEL_C, alpha=0.22, edgecolor=MODEL_C)
    for part in ('whiskers', 'caps'):
        for item in bp[part]:
            item.set_color(MODEL_C)
    ax.set_xlabel('Attacker effort (transformations applied)')
    ax.set_ylabel(f'Detection rate across {TRIALS} repetitions')
    ax.set_ylim(0, 1)
    ax.set_title('Each budget is a distribution, not a single run', color=INK, fontsize=11.5, pad=12)
    fig.tight_layout(); fig.savefig(OUT / 'attack_distribution.png', dpi=160); plt.close(fig)


def plot_impersonation(m, d, a, bm, bd, ba):
    groups = ['Structural\nmodel', 'Model + token\ndefence', 'Flag any visible\nbrand (stricter)']
    recall = [rate(m), rate(np.maximum(m, d)), rate(np.maximum(m, a))]
    fp = [rate(bm), rate(bd), rate(ba)]
    x = np.arange(len(groups))
    fig, ax = plt.subplots(figsize=(7.4, 4.4)); _style(ax)
    ax.bar(x - 0.2, recall, 0.4, color=DEF_C, alpha=0.85, label='Impersonation caught (recall)')
    ax.bar(x + 0.2, fp, 0.4, color=AGG_C, alpha=0.85, label='Benign wrongly flagged (FP)')
    for i, (r, f) in enumerate(zip(recall, fp)):
        ax.text(i - 0.2, r + 0.02, f'{r:.2f}', ha='center', fontsize=9, color=INK)
        ax.text(i + 0.2, f + 0.02, f'{f:.2f}', ha='center', fontsize=9, color=INK)
    ax.set_xticks(x); ax.set_xticklabels(groups)
    ax.set_ylim(0, 1.05); ax.set_ylabel('Rate')
    ax.set_title('Controlled impersonation suite: detection vs. its cost',
                 color=INK, fontsize=11.5, pad=12)
    ax.legend(frameon=False, fontsize=10)
    fig.tight_layout(); fig.savefig(OUT / 'impersonation_recovery.png', dpi=160); plt.close(fig)


def run():
    OUT.mkdir(exist_ok=True)
    saved = joblib.load(ROOT / 'models/classifier.joblib')   # team's trained model
    model, feats = saved['model'], saved['features']
    split = pd.read_csv(ROOT / 'results/split.csv')
    test = split[split['split'] == 'test']
    phishing = test[test['label'] == 1]['url'].tolist()
    benign = test[test['label'] == 0]['url'].tolist()

    print(f'PART 1 - real data: {len(phishing)} phishing, {len(benign)} benign')
    real, _ = part1_real_data(model, feats, phishing, benign)
    print('PART 2 - controlled impersonation suite')
    imp = part2_impersonation(model, feats)
    print(f'  model {imp["model_recall"]:.2f} -> defended {imp["defended_recall"]:.2f} recall '
          f'(token FP {imp["false_positives"]["token_defense"]:.3f})')

    summary = {'trials_per_budget': TRIALS,
               'part1_real_data': real,
               'part2_impersonation_suite': imp}
    (OUT / 'attack_defense.json').write_text(json.dumps(summary, indent=2))
    print(f'\nWrote results to {OUT}')
    return summary


if __name__ == '__main__':
    run()
