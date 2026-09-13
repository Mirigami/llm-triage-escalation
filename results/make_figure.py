"""
Figure 1: the two contrasts that carry the paper.

An earlier version plotted all six conditions against three models. It showed
everything and communicated nothing: the reader had to decode A to F before the
picture meant anything. The full six-condition numbers belong in a table, and
are in one. A figure should carry one message.

So this is two panels, each asking one question in plain words:

  left   can the model tell an intrusion from innocent activity?   (flat lines)
  right  does calling it the organisation's own test lab change the answer?

Slope form, because the quantity of interest is the CHANGE between two
conditions, not the level of six. Identity is carried by marker shape as well as
hue, so it survives a greyscale printer.

Run:  python3 results/make_figure.py
"""

import json
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "results" / "figure1_escalation.png"
RNG = np.random.default_rng(20260912)
B_REPS = 10_000

SERIES = [
    ("results.jsonl",         "Sonnet 4-5", "#2a78d6", "o"),
    ("results_sonnet5.jsonl", "Sonnet 5",   "#eb6834", "s"),
    ("results_m2.jsonl",      "Haiku 4-5",  "#1baf7a", "^"),
]

PANELS = [
    ("Can it tell an intrusion from a busy Tuesday?",
     [("B", "real\nintrusion"), ("C", "innocent activity,\nsame shape")]),
    ("Does calling it our own test lab change the answer?",
     [("B", "unattributed"), ("D", "\"our model\nevaluation pool\"")]),
]

SURFACE, SECONDARY, MUTED = "#fcfcfb", "#52514e", "#898781"
GRID, AXIS, INK = "#e1e0d9", "#c3c2b7", "#0b0b0b"


def rates(path, cond):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    acc = {}
    for r in rows:
        if r.get("cond") == cond and r.get("decision"):
            acc.setdefault(r["sid"], []).append(1 if r["decision"] != "HOLD" else 0)
    return np.array([np.mean(v) for v in acc.values()]) if acc else None


def mean_ci(v):
    idx = RNG.integers(0, len(v), size=(B_REPS, len(v)))
    d = v[idx].mean(axis=1)
    return float(v.mean()), float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))


def spread(items, min_gap=0.055):
    """Nudge near-coincident labels apart so they never overlap.

    Two models sitting at 1.00 and 0.98 are two points apart on the scale but
    their labels are taller than that, so without this they collide.
    """
    items = sorted(items, key=lambda t: t[0])
    ys = [it[0] for it in items]
    for i in range(1, len(ys)):
        if ys[i] - ys[i - 1] < min_gap:
            ys[i] = ys[i - 1] + min_gap
    excess = max(ys) - 1.09 if ys else 0
    if excess > 0:
        ys = [y - excess for y in ys]
    # (label position, colour, the value the label states)
    return [(ys[i], items[i][1], items[i][0]) for i in range(len(items))]


fig, axes = plt.subplots(1, 2, figsize=(7.2, 3.9), dpi=300, sharey=True)
fig.patch.set_facecolor(SURFACE)

for ax, (title, steps) in zip(axes, PANELS):
    ax.set_facecolor(SURFACE)
    xs = [0, 1]
    left_labels, right_labels = [], []
    for fname, label, colour, marker in SERIES:
        path = ROOT / "results" / fname
        if not path.exists():
            continue
        pts = []
        for cond, _ in steps:
            v = rates(path, cond)
            if v is None or not len(v):
                pts = []
                break
            pts.append(mean_ci(v))
        if not pts:
            continue
        ys = [p[0] for p in pts]
        ax.plot(xs, ys, color=colour, linewidth=1.6, zorder=2, alpha=0.9)
        for x, (m, lo, hi) in zip(xs, pts):
            ax.plot([x, x], [lo, hi], color=colour, linewidth=1.1, zorder=2)
            ax.plot([x], [m], marker=marker, markersize=7, color=colour,
                    markeredgecolor=SURFACE, markeredgewidth=1.2, zorder=3)
        left_labels.append((pts[0][0], colour))
        right_labels.append((pts[1][0], colour))

    # value at both ends, collision-avoided, so every number is legible
    for side_labels, x, ha, dx in ((left_labels, 0, "right", -12),
                                   (right_labels, 1, "left", 12)):
        for y_adj, colour, value in spread(side_labels):
            ax.annotate(f"{value:.2f}", (x, y_adj), textcoords="offset points",
                        xytext=(dx, -3.5), ha=ha, fontsize=8,
                        color=colour, fontweight="bold")

    ax.set_title(title, fontsize=9.5, color=INK, pad=12, loc="left")
    ax.set_xticks(xs)
    ax.set_xticklabels([lbl for _, lbl in steps], fontsize=8.5, color=SECONDARY)
    ax.set_xlim(-0.55, 1.55)
    ax.set_ylim(-0.05, 1.12)
    ax.yaxis.grid(True, color=GRID, linewidth=0.6)
    ax.xaxis.grid(False)
    ax.set_axisbelow(True)
    for side in ("top", "right", "left"):
        ax.spines[side].set_visible(False)
    ax.spines["bottom"].set_color(AXIS)
    ax.spines["bottom"].set_linewidth(0.8)
    ax.tick_params(length=0, pad=7)

axes[0].set_yticks([0, 0.25, 0.5, 0.75, 1.0])
axes[0].set_yticklabels(["0", "25%", "50%", "75%", "100%"], fontsize=8, color=MUTED)
axes[0].set_ylabel("escalation rate", fontsize=9, color=SECONDARY)

handles = [Line2D([0], [0], marker=mk, color=col, linewidth=1.6,
                  markersize=7, markeredgecolor=SURFACE, markeredgewidth=1.2, label=lbl)
           for f, lbl, col, mk in SERIES if (ROOT / "results" / f).exists()]
leg = fig.legend(handles=handles, loc="lower center", ncol=3, frameon=False,
                 fontsize=8.5, bbox_to_anchor=(0.5, -0.04),
                 handletextpad=0.5, columnspacing=2.2)
for t in leg.get_texts():
    t.set_color(SECONDARY)

fig.tight_layout()
fig.savefig(OUT, facecolor=SURFACE, bbox_inches="tight")
print(f"wrote {OUT}")

try:
    from PIL import Image
    gp = OUT.with_name("figure1_escalation_greyscale.png")
    Image.open(OUT).convert("L").save(gp)
    print(f"wrote {gp}  (check identity still reads with no colour)")
except ImportError:
    print("Pillow not installed; skipping the greyscale proof")
