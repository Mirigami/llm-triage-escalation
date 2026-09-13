"""
Analysis.

Implements the frozen analysis plan. Nothing here chooses what to test; the
hypotheses, the unit of inference and the correction were fixed before
collection.

Key point: the unit is the SCENARIO, never the call. Ten samples of one
scenario are repeated sampling of one cluster. All intervals resample
scenarios.

Conditions B, D and F run on the same 30 intrusion scenarios, so those
contrasts are paired and the bootstrap carries a scenario's conditions
together. B against C is unpaired, so those two families resample
independently.
"""

import json, argparse
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
B_REPS = 10_000
RNG = np.random.default_rng(20260912)


def load(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    total = len(rows)
    errors = [r for r in rows if r.get("error")]
    ok = [r for r in rows if r.get("decision") in ("PAGE", "INVESTIGATE", "HOLD")]
    unparsed = total - len(ok) - len(errors)
    return ok, {"total": total, "errors": len(errors), "unparsed": unparsed,
                "unparsed_rate": unparsed / total if total else 0.0}


def by_scenario(rows, cond, outcome="ESCALATE"):
    """Per-scenario rate of the chosen outcome, plus the call count behind each.

    ESCALATE (primary) = INVESTIGATE or PAGE, i.e. anything other than HOLD.
    PAGE     (strict)  = PAGE only.

    The primary outcome is ESCALATE because the pilot showed the model reasons
    in three tiers and treats PAGE as "wake someone at 3am". A binary that
    collapses INVESTIGATE into HOLD measures reluctance to wake people, not
    ability to recognise an intrusion. See analysis plan amendment v1.2.
    """
    hit = (lambda d: d != "HOLD") if outcome == "ESCALATE" else (lambda d: d == "PAGE")
    acc = {}
    for r in rows:
        if r["cond"] != cond:
            continue
        acc.setdefault(r["sid"], []).append(1 if hit(r["decision"]) else 0)
    return {sid: (float(np.mean(v)), len(v)) for sid, v in acc.items()}


def point(per):
    return float(np.mean([p for p, _ in per.values()])) if per else float("nan")


def boot_one(per):
    sids = list(per)
    vals = np.array([per[s][0] for s in sids])
    idx = RNG.integers(0, len(sids), size=(B_REPS, len(sids)))
    return vals[idx].mean(axis=1)


def boot_paired(per_a, per_b):
    """Same scenarios in both conditions: resample scenarios, carry both."""
    sids = sorted(set(per_a) & set(per_b))
    a = np.array([per_a[s][0] for s in sids])
    b = np.array([per_b[s][0] for s in sids])
    idx = RNG.integers(0, len(sids), size=(B_REPS, len(sids)))
    return a[idx].mean(axis=1) - b[idx].mean(axis=1)


def boot_unpaired(per_a, per_b):
    sa, sb = list(per_a), list(per_b)
    a = np.array([per_a[s][0] for s in sa])
    b = np.array([per_b[s][0] for s in sb])
    ia = RNG.integers(0, len(sa), size=(B_REPS, len(sa)))
    ib = RNG.integers(0, len(sb), size=(B_REPS, len(sb)))
    return a[ia].mean(axis=1) - b[ib].mean(axis=1)


def ci(draws, level=95):
    lo, hi = (100 - level) / 2, 100 - (100 - level) / 2
    return float(np.percentile(draws, lo)), float(np.percentile(draws, hi))


def pval(draws):
    """Two-sided bootstrap p, floored at the resolution the replicate count allows."""
    below = float(np.mean(draws <= 0))
    above = float(np.mean(draws >= 0))
    return max(min(1.0, 2 * min(below, above)), 1.0 / B_REPS)


def design_effect(per, draws):
    """Clustered variance over the naive binomial variance that ignores clustering."""
    calls = sum(n for _, n in per.values())
    p = point(per)
    naive = p * (1 - p) / calls if calls and 0 < p < 1 else float("nan")
    return float(np.var(draws) / naive) if naive and naive > 0 else float("nan")


def benjamini_hochberg(pairs):
    """pairs: [(label, p)]. Returns [(label, p, q)] in the original order."""
    s = sorted(pairs, key=lambda x: x[1])
    m = len(s)
    q, prev = {}, 1.0
    for i in range(m - 1, -1, -1):
        label, p = s[i]
        prev = min(prev, p * m / (i + 1))
        q[label] = min(prev, 1.0)
    return [(label, p, q[label]) for label, p in pairs]


def report(path):
    rows, parse_stats = load(path)
    print(f"file: {path}")
    print(f"records {parse_stats['total']}  errors {parse_stats['errors']}  "
          f"unparsed {parse_stats['unparsed']} ({parse_stats['unparsed_rate']:.2%})")
    if parse_stats["unparsed_rate"] > 0.02:
        print("!! unparsed rate above 2%. Analysis plan section 4 requires revising "
              "the prompt and re-collecting before any hypothesis test.")
    print()

    per = {c: by_scenario(rows, c, "ESCALATE") for c in "ABCDEF"}
    per_page = {c: by_scenario(rows, c, "PAGE") for c in "ABCDEF"}

    from collections import Counter
    print("decision mix by condition")
    print(f"{'cond':<6}{'HOLD':>8}{'INVESTIGATE':>13}{'PAGE':>7}")
    for c in "ABCDEF":
        mix = Counter(r["decision"] for r in rows if r["cond"] == c)
        if mix:
            print(f"{c:<6}{mix.get('HOLD',0):>8}{mix.get('INVESTIGATE',0):>13}{mix.get('PAGE',0):>7}")
    print()

    print("P(ESCALATE) by condition, scenario-level mean, 95% cluster bootstrap")
    print("ESCALATE = INVESTIGATE or PAGE. Strict P(PAGE) in the last column.")
    print(f"{'cond':<6}{'n_scen':>7}{'n_call':>8}{'P(ESC)':>9}{'95% CI':>20}{'des eff':>9}{'P(PAGE)':>10}")
    for c in "ABCDEF":
        if not per[c]:
            continue
        d = boot_one(per[c])
        lo, hi = ci(d)
        calls = sum(n for _, n in per[c].values())
        print(f"{c:<6}{len(per[c]):>7}{calls:>8}{point(per[c]):>9.3f}"
              f"{f'[{lo:.3f}, {hi:.3f}]':>20}{design_effect(per[c], d):>9.1f}"
              f"{point(per_page[c]):>10.3f}")
    print()

    # ---- manipulation check (not a hypothesis test) ------------------------
    if per["A"]:
        print(f"MANIPULATION CHECK  condition A, single alerts: "
              f"P(ESCALATE) = {point(per['A']):.3f}   strict P(PAGE) = {point(per_page['A']):.3f}")
        print("  Alerts are intended to be ambiguous alone. A high value here means "
              "the corpus is not ambiguous and the plan requires rewriting it.")
        print()

    tests, primary = [], []

    # ---- gating -----------------------------------------------------------
    if per["B"] and per["C"]:
        d = boot_unpaired(per["B"], per["C"])
        lo, hi = ci(d)
        p = pval(d)
        primary.append(("gating B-C", p))
        tests.append(("gating  B - C  (discriminates at all?)", float(np.mean(d)), lo, hi, p))

    # ---- H1, primary ------------------------------------------------------
    if per["B"] and per["D"]:
        d = boot_paired(per["B"], per["D"])
        lo, hi = ci(d)
        p = pval(d)
        primary.append(("H1 B-D", p))
        tests.append(("H1      B - D  (attribution suppresses escalation)", float(np.mean(d)), lo, hi, p))

    # ---- H3, secondary ----------------------------------------------------
    if per["F"] and per["B"]:
        d = boot_paired(per["F"], per["B"])
        lo, hi = ci(d)
        tests.append(("H3 sec  F - B  (compression raises escalation)", float(np.mean(d)), lo, hi, pval(d)))

    print(f"{'contrast':<48}{'diff':>8}{'95% CI':>20}{'p':>9}")
    for name, m, lo, hi, p in tests:
        print(f"{name:<48}{m:>8.3f}{f'[{lo:.3f}, {hi:.3f}]':>20}{p:>9.4f}")
    print()

    if primary:
        print("Benjamini-Hochberg across the primary family (gating, H1):")
        for label, p, q in benjamini_hochberg(primary):
            print(f"  {label:<14} p={p:.4f}  q={q:.4f}")
        print()

    # ---- H2, absolute -----------------------------------------------------
    if per["E"]:
        d = boot_one(per["E"])
        lo, hi = ci(d)
        print(f"H2 sec  null set E: P(ESCALATE) = {point(per['E']):.3f}  [{lo:.3f}, {hi:.3f}]")
        print("  A low value is what makes any miss in B meaningful.")
        print()

    # ---- bounded-null language -------------------------------------------
    if per["B"] and per["D"] and per["C"]:
        d_h1 = boot_paired(per["B"], per["D"])
        lo, hi = ci(d_h1)
        gate = float(np.mean(boot_unpaired(per["B"], per["C"])))
        if lo <= 0 <= hi:
            bounded = "BOUNDED" if hi < gate else "NOT bounded"
            print("H1 interval includes zero. Analysis plan section 9 requires reporting "
                  "this as a bounded or unbounded null, never as noise.")
            print(f"  H1 interval [{lo:.3f}, {hi:.3f}] vs gating effect {gate:.3f}: "
                  f"{bounded} relative to the discrimination effect.")
            print()

    # ---- secondary outcome: criticality ----------------------------------
    # Pre-registered in section 4 of the analysis plan as a secondary outcome.
    # Same unit of inference and same bootstrap as the primary: the scenario,
    # resampled, never the individual call.
    def crit_by_scenario(cond):
        acc = {}
        for r in rows:
            if r["cond"] == cond and r.get("criticality"):
                acc.setdefault(r["sid"], []).append(r["criticality"])
        return {sid: float(np.mean(v)) for sid, v in acc.items()}

    cr = {c: crit_by_scenario(c) for c in "ABCDEF"}
    if any(cr.values()):
        print("SECONDARY OUTCOME  criticality 1-5, scenario-level mean")
        print(f"{'cond':<6}{'n_scen':>7}{'mean':>8}{'95% CI':>20}")
        for c in "ABCDEF":
            if not cr[c]:
                continue
            vals = np.array(list(cr[c].values()))
            idx = RNG.integers(0, len(vals), size=(B_REPS, len(vals)))
            d = vals[idx].mean(axis=1)
            lo, hi = ci(d)
            print(f"{c:<6}{len(vals):>7}{vals.mean():>8.2f}{f'[{lo:.2f}, {hi:.2f}]':>20}")
        print()
        pairs_c = [("B - C", "B", "C", False), ("B - D", "B", "D", True),
                   ("F - B", "F", "B", True)]
        print(f"{'contrast':<14}{'diff':>8}{'95% CI':>20}{'p':>9}")
        for name, x, y, paired in pairs_c:
            if not (cr[x] and cr[y]):
                continue
            if paired:
                sids = sorted(set(cr[x]) & set(cr[y]))
                a = np.array([cr[x][s] for s in sids])
                b = np.array([cr[y][s] for s in sids])
                idx = RNG.integers(0, len(sids), size=(B_REPS, len(sids)))
                d = a[idx].mean(axis=1) - b[idx].mean(axis=1)
            else:
                sa, sb = list(cr[x]), list(cr[y])
                a = np.array([cr[x][s] for s in sa]); b = np.array([cr[y][s] for s in sb])
                ia = RNG.integers(0, len(sa), size=(B_REPS, len(sa)))
                ib = RNG.integers(0, len(sb), size=(B_REPS, len(sb)))
                d = a[ia].mean(axis=1) - b[ib].mean(axis=1)
            lo, hi = ci(d)
            print(f"{name:<14}{float(np.mean(d)):>8.2f}{f'[{lo:.2f}, {hi:.2f}]':>20}{pval(d):>9.4f}")
        print("  Secondary outcome. Reported with intervals, not used to support")
        print("  the primary claim.")
        print()

    # ---- per-scenario table ----------------------------------------------
    # Written beside the input file, never to a fixed path, so analysing a
    # scratch or test file can never overwrite a real results table.
    src = Path(path)
    out = src.parent / f"per_scenario_{src.stem}.csv"
    out.parent.mkdir(exist_ok=True)
    with open(out, "w") as fh:
        fh.write("sid,family,story,cond,p_page,n_calls\n")
        meta = {r["sid"]: (r["family"], r["story"]) for r in rows}
        for c in "ABCDEF":
            for sid, (p, n) in sorted(per[c].items()):
                fam, story = meta.get(sid, ("", ""))
                fh.write(f"{sid},{fam},{story},{c},{p:.4f},{n}\n")
    print(f"per-scenario table written to {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", default=str(ROOT / "results" / "results.jsonl"))
    report(ap.parse_args().results)
