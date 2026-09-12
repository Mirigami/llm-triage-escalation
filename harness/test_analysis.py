"""
Unit tests for the analysis chain.

Two things must be true before the analysis is trusted with real data:

  1. It recovers a planted effect.
  2. It does NOT fire when both conditions are drawn from the same distribution.

The second is the one that matters. An analysis that finds effects in pure
noise would find one in the real data too.

Run:  python3 harness/test_analysis.py
"""

import json, subprocess, sys, tempfile, re
from pathlib import Path
import numpy as np

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness"))

RNG = np.random.default_rng(7)
SCEN = json.load(open(ROOT / "corpus" / "scenarios.json"))["scenarios"]
INTR = [s for s in SCEN if s["family"] == "INTRUSION"]
BEN = [s for s in SCEN if s["family"] == "BENIGN"]
NUL = [s for s in SCEN if s["family"] == "NULL"]


def synth(path, p_b, p_c, p_d, p_e, reps=10):
    """Write a synthetic results file and return the effect actually present.

    Each scenario gets its own rate drawn around the condition mean, so the data
    has genuine between-scenario variance. Without that the design effect would
    be 1 and the clustering code would never be exercised.

    The nominal means are only a target. Clipping and sampling mean the realised
    effect differs, so the realised per-scenario rates are returned and the tests
    assert against those. Asserting against the nominal value would test this
    generator rather than the analysis.
    """
    rows, realised = [], {}
    def block(scens, cond, p_mean):
        ps = []
        for s in scens:
            p_s = float(np.clip(RNG.normal(p_mean, 0.14), 0.01, 0.99))
            ps.append(p_s)
            for r in range(reps):
                rows.append({
                    "key": f"{cond}|{s['sid']}|-|{r}", "cond": cond, "sid": s["sid"],
                    "family": s["family"], "story": s["story"], "alert": None, "rep": r,
                    "decision": "PAGE" if RNG.random() < p_s else "HOLD",
                    "criticality": 3, "raw": "synthetic",
                })
        realised[cond] = float(np.mean(ps))
    block(INTR, "B", p_b); block(BEN, "C", p_c)
    block(INTR, "D", p_d); block(NUL, "E", p_e)
    block(INTR, "F", p_b)
    with open(path, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    return realised


def run(path):
    out = subprocess.run([sys.executable, str(ROOT / "harness" / "analyse.py"), str(path)],
                         capture_output=True, text=True)
    if out.returncode != 0:
        print(out.stdout, out.stderr); raise SystemExit("analyse.py failed")
    return out.stdout


def contrast(text, name):
    """Pull (diff, lo, hi, p) for a named contrast out of the report."""
    for line in text.splitlines():
        if line.startswith(name):
            nums = re.findall(r"-?\d+\.\d+", line)
            return float(nums[0]), float(nums[1]), float(nums[2]), float(nums[3])
    raise AssertionError(f"contrast {name!r} not found")


def main():
    fails = []

    with tempfile.TemporaryDirectory() as td:
        # ---- 1. planted effect, asserted against the truth in the data -----
        p = Path(td) / "planted.jsonl"
        real = synth(p, p_b=0.75, p_c=0.28, p_d=0.40, p_e=0.05)
        true_h1 = real["B"] - real["D"]
        txt = run(p)
        diff, lo, hi, pv = contrast(txt, "H1")
        print(f"planted effect   H1 diff={diff:+.3f} [{lo:.3f}, {hi:.3f}] p={pv:.4f}"
              f"   (true effect in data {true_h1:+.3f})")
        # The correct check is interval coverage, not point-estimate closeness.
        # With 10 reps over 30 scenarios the standard error of this difference is
        # around 0.05, so a point estimate can sit more than 0.05 from the truth
        # and still be perfectly behaved. Only the sign and the coverage are
        # assertable.
        if diff <= 0:
            fails.append(f"point estimate has the wrong sign: {diff:+.3f}")
        if not (lo <= true_h1 <= hi):
            fails.append(f"interval misses the truth: [{lo:.3f}, {hi:.3f}] vs {true_h1:+.3f}")
        if lo <= 0:
            fails.append(f"failed to detect a real effect: [{lo:.3f}, {hi:.3f}]")

        gdiff, glo, ghi, gp = contrast(txt, "gating")
        true_gate = real["B"] - real["C"]
        print(f"planted gating   B-C  diff={gdiff:+.3f} [{glo:.3f}, {ghi:.3f}] p={gp:.4f}"
              f"   (true {true_gate:+.3f})")
        if glo <= 0:
            fails.append("gating failed to separate B from C when it should have")
        if not (glo <= true_gate <= ghi):
            fails.append(f"gating interval misses the truth: [{glo:.3f}, {ghi:.3f}]")

        # ---- 2. true null: B and D drawn from the same distribution --------
        p = Path(td) / "null.jsonl"
        synth(p, p_b=0.60, p_c=0.28, p_d=0.60, p_e=0.05)
        txt = run(p)
        diff, lo, hi, pv = contrast(txt, "H1")
        print(f"true null        H1 diff={diff:+.3f} [{lo:.3f}, {hi:.3f}] p={pv:.4f}")
        if not (lo <= 0 <= hi):
            fails.append(f"FIRED ON NOISE: interval excludes zero [{lo:.3f}, {hi:.3f}]")
        if pv < 0.05:
            fails.append(f"FIRED ON NOISE: p={pv:.4f} under a true null")

        # ---- 3. design effect must exceed 1 when scenarios vary ------------
        de = [float(l.split()[-1]) for l in txt.splitlines()
              if l.strip().startswith(("B ", "C ", "D ")) and len(l.split()) >= 6]
        print(f"design effects   {de}")
        if de and max(de) <= 1.5:
            fails.append("design effect near 1 despite between-scenario variance; "
                         "clustering may not be applied")

    print()
    if fails:
        for f in fails:
            print("FAIL:", f)
        raise SystemExit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
