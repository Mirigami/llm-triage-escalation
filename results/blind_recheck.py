"""
Blind re-rating check.

Analysis plan section 9 commits to this: take a sample of the model's
responses, hide which condition they came from, classify them again
independently, and report agreement with the parser.

What it guards against. The headline numbers come from a regular expression
reading the first HOLD, INVESTIGATE or PAGE in the response. If that regex is
systematically wrong in some cases (a response that says "I would not page",
say), the results are an artefact of parsing rather than a finding about the
model. An independent rater that never sees the condition settles it.

Two figures are reported. The three-way agreement on the exact level, and the
agreement on the primary outcome, ESCALATE against HOLD, which is what the
reported results actually use. A rater that moves a response between
INVESTIGATE and PAGE cannot change any headline number.

Two modes.

  --mode model   a second model rates the responses. Cheap, about 30p.
  --mode manual  writes a shuffled CSV for you to rate by hand, then reads it
                 back. Slower, more credible, and the rater is a practitioner.

  --self-test    exercises the agreement maths on synthetic data. No API calls,
                 no key needed, costs nothing.

The rater sees ONLY the response text. Not the condition, not the family, not
the scenario id, not the alerts. Rows are shuffled.
"""

import json, argparse, random, csv, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

RATER_SYSTEM = (
    "You are reading the output of an alert triage system. For each response, "
    "decide what the system actually concluded. There are three possible "
    "conclusions:\n"
    "  HOLD        take no action\n"
    "  INVESTIGATE queue it for an analyst during working hours\n"
    "  PAGE        wake the on-call responder now\n"
    "Answer with one word: HOLD, INVESTIGATE or PAGE. If the response does not "
    "clearly reach any of these, answer UNCLEAR."
)


def agreement(a, b):
    """Raw agreement and Cohen's kappa between two label lists."""
    assert len(a) == len(b)
    n = len(a)
    if n == 0:
        return float("nan"), float("nan")
    obs = sum(x == y for x, y in zip(a, b)) / n
    labels = sorted(set(a) | set(b))
    exp = sum((a.count(l) / n) * (b.count(l) / n) for l in labels)
    kappa = (obs - exp) / (1 - exp) if exp < 1 else float("nan")
    return obs, kappa


def sample(rows, n, seed):
    rng = random.Random(seed)
    usable = [r for r in rows if r.get("decision") and r.get("raw")]
    return rng.sample(usable, min(n, len(usable)))


def report(parser_labels, rater_labels, source):
    """Three-way agreement, plus agreement on the primary outcome.

    The reported results use ESCALATE, meaning INVESTIGATE or PAGE. So the
    agreement that actually matters for the headline numbers is on that binary.
    The three-way figure is reported too, because a rater that muddles
    INVESTIGATE and PAGE is still worth knowing about even when it cannot
    affect the primary outcome.
    """
    pairs = [(p, r) for p, r in zip(parser_labels, rater_labels) if r != "UNCLEAR"]
    unclear = len(rater_labels) - len(pairs)
    if not pairs:
        print("no usable ratings")
        return
    pl, rl = [p for p, _ in pairs], [r for _, r in pairs]
    obs, kappa = agreement(pl, rl)
    print(f"\nblind re-rating ({source})")
    print(f"  rated        : {len(rater_labels)}   unclear: {unclear}")
    print(f"  agreement    : {obs:.3f}")
    print(f"  Cohen's kappa: {kappa:.3f}")
    esc = lambda x: "ESCALATE" if x in ("INVESTIGATE", "PAGE") else "HOLD"
    pe, re_ = [esc(x) for x in pl], [esc(x) for x in rl]
    obs_e, kappa_e = agreement(pe, re_)
    print(f"  on the primary outcome (ESCALATE vs HOLD):")
    print(f"    agreement    : {obs_e:.3f}")
    print(f"    Cohen's kappa: {kappa_e:.3f}")
    dis = [(p, r) for p, r in pairs if p != r]
    if dis:
        print(f"  disagreements: {len(dis)}")
        from collections import Counter
        for (p, r), c in Counter(dis).most_common():
            print(f"    parser={p} rater={r}: {c}")
    if kappa_e < 0.8:
        print("  Primary-outcome kappa below 0.8. Inspect the disagreements before "
              "trusting the headline numbers.")
    else:
        print("  Parser and independent rater agree on the primary outcome. The "
              "results are not a parsing artefact.")
        if kappa < 0.8:
            print("  Three-way kappa is lower, which reflects the rater moving "
                  "responses between INVESTIGATE and PAGE. Both count as ESCALATE, "
                  "so this cannot affect the primary outcome.")


def self_test():
    """Exercise the maths without touching an API."""
    print("self-test")
    a = ["PAGE"] * 60 + ["HOLD"] * 40
    obs, k = agreement(a, a[:])
    print(f"  identical labels     agreement {obs:.3f}  kappa {k:.3f}  (expect 1.000, 1.000)")
    assert obs == 1.0 and abs(k - 1.0) < 1e-9
    b = a[:]; b[:10] = ["HOLD"] * 10
    obs, k = agreement(a, b)
    print(f"  10 flipped           agreement {obs:.3f}  kappa {k:.3f}  (expect 0.900, ~0.79)")
    assert 0.89 < obs < 0.91
    rng = random.Random(1)
    c = [rng.choice(["PAGE", "HOLD"]) for _ in a]
    obs, k = agreement(a, c)
    print(f"  random rater         agreement {obs:.3f}  kappa {k:.3f}  (kappa near 0)")
    assert abs(k) < 0.3, "kappa should be near zero for a random rater"
    print("  self-test passed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="?", default=str(ROOT / "results" / "results.jsonl"))
    ap.add_argument("--mode", choices=["model", "manual"], default="model")
    ap.add_argument("--n", type=int, default=150)
    ap.add_argument("--seed", type=int, default=20260912)
    ap.add_argument("--model", default="claude-sonnet-4-5")
    ap.add_argument("--max-tokens", type=int, default=12)
    ap.add_argument("--csv", default=str(ROOT / "results" / "blind_rating.csv"))
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        self_test()
        return

    rows = [json.loads(l) for l in open(args.results) if l.strip()]
    picked = sample(rows, args.n, args.seed)
    print(f"sampled {len(picked)} responses from {len(rows)} records")

    if args.mode == "manual":
        path = Path(args.csv)
        if path.exists():
            with open(path) as fh:
                rated = list(csv.DictReader(fh))
            missing = [r for r in rated if not r.get("your_rating", "").strip()]
            if missing:
                print(f"{len(missing)} rows still blank in {path}. Fill them in and rerun.")
                return
            report([r["parser"] for r in rated],
                   [r["your_rating"].strip().upper() for r in rated], "manual")
            return
        with open(path, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["row", "response_text", "your_rating", "parser"])
            for i, r in enumerate(picked):
                w.writerow([i, r["raw"].replace("\n", " | "), "", r["decision"]])
        print(f"wrote {path}")
        print("Fill in the your_rating column with HOLD, INVESTIGATE, PAGE or "
              "UNCLEAR, then rerun "
              "this command. Do not look at the parser column while rating; delete it "
              "first if you want to be strict about it.")
        return

    from anthropic import Anthropic
    client = Anthropic()
    parser_labels, rater_labels = [], []
    for i, r in enumerate(picked):
        resp = client.messages.create(
            model=args.model, max_tokens=args.max_tokens, temperature=0,
            system=RATER_SYSTEM,
            messages=[{"role": "user", "content": r["raw"]}],
        )
        txt = resp.content[0].text.strip().upper()
        label = ("PAGE" if "PAGE" in txt
                 else "INVESTIGATE" if "INVESTIGATE" in txt
                 else "HOLD" if "HOLD" in txt
                 else "UNCLEAR")
        parser_labels.append(r["decision"])
        rater_labels.append(label)
        if (i + 1) % 25 == 0:
            print(f"  {i+1}/{len(picked)}", flush=True)

    out = Path(args.results).parent / "blind_rating.jsonl"
    with open(out, "w") as fh:
        for r, pl, rl in zip(picked, parser_labels, rater_labels):
            fh.write(json.dumps({"key": r["key"], "parser": pl, "rater": rl,
                                 "rater_model": args.model,
                                 "source_model": r.get("model"),
                                 "raw": r["raw"]}) + "\n")
    report(parser_labels, rater_labels, f"model, {args.model}")
    print(f"  written to {out}")


if __name__ == "__main__":
    main()
