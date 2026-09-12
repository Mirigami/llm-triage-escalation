"""
Scenario generator.

Assembles 30 INTRUSION, 30 BENIGN and 30 NULL scenarios from the template
library. Every numeric parameter is drawn from ONE distribution shared by both
families, so no single value is informative about which family a bundle
belongs to. The only signal is which templates co-occur and whether they form
a coherent chain.

Timestamps: base scenarios spread across a 12-hour shift with uneven gaps.
Condition F re-renders the identical alerts compressed into 2 hours.
"""

import json, random, pathlib, datetime as dt

ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = ROOT / "corpus"

SEED = 20260912
random.seed(SEED)

LIB = json.load(open(CORPUS / "alert_templates.json"))
T = {t["id"]: t for t in LIB["templates"]}
N = LIB["null_templates"]

# ---------------------------------------------------------------- parameters
# One sampler per placeholder. Used identically for INTRUSION and BENIGN.
# Ranges are deliberately wide and overlapping.

def _i(a, b): return lambda: random.randint(a, b)
def _c(*v):   return lambda: random.choice(v)

P = {
    "n":        _i(3, 260),
    "k":        _i(3, 40),
    "h":        _i(2, 30),
    "mins":     _i(4, 55),
    "secs":     _i(20, 240),
    "hrs":      _i(2, 9),
    "pct":      _i(38, 71),
    "med":      _i(8, 90),
    "interval": _c(31, 47, 61, 73, 89),
    "jitter":   _i(1, 6),
    "before":   _i(180, 900),
    "after":    _i(0, 40),
    "days":     _i(3, 21),
    "ms":       _i(120, 900),
    "exp":      _i(5, 40),
    "size":     lambda: f"{random.randint(40, 900)} MB",
    "base":     lambda: f"{random.randint(5, 80)} MB",
    "host":     lambda: f"pool-{random.randint(1,19):02d}",
    "ctr":      lambda: f"ctr-{random.randbytes(2).hex()}",
    "ns":       _c("runtime-a", "runtime-b", "platform-shared", "batch-c"),
    "sa":       _c("sa-runner", "sa-ci-shared", "sa-collector", "sa-batch"),
    "ua":       _c("go-http-client/2.1", "python-requests/2.32", "kubectl/v1.31", "curl/8.7"),
    "proc":     _c("sh", "bash", "python3.11", "node"),
    "path":     _c("/tmp/build.out", "/var/tmp/stage", "/tmp/art.tar", "/opt/run/bin"),
    "dev":      lambda: f"dev-{random.randbytes(2).hex()}",
    "principal":_c("role/runner", "role/collector", "role/batch", "role/deploy"),
    "svc":      _c("api-gateway", "artifact-store", "scheduler", "registry-proxy"),
    "chg":      lambda: f"CHG-{random.randint(10000,99999)}",
    "time":     lambda: f"{random.randint(0,23):02d}:{random.randint(0,59):02d}",
}

def coherence(keys):
    """
    Keep alerts internally consistent.

    Any alert that compares an observed value against a baseline must actually
    exceed it, or the detection rule would not have fired and the alert reads as
    nonsense to a practitioner. The exceedance RATIO is sampled from a single
    range shared by both families, so coherence is restored without giving the
    numbers any discriminative power.
    """
    if "size" in keys and "base" in keys:
        base = random.randint(5, 80)
        ratio = random.uniform(2.5, 14.0)          # shared across families
        keys["base"] = f"{base} MB"
        keys["size"] = f"{int(base * ratio)} MB"
    if "before" in keys and "after" in keys and keys["after"] >= keys["before"]:
        keys["after"] = random.randint(0, max(1, keys["before"] // 8))
    if "med" in keys and "hrs" in keys:             # session far above median
        keys["med"] = random.randint(8, 90)
    return keys

def fill(text):
    """Substitute placeholders, returning the rendered line and the values used."""
    used = {}
    out = text
    pending = []
    scan = text
    while "{" in scan:
        a = scan.index("{"); b = scan.index("}", a)
        pending.append(scan[a+1:b]); scan = scan[b+1:]
    for key in pending:
        if key not in used:
            used[key] = P[key]()
    used = coherence(used)
    while "{" in out:
        a = out.index("{"); b = out.index("}", a)
        out = out[:a] + str(used[out[a+1:b]]) + out[b+1:]
    return out, used

# ------------------------------------------------------------------- stories
# Each story is an ordered set of template ids that plausibly co-occur.
# Intrusion chains follow the nine published phases of the July 2026 incident.

INTRUSION_CHAINS = {
    "proxy-to-cluster":    ["T-01","T-07","T-12","T-33","T-27","T-20","T-17"],
    "api-first":           ["T-02","T-06","T-08","T-14","T-29","T-22","T-16"],
    "supply-chain-entry":  ["T-35","T-34","T-13","T-15","T-28","T-21","T-19"],
    "capability-escalate": ["T-05","T-11","T-12","T-30","T-31","T-24","T-37"],
    "credential-sprawl":   ["T-03","T-09","T-26","T-32","T-27","T-39","T-40"],
    "quiet-persistence":   ["T-01","T-10","T-14","T-36","T-23","T-25","T-38"],
}

BENIGN_STORIES = {
    "dependency-upgrade":  ["T-01","T-33","T-35","T-12","T-07","T-17","T-34"],
    "new-agent-rollout":   ["T-02","T-03","T-32","T-04","T-31","T-29","T-22"],
    "authorised-pentest":  ["T-05","T-02","T-22","T-03","T-06","T-39","T-24"],
    "new-starter":         ["T-38","T-39","T-40","T-09","T-03","T-29","T-36"],
    "base-image-redeploy": ["T-17","T-29","T-30","T-23","T-36","T-12","T-35"],
    "incident-bridge":     ["T-06","T-09","T-26","T-37","T-24","T-08","T-21"],
}

# Applied from practitioner review:
#   T-06 moved out of new-starter into incident-bridge, where it already sat.
#   T-25 dropped from incident-bridge; engineers debugging live rarely truncate
#   history, so the pairing was the odd one out.

SHIFT_START = dt.datetime(2026, 7, 9, 4, 0)

def timestamps(count, span_minutes):
    """Uneven gaps across the window, never a regular cadence."""
    pts = sorted(random.uniform(0, span_minutes) for _ in range(count))
    return [SHIFT_START + dt.timedelta(minutes=m) for m in pts]

def render(ids, span_minutes):
    times = timestamps(len(ids), span_minutes)
    alerts, params = [], []
    for tid, ts in zip(ids, times):
        t = T[tid]
        line, used = fill(t["intrusion"])          # identical text in both families
        alerts.append({
            "id": tid, "time": ts.strftime("%d %b %H:%M"),
            "rule": t["rule"], "severity": t["severity"],
            "surface": t["surface"], "text": line,
        })
        params.append({"template": tid, **{k: v for k, v in used.items()
                                           if isinstance(v, int)}})
    return alerts, params

def build():
    scenarios = []
    for family, book in (("INTRUSION", INTRUSION_CHAINS), ("BENIGN", BENIGN_STORIES)):
        keys = list(book)
        for i in range(30):
            story = keys[i % len(keys)]
            ids = book[story][:]
            # drop one alert at random in a third of scenarios, so bundle size
            # varies 6-7 and length is not a family cue
            if random.random() < 0.33:
                ids.pop(random.randrange(len(ids)))
            spread, sp_params = render(ids, 12 * 60)
            tight, _         = render(ids, 2 * 60)
            scenarios.append({
                "sid": f"{family[:3]}-{i+1:02d}", "family": family, "story": story,
                "alerts_spread": spread, "alerts_tight": tight, "params": sp_params,
            })
    for i in range(30):
        picks = random.sample(N, 7)
        times = timestamps(7, 12 * 60)
        alerts = []
        for t, ts in zip(picks, times):
            line, _ = fill(t["text"])
            alerts.append({"id": t["id"], "time": ts.strftime("%d %b %H:%M"),
                           "rule": t["rule"], "severity": t["severity"],
                           "surface": "mixed", "text": line})
        scenarios.append({"sid": f"NUL-{i+1:02d}", "family": "NULL", "story": "noise",
                          "alerts_spread": alerts, "alerts_tight": alerts, "params": []})
    return scenarios

if __name__ == "__main__":
    s = build()
    json.dump({"seed": SEED, "scenarios": s}, open(CORPUS / "scenarios.json", "w"), indent=1)
    from collections import Counter
    print("scenarios:", len(s), dict(Counter(x["family"] for x in s)))
    print("bundle sizes:", sorted(Counter(len(x["alerts_spread"]) for x in s).items()))
    shared = set()
    for c in INTRUSION_CHAINS.values(): shared |= set(c)
    other = set()
    for c in BENIGN_STORIES.values(): other |= set(c)
    print("templates used:", len(shared | other), "of 40")
    print("templates in BOTH families:", len(shared & other))
