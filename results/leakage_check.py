"""
Parameter leakage check.

Requirement from practitioner review: confirm that the numeric parameter values
alone cannot separate INTRUSION from BENIGN. If they can, the study degenerates
into "can a model threshold a number" rather than "can a model read a
correlated pattern", and the ranges must be tightened before any data is
collected.

Test 1 (the one that matters). Restricted to templates that appear in BOTH
families. Features are the raw numeric parameters of a single alert, with the
template identity stripped. A classifier here should sit at chance.

Test 2 (contrast, expected to succeed). Scenario-level bag of template ids, no
numbers at all. This SHOULD separate the families, because which templates
co-occur is the signal under test. Reporting both makes the point precisely:
the information is in the composition, not the values.
"""

import json, pathlib, numpy as np

ROOT = pathlib.Path(__file__).resolve().parent.parent
from collections import Counter
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import make_pipeline

S = json.load(open(ROOT / "corpus" / "scenarios.json"))["scenarios"]
S = [s for s in S if s["family"] in ("INTRUSION", "BENIGN")]

fam_templates = {f: set() for f in ("INTRUSION", "BENIGN")}
for s in S:
    fam_templates[s["family"]] |= {a["id"] for a in s["alerts_spread"]}
shared = fam_templates["INTRUSION"] & fam_templates["BENIGN"]

# ---- Test 1: numeric parameters only, shared templates only ---------------
keys, rows, labels = set(), [], []
for s in S:
    for p in s["params"]:
        if p["template"] in shared:
            keys |= set(p) - {"template"}
keys = sorted(keys)
for s in S:
    for p in s["params"]:
        if p["template"] in shared:
            rows.append([p.get(k, 0) for k in keys])
            labels.append(1 if s["family"] == "INTRUSION" else 0)

X, y = np.array(rows, float), np.array(labels)
cv = StratifiedKFold(5, shuffle=True, random_state=0)
clf = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000))
auc = cross_val_score(clf, X, y, cv=cv, scoring="roc_auc")
acc = cross_val_score(clf, X, y, cv=cv, scoring="accuracy")
base = max(np.mean(y), 1 - np.mean(y))

print("TEST 1  numeric parameters only, shared templates")
print(f"  alerts: {len(y)}  features: {len(keys)}  shared templates: {len(shared)}")
print(f"  majority-class baseline : {base:.3f}")
print(f"  accuracy  : {acc.mean():.3f} +/- {acc.std():.3f}")
print(f"  ROC AUC   : {auc.mean():.3f} +/- {auc.std():.3f}   (0.500 = chance)")
verdict = "PASS, values do not leak" if abs(auc.mean() - 0.5) < 0.10 else "FAIL, tighten ranges"
print(f"  verdict   : {verdict}")

# ---- Test 2: template composition only, no numbers -------------------------
tids = sorted({a["id"] for s in S for a in s["alerts_spread"]})
Xc = np.array([[1 if t in {a["id"] for a in s["alerts_spread"]} else 0 for t in tids] for s in S], float)
yc = np.array([1 if s["family"] == "INTRUSION" else 0 for s in S])
auc2 = cross_val_score(make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000)),
                       Xc, yc, cv=StratifiedKFold(5, shuffle=True, random_state=0), scoring="roc_auc")
print("\nTEST 2  template composition only, no numeric values (contrast)")
print(f"  scenarios: {len(yc)}  ROC AUC: {auc2.mean():.3f}")
print("  expected to separate. The signal is which templates co-occur,")
print("  which is the mechanism under test.")

# ---- bundle size, a possible confound -------------------------------------
sz = {f: Counter(len(s["alerts_spread"]) for s in S if s["family"] == f)
      for f in ("INTRUSION", "BENIGN")}
print("\nBundle size by family (must not be a cue):", dict(sz["INTRUSION"]), dict(sz["BENIGN"]))
