"""
Rule provenance table.

Analysis plan section 2.3 commits to publishing which detection rule each alert
template corresponds to, and whether that rule is one a security vendor actually
ships, a public Sigma rule, or a custom check invented for this study.

Publishing it matters because it is the difference between "we wrote realistic
alerts" and "here is exactly how realistic, rule by rule, check us".

Run:  python3 results/make_provenance_table.py
"""

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LIB = json.load(open(ROOT / "corpus" / "alert_templates.json"))
OUT = ROOT / "results" / "provenance_table.md"

LABEL = {
    "elastic": "Elastic, shipped",
    "sigma": "SigmaHQ, public",
    "custom": "custom, this study",
}

rows = LIB["templates"]
counts = Counter(r["provenance"] for r in rows)

lines = [
    "# Rule provenance",
    "",
    f"{len(rows)} alert templates. "
    + ", ".join(f"{counts.get(k,0)} {LABEL[k]}" for k in ("elastic", "sigma", "custom"))
    + ".",
    "",
    "Templates marked *custom* have no public equivalent that was found. They are "
    "plausible detections rather than ones a named product is known to ship, and "
    "are labelled so that a reader can discount them if they wish.",
    "",
    "Elastic's GenAI-prefixed rule family is excluded from the library. Those rule "
    "names identify activity as AI-driven, which would place the condition D "
    "attribution inside the condition B telemetry and confound the primary "
    "comparison.",
    "",
    "| Template | Phase | Detection rule | Source | Reference |",
    "|---|---|---|---|---|",
]

for r in sorted(rows, key=lambda x: (x["phase"], x["id"])):
    ref = r["ref"] if r["provenance"] != "custom" else "_n/a_"
    lines.append(f"| {r['id']} | {r['phase']} | {r['rule']} | {LABEL[r['provenance']]} | `{ref}` |")

lines += [
    "",
    "## Null set",
    "",
    "The null scenarios use routine infrastructure events rather than security "
    "detections, so no provenance applies.",
    "",
    "| Template | Event |",
    "|---|---|",
]
for r in LIB["null_templates"]:
    lines.append(f"| {r['id']} | {r['rule']} |")

OUT.write_text("\n".join(lines) + "\n")
print(f"wrote {OUT}")
print(dict(counts))
