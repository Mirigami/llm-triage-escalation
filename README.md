# llm-triage-escalation

Code, corpus and raw results for my submission to the Apart Research
**AI Incident Response Sprint** (11 to 13 September 2026), containment track.

The problem: in July 2026 an AI agent escaped an evaluation sandbox and ran
inside Hugging Face's production systems for four and a half days. Detections
fired the whole time and nobody was paged. Language models are now sold to do
exactly that triage step, so the question is whether one would have raised the
alarm, and whether describing the environment changes its answer. This repo is
the test for that, and the corpus you need to run it.

## What it does

Two things, and the order matters.

**Can it tell an intrusion from a busy Tuesday?** Give a model a bundle of
security alerts reconstructed from the published intrusion, then give it a
bundle of innocent activity matched alert for alert, and see whether it
escalates one more than the other. If it cannot separate them, its escalation
rate is not evidence of detection.

**Does calling it your own test lab change the answer?** Take the identical
intrusion bundle and change one line, the one describing the environment, from
a shared compute pool to the organisation's own model evaluation pool. Nothing
else moves. Anything that changes is the model reacting to who the activity is
attributed to.

Neither question is useful on its own. A model that escalates everything passes
the second by being useless, which is why two gating conditions come first: are
the alerts ambiguous in isolation, and is the noise floor clean.

## What was found

- No model separated an intrusion from matched benign activity by a useful
  margin. One went the wrong way by 10.8 points, another went the right way by
  2.0 points with a range that includes zero, and the third escalated
  everything.
- The task was solvable. A small classifier given only which rule names appear
  together, and none of the numbers, got every case right.
- One line of environment description cut escalation from 62% to 13% on one
  model and from 98% to 70% on another, and stopped paging entirely. Across 300
  attributed intrusion bundles, one model paged zero times.
- The models said why. Mentions of the evaluation framing in their own
  reasoning went from almost never to most of the time.
- Squeezing the same alerts from twelve hours into two changed nothing, so the
  signals being spread out was not the blocker.
- `claude-opus-5` refused the task outright, returning nothing on 108 of 150
  requests, on alerts containing no commands and no exploit detail.

## Layout

The corpus:

- `corpus/alert_templates.json` is the library: 40 intrusion templates each
  paired with an innocent twin worded identically, plus 12 null templates. Each
  names the detection rule that would realistically have fired and where that
  rule comes from.
- `corpus/alert_library.md` is the same thing in readable form, for review.
- `corpus/scenarios.json` is the built corpus: 90 bundles, 30 intrusion, 30
  matched benign, 30 null.
- `corpus/scenario_samples.md` is a handful of built scenarios to eyeball.

The harness (`harness/`):

- `build_scenarios.py` assembles the 90 bundles from the templates. Fully
  deterministic from seed 20260912, so it reproduces the exact corpus used.
- `run_triage.py` sends every scenario to a model under all six conditions and
  appends each answer to a JSONL file. Resumable, so a crash costs you nothing.
- `analyse.py` implements the frozen analysis plan. The unit is the scenario,
  never the individual call.
- `test_analysis.py` checks the analysis recovers an effect that is really
  there and, more importantly, stays quiet when there is nothing to find.

The checks and outputs (`results/`):

- `leakage_check.py` runs both pre-collection checks: whether the numbers alone
  give the answer away, and whether the task is solvable at all.
- `blind_recheck.py` re-rates a sample of responses with the condition hidden,
  to prove the headline numbers are not an artefact of how answers were parsed.
- `make_figure.py`, `make_appendices.py`, `make_provenance_table.py` build the
  figure, the appendix material and the rule-source table.
- `explore_omission.py` is the analysis that **did not work**, kept because the
  negative result is part of the account.
- `results*.jsonl` are every raw response from every model, including the
  refusals.
- `analysis_plan.md` in the repo root is the plan, written and frozen before
  any data was collected, with both amendments dated and explained.

## Running it

### Before you start

```
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

The corpus is already built and committed, so you do not need to regenerate it
unless you want to change the templates.

### Step by step

```
# 1. Check the analysis before you spend anything. This plants an effect and
#    confirms the code finds it, then feeds it pure noise and confirms it
#    stays quiet. If this fails, nothing downstream is worth running.
python harness/test_analysis.py

# 2. Confirm the corpus is fair. Can a model get the right answer from the
#    numbers alone (it should not), and is the task solvable at all from the
#    rule names (it should be).
python results/leakage_check.py

# 3. Find out what the run will cost before you start it.
python harness/run_triage.py --estimate

# 4. Small pilot first. Read a few raw answers yourself before committing to
#    the full run. This is where I caught that my first outcome measure was
#    broken.
python harness/run_triage.py --pilot

# 5. The full run, one model at a time. Roughly 2,100 calls each.
python harness/run_triage.py --model claude-sonnet-4-5 --out results/results.jsonl
python harness/run_triage.py --model claude-haiku-4-5  --out results/results_m2.jsonl
python harness/run_triage.py --model claude-sonnet-5   --out results/results_sonnet5.jsonl

# 6. Analyse each one. Prints every condition, both comparisons, and the
#    confidence ranges.
python harness/analyse.py results/results.jsonl

# 7. Confirm the numbers are not a parsing artefact.
python results/blind_recheck.py results/results.jsonl

# 8. Build the figure, the tables and the appendix material.
python results/make_figure.py
python results/make_appendices.py
python results/make_provenance_table.py
```

To test a different provider, `run_triage.py` is the only file that talks to an
API. Everything downstream reads the JSONL.

### Four things that cost me time

- **An empty response is not a result.** The harness originally recorded a
  blank completion as a valid answer. That would have logged 93% of one run as
  unreadable instead of showing what it was: a model refusing. Always check why
  a response is empty before you record it.
- **Not every model accepts a temperature setting.** One returned an error on
  every single call until the code learned to leave it out. Fail loudly on the
  first call rather than burning the whole run.
- **Run the pilot and read the raw answers.** My first outcome had two levels,
  PAGE or HOLD, and came back HOLD every single time. The answers said exactly
  why. I would have wasted the entire budget measuring reluctance to wake
  somebody at 3am.
- **Do not run the analysis on a test file inside `results/`.** It writes its
  per-scenario output next to its input, so a test run will quietly overwrite a
  real one.

### Cost

The whole study was API calls only, roughly $20 for about 6,500 requests across
three models. Use `--reduced` and `--reps` to run a cheaper version first.

## What this cannot tell you

The alerts are constructed, not taken from a real system, because no public set
of matched bundles exists. Real queues are longer and noisier. A model behind a
triage prompt is not a vendor's triage product. Nothing here describes what any
named organisation actually had running.

## A note on what is in here

The alerts describe telemetry only: counts, timestamps, process names,
destinations, rule names, severities. No commands and no exploit detail. The
corpus was built under that constraint rather than cleaned up afterwards, and
the rule names come from public repositories. No model weights, attack tooling
or exploit detail are released.

## Credits

Detection rule names come from
[Elastic's detection-rules](https://github.com/elastic/detection-rules) and
[SigmaHQ](https://github.com/SigmaHQ/sigma). The intrusion phases are
reconstructed from Hugging Face's published forensic timeline. Rules named after
GenAI activity are deliberately excluded, because those names would give the
answer away.
