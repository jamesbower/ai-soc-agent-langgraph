# ai-soc-agent-langgraph

Companion code for **[How To Build Graph-Based AI SOC Agents The Best Way](https://www.jamesbower.com/ai-soc-agent-langgraph/)** (Part 1): a Tier 1 triage agent that closes alerts only when it's confident and safe to, and escalates everything else to Tier 2.

Read the article first. It explains why the code is built this way, section by section, and each section has a matching [checkpoint tag](#checkpoints).

**This is Part 1 of 3.** Part 2 adds a Tier 2 investigation agent (hypotheses, log queries, alert correlation, human approval). Part 3 adds multiple agents, persistent memory and threat hunting. I'm planning a free course built on this repo, and the waitlist decides whether I build it. If you want it, [join the waitlist](https://james-bower.kit.com/ai-soc-agent-course?utm_source=github&utm_medium=readme&utm_campaign=ai-soc-agent-part1).

Requires Python 3.10 or later. Run every command from the repo root: data paths are relative. Commands use macOS/Linux shell syntax; on Windows, use WSL.

## Quickstart (no API key)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
SOC_AGENT_MODE=replay python -m scripts.run_samples
SOC_AGENT_MODE=replay python -m scripts.run_eval
```

Or with Docker:

```bash
docker build -t ai-soc-agent .
docker run --rm ai-soc-agent
```

## Live mode

```bash
cp .env.example .env   # set OPENAI_API_KEY; OPENAI_MODEL is pinned
SOC_AGENT_MODE=live python -m scripts.run_samples
```

Keep the `SOC_AGENT_MODE=live` prefix: `.env.example` sets `replay`, and a variable set in the shell overrides `.env`.

Live mode always calls the model, even for alerts that are already recorded, and overwrites their entries in `data/recorded_verdicts.json`. The model doesn't accept `temperature=0`, so verdicts can vary between runs and `git diff` will show changes. `git checkout data/recorded_verdicts.json` restores the committed recordings. Replay is what makes results reproducible.

The cache key is a hash of the system prompt plus the payload (the alert and its enrichment context). Changing the prompt, the mock context or an alert changes the key, so replay fails with a `KeyError` until you re-record with a live run.

A live eval run (25 alerts, 22 model calls) costs about $0.003 at gpt-6-luna's October 2026 prices. To measure it yourself, run `python -m scripts.measure_cost data/eval_set.json`. It needs the key, makes real API calls, and leaves the recordings untouched. Set `PRICE_IN_PER_M` and `PRICE_OUT_PER_M` to change the prices.

Live mode in Docker (the image defaults to replay, and `--env-file` alone would set it back to replay). Docker keeps quote characters in `.env` values, so write `OPENAI_API_KEY=sk-...` without quotes:

```bash
docker run --rm --env-file .env -e SOC_AGENT_MODE=live ai-soc-agent
```

## Checkpoints

Each article section has a tag: `s1-graph`, `s2-context`, `s3-policy`, `s4-verification`, `s5-loop`. Run `git checkout s2-context` to see the code at the end of that section.

The run scripts and sample data arrive at `s4-verification`, so at `s1-graph` to `s3-policy` only `pytest` runs. The Dockerfile, the cost script and the diagrams are only on the latest commit.

## Diagrams

`docs/graph.mmd` and `docs/graph.png` are exported from the compiled graph (`python -m scripts.export_graph`; the PNG step calls the mermaid.ink web service, and offline it removes the old PNG). `docs/state-schema.mmd` shows the state, and `docs/tier1-workflow.mmd` maps a Tier 1 analyst's steps to the graph's nodes.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```
