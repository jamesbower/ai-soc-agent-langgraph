# scripts/measure_cost.py
# Measures live token usage and cost. Not part of the article.
# Usage: python -m scripts.measure_cost data/sample_alerts.json
import json, os, sys, tempfile
from pathlib import Path
from langchain_core.callbacks import get_usage_metadata_callback
import app.llm
from app.graph import graph

PRICE_IN_PER_M = float(os.getenv('PRICE_IN_PER_M', '0.10'))
PRICE_OUT_PER_M = float(os.getenv('PRICE_OUT_PER_M', '0.50'))


def alerts_from(path):
    items = json.loads(Path(path).read_text())
    return [i['alert'] if 'expected_decision' in i else i for i in items]


def main(path):
    os.environ['SOC_AGENT_MODE'] = 'live'
    app.llm.CACHE = Path(tempfile.mkdtemp()) / 'scratch_verdicts.json'
    alerts = alerts_from(path)
    with get_usage_metadata_callback() as cb:
        for alert in alerts:
            graph.invoke({'alert': alert})
    if not cb.usage_metadata:
        sys.exit('no usage metadata captured; cost would be misreported as $0')
    tokens_in = sum(u['input_tokens'] for u in cb.usage_metadata.values())
    tokens_out = sum(u['output_tokens'] for u in cb.usage_metadata.values())
    cost = tokens_in / 1e6 * PRICE_IN_PER_M + tokens_out / 1e6 * PRICE_OUT_PER_M
    print(f'{path}: {len(alerts)} alerts, {tokens_in} input tokens, {tokens_out} output tokens, ${cost:.6f}')


if __name__ == '__main__':
    main(sys.argv[1])
