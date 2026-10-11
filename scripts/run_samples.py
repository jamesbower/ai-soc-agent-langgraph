# scripts/run_samples.py
import json
from app.graph import graph

for alert in json.load(open('data/sample_alerts.json')):
    result = graph.invoke({'alert': alert})
    print(result['decision'], '|', result['case_note'])
    for line in result['audit']:
        print('   ', line)
