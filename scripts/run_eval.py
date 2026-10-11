# scripts/run_eval.py
import json
from app.graph import graph

cases = json.load(open('data/eval_set.json'))
results = [(c['expected_decision'], graph.invoke({'alert': c['alert']})['decision']) for c in cases]

total = len(results)
correct = sum(1 for exp, got in results if exp == got)
false_neg = sum(1 for exp, got in results if exp == 'escalate_tier2' and got == 'close_benign')
escalated = sum(1 for _, got in results if got == 'escalate_tier2')

print(f'accuracy: {correct / total:.2%}')
print(f'false negatives: {false_neg}')
print(f'escalation rate: {escalated / total:.2%}')
