import json
from pathlib import Path

def add_to_eval(alert: dict, expected: str, path: str = 'data/eval_set.json') -> None:
    p = Path(path)
    cases = json.loads(p.read_text()) if p.exists() else []
    cases.append({'alert': alert, 'expected_decision': expected})
    p.write_text(json.dumps(cases, indent=2))
