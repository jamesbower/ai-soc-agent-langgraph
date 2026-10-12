import json
from app.feedback import add_to_eval


def test_add_to_eval_creates_then_appends(tmp_path):
    path = tmp_path / 'eval.json'
    add_to_eval({'rule_name': 'a'}, 'escalate_tier2', str(path))
    add_to_eval({'rule_name': 'b'}, 'close_benign', str(path))
    assert json.loads(path.read_text()) == [
        {'alert': {'rule_name': 'a'}, 'expected_decision': 'escalate_tier2'},
        {'alert': {'rule_name': 'b'}, 'expected_decision': 'close_benign'},
    ]
