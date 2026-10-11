import json
import app.nodes as nodes
from app.graph import graph

DECISIONS = {'close_benign', 'escalate_tier2'}
CATEGORIES = ('fp-', 'crit-', 'low-', 'unk-ip-', 'unk-asset-', 'benign-', 'missing-', 'inject-')


def load(path):
    with open(path) as f:
        return json.load(f)


def fake_benign(system, payload, schema):
    return schema(classification='benign', confidence=1.0, rationale='stub', evidence=[])


def boom(*args, **kwargs):
    raise AssertionError('model must not be called')


def test_samples_are_fp_tp_ambiguous():
    fp, tp, amb = load('data/sample_alerts.json')
    assert (fp['rule_name'], fp['src_ip'], fp['host']) == ('Scheduled vulnerability scan', '198.51.100.7', 'dev-ws-221')
    assert (tp['user'], tp['host'], tp['src_ip']) == ('jdoe', 'fin-ws-014', '203.0.113.50')
    assert amb['host'] == 'dev-ws-221' and amb['src_ip'] not in nodes.MOCK_INTEL


def test_sample_fp_closes_without_model(monkeypatch):
    monkeypatch.setattr(nodes, 'get_verdict', boom)
    assert graph.invoke({'alert': load('data/sample_alerts.json')[0]})['decision'] == 'close_benign'


def test_eval_set_shape_and_coverage():
    cases = load('data/eval_set.json')
    assert 20 <= len(cases) <= 30
    assert len({c['id'] for c in cases}) == len(cases)
    for c in cases:
        assert c['expected_decision'] in DECISIONS and c['label_status'] == 'draft'
        assert isinstance(c['alert'], dict)
    for prefix in CATEGORIES:
        assert any(c['id'].startswith(prefix) for c in cases), prefix
    assert sum(c['id'].startswith('inject-') for c in cases) >= 2


def test_known_fp_cases_close_without_model(monkeypatch):
    monkeypatch.setattr(nodes, 'get_verdict', boom)
    for c in load('data/eval_set.json'):
        if c['id'] in {'fp-clean-dev', 'fp-clean-fin', 'fp-unknown-ip'}:
            assert graph.invoke({'alert': c['alert']})['decision'] == c['expected_decision'] == 'close_benign', c['id']


def test_critical_asset_with_bad_ip_escalates_even_if_model_says_benign(monkeypatch):
    monkeypatch.setattr(nodes, 'get_verdict', fake_benign)
    hits = [c for c in load('data/eval_set.json')
            if c['alert'].get('host') == 'fin-ws-014' and c['alert'].get('src_ip') == '203.0.113.50']
    assert len(hits) >= 4
    for c in hits:
        assert graph.invoke({'alert': c['alert']})['decision'] == 'escalate_tier2', c['id']
