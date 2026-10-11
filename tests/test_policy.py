import pytest
from app.nodes import check_known_fp, decide, record

CLEAN, BAD, UNK = {'reputation': 'clean'}, {'reputation': 'malicious'}, {'reputation': 'unknown'}
HIGH, LOW = {'criticality': 'high'}, {'criticality': 'low'}


def fp_state(rule, ip):
    return {'normalized': {'rule': rule}, 'enrichment': {'ip': ip, 'asset': LOW}}


def verdict(cls, conf, why='r'):
    return {'classification': cls, 'confidence': conf, 'rationale': why, 'evidence': []}


def test_known_fp_rule_from_clean_ip_short_circuits():
    out = check_known_fp(fp_state('Scheduled vulnerability scan', CLEAN))
    assert out['known_fp'] is True
    assert out['verdict']['classification'] == 'benign'
    assert out['audit'] == ['check_known_fp: True']


def test_known_fp_rule_from_bad_ip_does_not_short_circuit():
    out = check_known_fp(fp_state('Scheduled vulnerability scan', BAD))
    assert out['known_fp'] is False
    assert 'verdict' not in out


def test_other_rule_is_not_known_fp():
    assert check_known_fp(fp_state('Suspicious login success after failures', CLEAN))['known_fp'] is False


@pytest.mark.parametrize('v, asset, ip, expected', [
    (verdict('benign', 0.8), LOW, CLEAN, 'close_benign'),       # threshold is inclusive
    (verdict('benign', 0.79), LOW, CLEAN, 'escalate_tier2'),
    (verdict('suspicious', 0.95), LOW, CLEAN, 'escalate_tier2'),
    (verdict('benign', 0.99), HIGH, BAD, 'escalate_tier2'),     # hard rule beats the model
    (verdict('benign', 0.99), HIGH, UNK, 'close_benign'),
    (verdict('benign', 0.99), LOW, BAD, 'close_benign'),        # current policy: hard rule needs both
])
def test_decide(v, asset, ip, expected):
    assert decide({'verdict': v, 'enrichment': {'asset': asset, 'ip': ip}})['decision'] == expected


def test_record_writes_case_note():
    out = record({'verdict': verdict('benign', 0.95, 'Matches a known false-positive rule.'),
                  'decision': 'close_benign'})
    assert out['case_note'] == 'close_benign | benign (0.95) | Matches a known false-positive rule.'
    assert out['audit'] == ['record: wrote case note']
