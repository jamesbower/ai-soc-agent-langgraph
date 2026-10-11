import json
import pytest
import app.llm as llm
from app.nodes import Verdict

V = {'classification': 'malicious', 'confidence': 0.9, 'rationale': 'r', 'evidence': ['src_ip']}


@pytest.fixture
def cache(tmp_path, monkeypatch):
    path = tmp_path / 'recorded.json'
    monkeypatch.setattr(llm, 'CACHE', path)
    return path


def test_replay_reads_recorded_verdict(cache, monkeypatch):
    cache.write_text(json.dumps({llm._key('sys', 'pay'): V}))
    monkeypatch.setenv('SOC_AGENT_MODE', 'replay')
    assert llm.get_verdict('sys', 'pay', Verdict).classification == 'malicious'


def test_replay_unrecorded_raises_keyerror(cache, monkeypatch):
    monkeypatch.setenv('SOC_AGENT_MODE', 'replay')
    with pytest.raises(KeyError):
        llm.get_verdict('sys', 'other', Verdict)


def test_live_calls_model_and_records(cache, monkeypatch):
    calls = {}

    class FakeChat:
        def __init__(self, **kwargs):
            calls['kwargs'] = kwargs

        def with_structured_output(self, schema):
            return self

        def invoke(self, messages):
            calls['messages'] = messages
            return Verdict(**V)

    monkeypatch.setattr(llm, 'ChatOpenAI', FakeChat)
    monkeypatch.setenv('SOC_AGENT_MODE', 'live')
    monkeypatch.setenv('OPENAI_MODEL', 'test-model')
    assert llm.get_verdict('sys', 'pay', Verdict).confidence == 0.9
    assert calls['kwargs']['model'] == 'test-model'
    assert calls['messages'] == [('system', 'sys'), ('human', 'pay')]
    assert json.loads(cache.read_text()) == {llm._key('sys', 'pay'): V}


def test_key_changes_with_prompt():
    assert llm._key('a', 'p') != llm._key('b', 'p')
