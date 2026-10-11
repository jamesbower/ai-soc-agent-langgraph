from examples.hello_graph import graph


def test_urgent_text_escalates():
    assert graph.invoke({'text': '  URGENT: disk alert  '})['result'] == 'escalated'


def test_plain_text_closes():
    assert graph.invoke({'text': 'disk at 40%'})['result'] == 'closed'
