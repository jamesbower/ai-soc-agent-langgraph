from langgraph.graph import StateGraph, START, END
from app.state import TriageState


def test_audit_reducer_appends_across_nodes():
    b = StateGraph(TriageState)
    b.add_node('a', lambda s: {'audit': ['a ran']})
    b.add_node('b', lambda s: {'audit': ['b ran']})
    b.add_edge(START, 'a')
    b.add_edge('a', 'b')
    b.add_edge('b', END)
    out = b.compile().invoke({'alert': {}})
    assert out['audit'] == ['a ran', 'b ran']
