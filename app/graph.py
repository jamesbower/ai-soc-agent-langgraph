# app/graph.py
from langgraph.graph import StateGraph, START, END
from app.state import TriageState
from app.nodes import ingest, classify, enrich, check_known_fp, assess, decide, record

def after_fp(state):
    return 'decide' if state['known_fp'] else 'assess'

builder = StateGraph(TriageState)
for name, fn in [('ingest', ingest), ('classify', classify), ('enrich', enrich),
                 ('check_known_fp', check_known_fp), ('assess', assess),
                 ('decide', decide), ('record', record)]:
    builder.add_node(name, fn)

builder.add_edge(START, 'ingest')
builder.add_edge('ingest', 'classify')
builder.add_edge('classify', 'enrich')
builder.add_edge('enrich', 'check_known_fp')
builder.add_conditional_edges('check_known_fp', after_fp, {'decide': 'decide', 'assess': 'assess'})
builder.add_edge('assess', 'decide')
builder.add_edge('decide', 'record')
builder.add_edge('record', END)

graph = builder.compile()
