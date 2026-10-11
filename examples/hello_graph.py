from typing import TypedDict
from langgraph.graph import StateGraph, START, END

class State(TypedDict):
    text: str
    is_urgent: bool
    result: str

def clean(state: State) -> dict:
    return {'text': state['text'].strip()}

def detect(state: State) -> dict:
    return {'is_urgent': 'urgent' in state['text'].lower()}

def escalate(state: State) -> dict:
    return {'result': 'escalated'}

def close(state: State) -> dict:
    return {'result': 'closed'}

def route(state: State) -> str:
    return 'escalate' if state['is_urgent'] else 'close'

builder = StateGraph(State)
builder.add_node('clean', clean)
builder.add_node('detect', detect)
builder.add_node('escalate', escalate)
builder.add_node('close', close)
builder.add_edge(START, 'clean')
builder.add_edge('clean', 'detect')
builder.add_conditional_edges('detect', route, {'escalate': 'escalate', 'close': 'close'})
builder.add_edge('escalate', END)
builder.add_edge('close', END)

graph = builder.compile()
print(graph.invoke({'text': '  URGENT: disk alert  '}))
