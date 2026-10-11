# app/state.py
import operator
from typing import Annotated, TypedDict

class TriageState(TypedDict, total=False):
    alert: dict
    normalized: dict
    alert_type: str
    enrichment: dict
    known_fp: bool
    verdict: dict
    decision: str
    case_note: str
    audit: Annotated[list, operator.add]
