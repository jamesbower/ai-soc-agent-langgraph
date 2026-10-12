# app/llm.py
import hashlib, json, os
from pathlib import Path
from dotenv import load_dotenv
from langchain_openai import ChatOpenAI

load_dotenv()
CACHE = Path('data/recorded_verdicts.json')

def _key(system: str, payload: str) -> str:
    return hashlib.sha256((system + payload).encode()).hexdigest()[:16]

def get_verdict(system: str, payload: str, schema):
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    key = _key(system, payload)
    if os.getenv('SOC_AGENT_MODE', 'live') == 'replay':
        return schema(**cache[key])
    llm = ChatOpenAI(model=os.environ['OPENAI_MODEL'], reasoning_effort='low').with_structured_output(schema)
    verdict = llm.invoke([('system', system), ('human', payload)])
    cache[key] = verdict.model_dump()
    CACHE.write_text(json.dumps(cache, indent=2))
    return verdict
