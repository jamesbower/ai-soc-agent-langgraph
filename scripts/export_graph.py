# scripts/export_graph.py
# Usage: python -m scripts.export_graph (from the repo root)
from pathlib import Path
from app.graph import graph

docs = Path('docs')
docs.mkdir(exist_ok=True)
(docs / 'graph.mmd').write_text(graph.get_graph().draw_mermaid())
png = docs / 'graph.png'
try:
    png.write_bytes(graph.get_graph().draw_mermaid_png())
except Exception as e:
    png.unlink(missing_ok=True)
    print(f'PNG export skipped, old graph.png removed: {e}')
