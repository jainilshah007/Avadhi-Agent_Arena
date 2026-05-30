"""
avadhi/pipeline/graph.py — Backwards-compatible re-export.

The canonical pipeline definition lives in avadhi/pipeline/workflow.py.
This file re-exports for any code that imports from here.
"""
from avadhi.pipeline.workflow import (  # noqa: F401
    create_audit_graph,
    enrichment_node,
    hunting_node,
    crossfeed_hunting_node,
    critic_node,
    review_node,
)

# Backwards-compatible alias
build_audit_graph = create_audit_graph
