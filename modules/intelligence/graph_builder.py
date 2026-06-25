"""Feature 6: Attack-surface graph.

Builds a graph of the application (nodes: roles, pages, APIs, forms, files; edges:
role→endpoint access, page→page workflow, form→action) and exports it as JSON,
GraphML and Draw.io (mxGraphModel) using only the standard library.
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape, quoteattr

from models.schemas import GraphEdge, GraphNode

ACCESSIBLE_STATUSES = {200, 201, 202, 203, 204, 206}


def build_graph(data: dict) -> tuple[list[GraphNode], list[GraphEdge]]:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []

    def add_node(node_id: str, label: str, kind: str) -> str:
        nodes.setdefault(node_id, GraphNode(id=node_id, label=label, kind=kind))
        return node_id

    # Roles
    for user in data.get("users", []):
        add_node(f"role:{user['role']}", user["role"], "role")
    add_node("role:anonymous", "anonymous", "role")

    # Pages / endpoints from crawl, with role -> endpoint access edges
    for ep in data.get("crawl_endpoints", []):
        nid = add_node(f"page:{ep['path']}", ep["path"], "page")
        if ep.get("status_code") in ACCESSIBLE_STATUSES:
            rid = f"role:{ep['role']}"
            add_node(rid, ep["role"], "role")
            edges.append(GraphEdge(source=rid, target=nid, kind="access"))

    # APIs
    for api in data.get("api_intel", []):
        add_node(f"api:{api['path']}", api["path"], "api")

    # Forms -> action endpoints
    for form in data.get("forms", []):
        fid = add_node(f"form:{form['page_url']}#{form['action']}", form["action"], "form")
        edges.append(
            GraphEdge(
                source=fid,
                target=add_node(f"page:{form['page_url']}", form["page_url"], "page"),
                kind="form",
            )
        )

    # Files
    for ep in data.get("crawl_endpoints", []):
        if ep.get("source") == "file":
            add_node(f"file:{ep['path']}", ep["path"], "file")

    # Page -> page workflow
    for edge in data.get("workflow_edges", []):
        a = add_node(f"page:{edge['from_path']}", edge["from_path"], "page")
        b = add_node(f"page:{edge['to_path']}", edge["to_path"], "page")
        edges.append(GraphEdge(source=a, target=b, kind=edge.get("kind", "link")))

    return list(nodes.values()), edges


def export_json(nodes: list[GraphNode], edges: list[GraphEdge]) -> str:
    import json

    return json.dumps(
        {
            "nodes": [n.model_dump() for n in nodes],
            "edges": [e.model_dump() for e in edges],
        },
        indent=2,
    )


def export_graphml(nodes: list[GraphNode], edges: list[GraphEdge]) -> str:
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">',
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>',
        '  <key id="kind" for="node" attr.name="kind" attr.type="string"/>',
        '  <key id="etype" for="edge" attr.name="kind" attr.type="string"/>',
        '  <graph id="G" edgedefault="directed">',
    ]
    for n in nodes:
        lines.append(f"    <node id={quoteattr(n.id)}>")
        lines.append(f'      <data key="label">{escape(n.label)}</data>')
        lines.append(f'      <data key="kind">{escape(n.kind)}</data>')
        lines.append("    </node>")
    for i, e in enumerate(edges):
        lines.append(
            f'    <edge id="e{i}" source={quoteattr(e.source)} target={quoteattr(e.target)}>'
        )
        lines.append(f'      <data key="etype">{escape(e.kind)}</data>')
        lines.append("    </edge>")
    lines += ["  </graph>", "</graphml>"]
    return "\n".join(lines)


def export_drawio(nodes: list[GraphNode], edges: list[GraphEdge]) -> str:
    cells = ['        <mxCell id="0"/>', '        <mxCell id="1" parent="0"/>']
    idx = {n.id: str(i + 2) for i, n in enumerate(nodes)}
    for n in nodes:
        cells.append(
            f'        <mxCell id="{idx[n.id]}" value={quoteattr(n.label + " (" + n.kind + ")")} '
            'style="rounded=1;whiteSpace=wrap;html=1;" vertex="1" parent="1">'
        )
        cells.append('          <mxGeometry width="160" height="40" as="geometry"/>')
        cells.append("        </mxCell>")
    for i, e in enumerate(edges):
        if e.source in idx and e.target in idx:
            cells.append(
                f'        <mxCell id="edge{i}" style="edgeStyle=orthogonalEdgeStyle;html=1;" '
                f'edge="1" parent="1" source="{idx[e.source]}" target="{idx[e.target]}">'
            )
            cells.append('          <mxGeometry relative="1" as="geometry"/>')
            cells.append("        </mxCell>")
    return (
        '<mxGraphModel dx="800" dy="600" grid="1" guides="1" tooltips="1" connect="1" '
        'arrows="1" fold="1" page="1" pageScale="1">\n'
        "      <root>\n" + "\n".join(cells) + "\n      </root>\n</mxGraphModel>"
    )


def write_graph(data: dict, output_dir: str | Path) -> dict[str, Path]:
    """Write graph.json / graph.graphml / graph.drawio; return their paths."""
    nodes, edges = build_graph(data)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out / "graph.json",
        "graphml": out / "graph.graphml",
        "drawio": out / "graph.drawio",
    }
    paths["json"].write_text(export_json(nodes, edges), encoding="utf-8")
    paths["graphml"].write_text(export_graphml(nodes, edges), encoding="utf-8")
    paths["drawio"].write_text(export_drawio(nodes, edges), encoding="utf-8")
    return paths
