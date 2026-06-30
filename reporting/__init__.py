"""Report generation: JSON, Markdown, HTML + attack-surface graph exports."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from models.schemas import GraphEdge, GraphNode
from modules.intelligence.domain_classifier import build_domain_intel
from modules.intelligence.graph_builder import (
    export_drawio,
    export_graphml,
    export_json,
    write_graph,
)
from reporting.html_report import write_html_report
from reporting.json_report import write_json_report
from reporting.markdown_report import write_markdown_report

__all__ = [
    "write_json_report",
    "write_markdown_report",
    "write_html_report",
    "write_reports",
]


def _next_version(out: Path) -> int:
    """Next ``report_<N>`` index for this folder (max existing + 1)."""
    import re

    highest = 0
    for p in out.glob("report_*.html"):
        m = re.fullmatch(r"report_(\d+)\.html", p.name)
        if m:
            highest = max(highest, int(m.group(1)))
    return highest + 1


def write_reports(
    data: dict[str, list[dict]],
    output_dir: str | Path,
    *,
    version: bool = False,
    **summary_opts: Any,
) -> dict[str, Path]:
    """Write the consolidated Tier-2 report set + graph exports.

    Produces ``report.md`` / ``report.html`` / ``report.json`` plus
    ``graph.{json,graphml,drawio}``. Also keeps Tier-1 ``output.{md,json}`` for
    back-compat. Returns a name->path mapping.

    When ``version`` is set, each run also keeps a numbered snapshot
    (``report_<N>.{json,md,html}``) alongside the always-latest ``report.*`` — so
    successive scans in the same folder don't overwrite previous results.
    """
    out = Path(output_dir)
    paths: dict[str, Path] = {}
    paths["json"] = write_json_report(data, output_dir, filename="report.json", **summary_opts)
    paths["md"] = write_markdown_report(data, output_dir, filename="report.md", **summary_opts)
    paths["html"] = write_html_report(data, output_dir, filename="report.html", **summary_opts)
    if version:
        import shutil

        n = _next_version(out)
        for ext in ("json", "md", "html"):
            dst = out / f"report_{n}.{ext}"
            shutil.copy2(out / f"report.{ext}", dst)
            paths[f"snapshot_{ext}"] = dst
    # Back-compat Tier-1 filenames.
    write_json_report(data, output_dir, filename="output.json", **summary_opts)
    write_markdown_report(data, output_dir, filename="output.md", **summary_opts)
    # Graph exports (attack-surface graph + domain relationship graph).
    graph_paths = write_graph(data, output_dir)
    paths.update({f"graph_{k}": v for k, v in graph_paths.items()})
    paths.update(_write_domain_graph(data, output_dir))
    return paths


def _write_domain_graph(data: dict, output_dir: str | Path) -> dict[str, Path]:
    """Export the application→domain relationship graph as JSON/GraphML/Draw.io."""
    di = build_domain_intel(data)
    rel = di.get("relationships", {})
    base = rel.get("base", "")
    if not base:
        return {}
    nodes = [GraphNode(id=base, label=base, kind="Primary Application")]
    edges = []
    for h in di.get("hosts", []):
        if h["host"] == base:
            continue
        nodes.append(GraphNode(id=h["host"], label=h["host"], kind=h["classification"]))
        edges.append(GraphEdge(source=base, target=h["host"], kind=h["classification"]))

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    written = {
        "domain_graph_json": out / "domain_graph.json",
        "domain_graph_graphml": out / "domain_graph.graphml",
        "domain_graph_drawio": out / "domain_graph.drawio",
    }
    written["domain_graph_json"].write_text(export_json(nodes, edges), encoding="utf-8")
    written["domain_graph_graphml"].write_text(export_graphml(nodes, edges), encoding="utf-8")
    written["domain_graph_drawio"].write_text(export_drawio(nodes, edges), encoding="utf-8")
    return written
