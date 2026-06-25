"""Feature 2: Application workflow mapping.

Builds page-to-page relationships from authenticated-crawl link structure, HAR/Burp
request sequences, and renders an indented ASCII workflow tree. Analysis only.
"""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from models.schemas import WorkflowEdge


def _path(url: str) -> str:
    return urlparse(url).path or "/"


# Static-asset noise to exclude from the workflow (Issue 8): prioritize pages,
# forms, APIs and user actions — drop tiles/fonts/styles/scripts/images.
NOISE_EXTENSIONS = (
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".css",
    ".js",
    ".map",
    ".mp4",
    ".webm",
)
NOISE_TOKENS = (
    "mapbox",
    "wmts",
    "/tiles",
    "tile/",
    "/fonts",
    "basemap",
    ".blob.",
    "gstatic",
    "cdnjs",
    "/sprite",
)


def _is_noise(path: str) -> bool:
    low = (path or "").lower()
    return low.endswith(NOISE_EXTENSIONS) or any(tok in low for tok in NOISE_TOKENS)


def build_workflow(data: dict) -> list[WorkflowEdge]:
    """Derive workflow edges from crawl link structure + capture sequences.

    Static assets (tiles, fonts, css/js, images, blobs) are filtered out so the
    workflow reflects pages / forms / APIs / user actions, not noise.
    """
    edges: dict[tuple[str, str, str], WorkflowEdge] = {}

    # 1) Crawl link structure: page -> linked page (we approximate with same-role
    #    reachable paths under a common parent).
    crawl = data.get("crawl_endpoints", [])
    by_role_paths: dict[str, list[str]] = {}
    for ep in crawl:
        if not _is_noise(ep["path"]):
            by_role_paths.setdefault(ep["role"], []).append(ep["path"])

    for role, paths in by_role_paths.items():
        uniq = sorted(set(paths))
        for p in uniq:
            parent = _parent(p)
            if parent and parent != p and (parent in uniq or parent == "/"):
                key = (parent, p, "link")
                edges.setdefault(
                    key, WorkflowEdge(role=role, from_path=parent, to_path=p, kind="link")
                )

    # 2) Capture sequences: consecutive requests imply a navigation/workflow step.
    for cap_key in ("har_requests", "burp_requests"):
        seq = [
            _path(r["url"])
            for r in data.get(cap_key, [])
            if r.get("url") and not _is_noise(_path(r["url"]))
        ]
        for a, b in zip(seq, seq[1:], strict=False):
            if a != b:
                key = (a, b, "sequence")
                edges.setdefault(key, WorkflowEdge(from_path=a, to_path=b, kind="sequence"))

    return list(edges.values())


def _parent(path: str) -> str:
    path = path.rstrip("/")
    if "/" not in path[1:]:
        return "/"
    return path.rsplit("/", 1)[0] or "/"


def render_tree(edges: list[WorkflowEdge], root: str = "/") -> str:
    """Render an indented ASCII tree from workflow edges."""
    children: dict[str, list[str]] = {}
    for e in edges:
        children.setdefault(e.from_path, [])
        if e.to_path not in children[e.from_path]:
            children[e.from_path].append(e.to_path)

    lines: list[str] = []
    visited: set[str] = set()

    def walk(node: str, depth: int) -> None:
        if node in visited or depth > 12:
            return
        visited.add(node)
        lines.append(("  " * depth) + ("└── " if depth else "") + (node or "/"))
        for child in sorted(children.get(node, [])):
            walk(child, depth + 1)

    start = root if root in children else (sorted(children)[0] if children else root)
    walk(start, 0)
    # Append any disconnected subtrees.
    for node in sorted(children):
        if node not in visited:
            walk(node, 0)
    return "\n".join(lines)


# Convenience for callers that want absolute URLs resolved against a base.
def absolute(base: str, href: str) -> str:
    return urljoin(base + "/", href)
