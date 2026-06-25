"""Role-based access comparison logic.

For each configured role we determine GET-reachability of the endpoint universe
(built-in paths + wordlist + paths observed in any role's captures), using that
role's own authentication. From the resulting per-role observations we build:

  * an **access matrix** : endpoint -> {role -> accessible?}
  * a **role difference** analysis : per-role-exclusive endpoints + shared ones

Scope: discovery only. We issue read-only GET requests with each role's supplied
credentials/JWT. We do NOT log in programmatically, brute force, escalate
privileges, or test for authorization bypass — we simply observe what each role
can already reach and report the differences.
"""

from __future__ import annotations

from urllib.parse import urlparse

from core.logging import get_logger
from models.schemas import (
    RoleEndpointAccess,
    ScanContext,
    UserCredential,
)
from modules.recon.directories import DirectoryEnumModule
from parsers.burp_parser import parse_burp
from parsers.har_parser import parse_har

log = get_logger("access")

# A response is treated as "reachable" for a role only at 2xx. 401/403 are explicit
# denials, and 3xx is typically a redirect to a login page (i.e. NOT accessible
# for that role) — so redirects are recorded as not accessible for the matrix.
ACCESSIBLE_STATUSES = {200, 201, 202, 203, 204, 206}


def _endpoint_key(method: str, path: str) -> str:
    return f"{method.upper()} {path}"


def capture_paths(user: UserCredential) -> list[str]:
    """Extract distinct request paths from a role's HAR/Burp captures (if any)."""
    paths: set[str] = set()
    if user.har:
        try:
            for r in parse_har(user.har):
                paths.add(urlparse(r.url).path or "/")
        except (OSError, ValueError) as exc:
            log.warning("access.har_failed", role=user.role, error=str(exc))
    if user.burp:
        try:
            for r in parse_burp(user.burp):
                paths.add(urlparse(r.url).path or "/")
        except (OSError, ValueError) as exc:
            log.warning("access.burp_failed", role=user.role, error=str(exc))
    return sorted(p for p in paths if p)


async def build_access_records(ctx: ScanContext) -> list[RoleEndpointAccess]:
    """Probe the endpoint universe once per role and return access observations.

    Roles with a JWT are probed live (authenticated GETs). Roles without a token
    are still probed (anonymously) so the matrix shows what is reachable without
    their credentials; their captured paths additionally contribute to the
    universe so cross-role reachability is comparable.
    """
    users = ctx.users
    if not users:
        return []

    # Universe of extra paths = union of every role's captured request paths.
    extra: set[str] = set()
    for user in users:
        extra.update(capture_paths(user))

    records: list[RoleEndpointAccess] = []
    for user in users:
        uctx = ctx.for_user(user)
        uctx = uctx.model_copy(update={"options": {**uctx.options, "extra_paths": sorted(extra)}})
        result = await DirectoryEnumModule().safe_run(uctx)
        for hit in result.data or []:
            status = hit["status_code"]
            records.append(
                RoleEndpointAccess(
                    role=user.role,
                    method="GET",
                    path=hit["path"],
                    url=hit["url"],
                    status_code=status,
                    accessible=status in ACCESSIBLE_STATUSES,
                    source="live",
                )
            )
        log.info(
            "access.role_probed",
            role=user.role,
            authenticated=user.can_authenticate,
            endpoints=len(result.data or []),
        )
    return records


def access_matrix(records: list[RoleEndpointAccess]) -> dict[str, dict[str, bool]]:
    """Build endpoint -> {role -> accessible} from access records."""
    matrix: dict[str, dict[str, bool]] = {}
    for rec in records:
        key = _endpoint_key(rec.method, rec.path)
        matrix.setdefault(key, {})
        # If multiple observations exist for a role+endpoint, accessible wins.
        matrix[key][rec.role] = matrix[key].get(rec.role, False) or rec.accessible
    return matrix


def role_difference(records: list[RoleEndpointAccess]) -> dict[str, object]:
    """Compute per-role-exclusive and shared endpoints from access records.

    Returns a dict with:
      - ``roles``        : list of role names seen
      - ``accessible``   : {role -> [endpoints it can reach]}
      - ``exclusive``    : {role -> [endpoints only it can reach]}
      - ``shared``       : [endpoints reachable by every role]
    With the conventional ``admin`` / ``user`` roles, ``exclusive['admin']`` is
    the admin-only surface and ``exclusive['user']`` the user-only surface.
    """
    matrix = access_matrix(records)
    roles = sorted({rec.role for rec in records})

    accessible: dict[str, list[str]] = {r: [] for r in roles}
    for endpoint, role_map in matrix.items():
        for role in roles:
            if role_map.get(role):
                accessible[role].append(endpoint)
    for r in roles:
        accessible[r].sort()

    exclusive: dict[str, list[str]] = {r: [] for r in roles}
    shared: list[str] = []
    for endpoint, role_map in matrix.items():
        can = [r for r in roles if role_map.get(r)]
        if len(can) == 1:
            exclusive[can[0]].append(endpoint)
        elif len(can) == len(roles) and len(roles) > 1:
            shared.append(endpoint)
    for r in roles:
        exclusive[r].sort()
    shared.sort()

    return {
        "roles": roles,
        "accessible": accessible,
        "exclusive": exclusive,
        "shared": shared,
    }
