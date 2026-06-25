"""Sprint B.2 Feature 2: Runtime Configuration Risk Analysis.

Turns the raw runtime-config findings (from ``runtime_config_discovery``) into
security observations a pentester cares about: authentication infrastructure,
administrative role definitions, GIS infrastructure, tenant model and feature
flags exposed in frontend configuration. Pure/offline; values stay masked where
already masked.
"""

from __future__ import annotations

import re

# A role value looks like UPPER_SNAKE / mixed RBAC identifier.
_ROLE_VALUE_RE = re.compile(r"^[A-Za-z]{2,}[A-Za-z0-9_]*$")
_ADMIN_RE = re.compile(r"(?i)(admin|superuser|root|implementer|supervisor)")
_GIS_KEY_RE = re.compile(r"(?i)(geoserver|workspace|layer|vector|wms|wfs|map_)")
_TENANT_RE = re.compile(r"(?i)(tenant)")


def _runtime(data: dict) -> list[dict]:
    return [f for f in data.get("intel_findings", []) or [] if f.get("kind") == "runtime_config"]


def _raw_key(f: dict) -> str:
    return (f.get("extra") or {}).get("raw_key") or f.get("name", "")


def build_runtime_config_risks(data: dict) -> list[dict]:
    """Return runtime-config risk findings ``[{title, severity, confidence, evidence}]``."""
    rc = _runtime(data)
    risks: list[dict] = []

    # 1) Authentication infrastructure.
    auth_ev = [
        f"{f['name']}: {f.get('value_masked')}"
        for f in rc
        if f["name"]
        in {"Keycloak Realm", "Keycloak Client ID", "API Gateway URL", "Authentication URL"}
    ]
    if auth_ev:
        risks.append(
            {
                "title": "Authentication infrastructure exposed in frontend configuration",
                "severity": "Medium",
                "confidence": "high",
                "evidence": auth_ev,
            }
        )

    # 2) Administrative role definitions.
    role_values = []
    admin_roles = []
    for f in rc:
        key = _raw_key(f)
        val = f.get("value_masked")
        is_role = "ROLE" in key.upper() or (
            isinstance(val, str) and _ROLE_VALUE_RE.match(val) and ("_" in val) and val.isupper()
        )
        if is_role and isinstance(val, str):
            role_values.append(val)
            if _ADMIN_RE.search(val) or _ADMIN_RE.search(key):
                admin_roles.append(val)
    if admin_roles:
        risks.append(
            {
                "title": "Administrative roles exposed in frontend configuration",
                "severity": "High",
                "confidence": "high",
                "evidence": sorted(set(admin_roles))[:20],
            }
        )
    elif role_values:
        risks.append(
            {
                "title": "Role definitions exposed in frontend configuration",
                "severity": "Medium",
                "confidence": "high",
                "evidence": sorted(set(role_values))[:20],
            }
        )

    # 3) GIS infrastructure.
    gis_ev = [
        f"{_raw_key(f)}: {f.get('value_masked')}" for f in rc if _GIS_KEY_RE.search(_raw_key(f))
    ]
    if gis_ev:
        risks.append(
            {
                "title": "GIS infrastructure exposed in frontend configuration",
                "severity": "Low",
                "confidence": "high",
                "evidence": gis_ev[:15],
            }
        )

    # 4) Tenant model.
    tenant_ev = [
        f"{_raw_key(f)}: {f.get('value_masked')}" for f in rc if _TENANT_RE.search(_raw_key(f))
    ]
    if tenant_ev:
        risks.append(
            {
                "title": "Tenant configuration exposed in frontend configuration",
                "severity": "Informational",
                "confidence": "high",
                "evidence": tenant_ev[:10],
            }
        )

    # 5) Feature flags exposed.
    flags = [f for f in data.get("intel_findings", []) or [] if f.get("kind") == "feature_flag"]
    if flags:
        enabled = [f["name"] for f in flags if (f.get("extra") or {}).get("enabled") is True]
        risks.append(
            {
                "title": "Feature flags exposed in frontend configuration",
                "severity": "Informational",
                "confidence": "high",
                "evidence": [
                    f"{len(flags)} flags ({len(enabled)} enabled): " + ", ".join(enabled[:8])
                ],
            }
        )

    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    risks.sort(key=lambda r: sev_order.get(r["severity"], 5))
    return risks
