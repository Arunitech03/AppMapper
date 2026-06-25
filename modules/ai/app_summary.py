"""Feature 9: human-readable application summary.

A provider abstraction generates a summary from a structured *facts* dict:

  * ``TemplateProvider``        — deterministic, offline, no LLM (the default).
  * ``OllamaProvider``          — local Ollama (``/api/generate``).
  * ``OpenAICompatibleProvider``— any OpenAI-compatible chat endpoint.

The facts are derived purely from already-discovered data; the summary describes
and prioritizes — it never instructs or performs any exploitation.
"""

from __future__ import annotations

import abc

import httpx

from core.logging import get_logger
from models.schemas import AppSummary

log = get_logger("ai")

# Sensitive-function labels considered high-risk areas for manual review.
HIGH_RISK_LABELS = {
    "Upload",
    "Export",
    "Download",
    "Password Reset",
    "MFA",
    "Admin",
    "Users",
    "Roles",
    "Permissions",
}


def build_facts(data: dict) -> dict:
    """Derive the structured facts the summary is built from."""
    techs = data.get("technologies", [])
    technology = {
        "frontend": [t["name"] for t in techs if t["category"] == "frontend"],
        "backend": [t["name"] for t in techs if t["category"] == "backend"],
        "servers": [t["name"] for t in techs if t["category"] == "server"],
        "libraries": [t["name"] for t in techs if t["category"] == "library"],
    }

    roles = [u["role"] for u in data.get("users", [])]
    if data.get("crawl_endpoints") and "anonymous" not in roles:
        roles = ["anonymous", *roles]

    functions = data.get("sensitive_functions", [])
    functional_areas = sorted({f["category"] for f in functions})
    high_risk = sorted(
        {
            f"{f['category']}: {f['subcategory']}"
            for f in functions
            if f.get("subcategory") in HIGH_RISK_LABELS
        }
    )

    # Structured infrastructure metadata (NEVER raw HAR/responses/JS — only
    # counts, hostnames, service/module/dependency names).
    from modules.intelligence.asset_inventory import build_asset_intelligence
    from modules.intelligence.domain_classifier import build_domain_intel

    di = build_domain_intel(data)
    asset = build_asset_intelligence(data)
    infra = di.get("infrastructure_summary", {})
    auth = di.get("auth_infra", {})
    dependencies = list(infra.get("dependencies", []))
    if auth.get("identity_provider") and auth["identity_provider"] != "Unknown":
        dependencies = [auth["identity_provider"], *dependencies]

    return {
        "target": data.get("target", {}),
        "technology": technology,
        "roles": roles,
        "functional_areas": functional_areas,
        "high_risk_areas": high_risk,
        "infrastructure": {
            "internal_apis": infra.get("internal_apis", 0),
            "auth_providers": infra.get("auth_providers", 0),
            "third_party": infra.get("third_party", 0),
            "analytics": infra.get("analytics", 0),
            "cdn": infra.get("cdn", 0),
            "payment": infra.get("payment", 0),
            "dependencies": dependencies,
            "api_gateways": asset["infrastructure"].get("api_gateways", []),
            "backend_services": asset.get("services", []),
            "related_applications": asset["infrastructure"].get("related_applications", []),
        },
        "business_modules": [m["module"] for m in asset.get("business_modules", [])[:8]],
        "attack_surface": [a["area"] for a in asset.get("attack_surface", [])[:6]],
        "counts": {
            "crawl_endpoints": len(data.get("crawl_endpoints", [])),
            "apis": len(data.get("api_intel", [])),
            "sensitive_functions": len(functions),
        },
    }


def _prompt(facts: dict) -> str:
    return (
        "You are a security analyst. Using ONLY the facts below, write a concise, "
        "non-exploitative application summary with these sections: Technology, Roles, "
        "Major Functional Areas, High-Risk Areas For Manual Review. Do not suggest "
        "exploits.\n\nFACTS:\n" + _render_facts_block(facts)
    )


def _render_facts_block(facts: dict) -> str:
    t = facts["technology"]
    infra = facts.get("infrastructure", {})
    lines = [
        f"Frontend: {', '.join(t['frontend']) or 'none detected'}",
        f"Backend: {', '.join(t['backend']) or 'none detected'}",
        f"Servers: {', '.join(t['servers']) or 'none detected'}",
        f"Libraries: {', '.join(t['libraries']) or 'none detected'}",
        f"Roles: {', '.join(facts['roles']) or 'none'}",
        f"Functional areas: {', '.join(facts['functional_areas']) or 'none'}",
        f"High-risk areas: {', '.join(facts['high_risk_areas']) or 'none'}",
        f"Internal APIs: {infra.get('internal_apis', 0)}, "
        f"Auth providers: {infra.get('auth_providers', 0)}, "
        f"Third-party services: {infra.get('third_party', 0)}",
        f"API gateways: {', '.join(infra.get('api_gateways', [])) or 'none'}",
        f"Backend services: {', '.join(infra.get('backend_services', [])) or 'none'}",
        f"Related applications: {', '.join(infra.get('related_applications', [])) or 'none'}",
        f"Dependencies: {', '.join(infra.get('dependencies', [])) or 'none'}",
        f"Business modules: {', '.join(facts.get('business_modules', [])) or 'none'}",
        f"Attack-surface focus: {', '.join(facts.get('attack_surface', [])) or 'none'}",
    ]
    return "\n".join(lines)


class SummaryProvider(abc.ABC):
    name = "base"

    @abc.abstractmethod
    def generate(self, facts: dict) -> str: ...


class TemplateProvider(SummaryProvider):
    """Deterministic, offline summary renderer (default)."""

    name = "template"

    def generate(self, facts: dict) -> str:
        t = facts["technology"]
        tech_lines = []
        for cat in ("backend", "frontend", "servers", "libraries"):
            for item in t[cat]:
                tech_lines.append(f"- {item}")
        if not tech_lines:
            tech_lines = ["- (none detected)"]

        roles = facts["roles"] or ["(none configured)"]
        areas = facts["functional_areas"] or ["(none detected)"]
        high = facts["high_risk_areas"] or ["(none detected)"]

        infra = facts.get("infrastructure", {})
        out = ["Application Summary", "", "Technology:"]
        out += tech_lines
        out += ["", "Roles:"]
        out += [f"- {r}" for r in roles]
        out += ["", "Major Functional Areas:"]
        out += [f"- {a}" for a in areas]
        out += ["", "High-Risk Areas For Manual Review:"]
        out += [f"- {h}" for h in high]
        # Business Module Summary.
        modules = facts.get("business_modules") or []
        if modules:
            out += ["", "Major Business Modules:"]
            out += [f"- {m}" for m in modules]

        # Infrastructure overview (from domain + asset intelligence).
        if any(infra.get(k) for k in ("internal_apis", "auth_providers", "third_party")):
            out += ["", "Infrastructure:"]
            out += [
                f"- {infra.get('internal_apis', 0)} Internal APIs",
                f"- {infra.get('auth_providers', 0)} Authentication Providers",
                f"- {infra.get('third_party', 0)} Third-Party Services",
            ]
            if infra.get("api_gateways"):
                out += [f"- API Gateway: {', '.join(infra['api_gateways'])}"]
            if infra.get("backend_services"):
                out += [f"- Backend Services: {', '.join(infra['backend_services'])}"]
            if infra.get("related_applications"):
                out += [f"- Related Applications: {', '.join(infra['related_applications'])}"]
            if infra.get("dependencies"):
                out += ["", "Primary Dependencies:"]
                out += [f"- {d}" for d in infra["dependencies"]]

        # Pentest Focus Areas / Attack-Surface Prioritization.
        focus = facts.get("attack_surface") or []
        if focus:
            out += ["", "Pentest Focus Areas (prioritized):"]
            out += [f"{i}. {a}" for i, a in enumerate(focus, 1)]
        return "\n".join(out)


class OllamaProvider(SummaryProvider):
    name = "ollama"

    def __init__(self, base_url: str = "http://localhost:11434", model: str = "llama3") -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model

    def generate(self, facts: dict) -> str:
        resp = httpx.post(
            f"{self.base_url}/api/generate",
            json={"model": self.model, "prompt": _prompt(facts), "stream": False},
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json().get("response", "").strip()


class OpenAICompatibleProvider(SummaryProvider):
    name = "openai_compatible"

    def __init__(
        self, base_url: str, model: str = "gpt-4o-mini", api_key: str | None = None
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.api_key = api_key

    def generate(self, facts: dict) -> str:
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        resp = httpx.post(
            f"{self.base_url}/v1/chat/completions",
            headers=headers,
            json={
                "model": self.model,
                "messages": [{"role": "user", "content": _prompt(facts)}],
            },
            timeout=60.0,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()


def get_provider(
    name: str = "template",
    *,
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> SummaryProvider:
    if name == "ollama":
        return OllamaProvider(base_url or "http://localhost:11434", model or "llama3")
    if name == "openai_compatible":
        if not base_url:
            raise ValueError("openai_compatible provider requires base_url")
        return OpenAICompatibleProvider(base_url, model or "gpt-4o-mini", api_key)
    return TemplateProvider()


def generate_summary(
    data: dict,
    *,
    provider: str = "template",
    base_url: str | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> AppSummary:
    """Generate an application summary, falling back to the template on LLM error."""
    facts = build_facts(data)
    prov = get_provider(provider, base_url=base_url, model=model, api_key=api_key)
    try:
        text = prov.generate(facts)
        used = prov.name
    except Exception as exc:  # noqa: BLE001 - LLM optional; degrade to template
        log.warning("ai.provider_failed", provider=provider, error=str(exc))
        text = TemplateProvider().generate(facts)
        used = "template"
    return AppSummary(provider=used, text=text)
