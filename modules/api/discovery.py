"""Module 9: API discovery.

Probes well-known API description endpoints (Swagger / OpenAPI / GraphQL) and, on
finding one, parses the specification into a structured endpoint inventory
(path + method + parameters). Read-only: it fetches and parses documents only.
"""

from __future__ import annotations

import asyncio

import httpx

from core.base import BaseModule
from core.http import client_for
from models.schemas import ApiEndpoint, ModuleResult, ScanContext

# Candidate specification locations to probe.
SPEC_PATHS = [
    "/swagger/v1/swagger.json",
    "/swagger.json",
    "/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/index.html",
]
GRAPHQL_PATHS = ["/graphql", "/api/graphql"]


class ApiDiscoveryModule(BaseModule):
    name = "api_discovery"
    category = "api"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        base = ctx.target.url
        endpoints: list[ApiEndpoint] = []

        async with client_for(ctx) as client:
            # Look for an OpenAPI/Swagger JSON spec.
            for path in SPEC_PATHS:
                spec = await self._fetch_json(client, base + path)
                if spec:
                    parsed = self._parse_openapi(spec)
                    if parsed:
                        self.log.info("api.spec_found", path=path, endpoints=len(parsed))
                        endpoints.extend(parsed)
                        break

            # Detect a GraphQL endpoint (presence only; no introspection queries).
            for path in GRAPHQL_PATHS:
                if await self._graphql_present(client, base + path):
                    endpoints.append(
                        ApiEndpoint(
                            path=path, method="POST", source="graphql", summary="GraphQL endpoint"
                        )
                    )
                    break

        # De-duplicate by (method, path).
        unique: dict[tuple[str, str], ApiEndpoint] = {}
        for ep in endpoints:
            unique.setdefault((ep.method, ep.path), ep)
        result = list(unique.values())
        return ModuleResult(
            module=self.name, data=[e.model_dump() for e in result], items=len(result)
        )

    async def _fetch_json(self, client: httpx.AsyncClient, url: str) -> dict | None:
        try:
            resp = await client.get(url)
            if resp.status_code == 200 and "json" in resp.headers.get("content-type", ""):
                return resp.json()
        except (httpx.HTTPError, ValueError):
            return None
        return None

    async def _graphql_present(self, client: httpx.AsyncClient, url: str) -> bool:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return False
        # GraphQL endpoints typically reject GET with 400/405 and mention "query".
        body = (resp.text or "").lower()
        return resp.status_code in {200, 400, 405} and ("graphql" in body or "query" in body)

    def _parse_openapi(self, spec: dict) -> list[ApiEndpoint]:
        paths = spec.get("paths")
        if not isinstance(paths, dict):
            return []

        source = "openapi" if str(spec.get("openapi", "")).startswith("3") else "swagger"
        endpoints: list[ApiEndpoint] = []
        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                if method.lower() not in {
                    "get",
                    "post",
                    "put",
                    "patch",
                    "delete",
                    "head",
                    "options",
                }:
                    continue
                params: list[str] = []
                summary = None
                if isinstance(op, dict):
                    summary = op.get("summary") or op.get("operationId")
                    for p in op.get("parameters", []) or []:
                        if isinstance(p, dict) and p.get("name"):
                            params.append(str(p["name"]))
                endpoints.append(
                    ApiEndpoint(
                        path=path,
                        method=method.upper(),
                        source=source,
                        parameters=params,
                        summary=summary,
                    )
                )
        return endpoints


async def _gather_first(*coros):  # pragma: no cover - small helper retained for extension
    return await asyncio.gather(*coros)
