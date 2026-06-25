"""Module 4: SSL/TLS analysis.

Connects to the target host and inspects the presented certificate (issuer,
validity window, SAN entries) and the set of negotiable TLS versions. Flags
expired and self-signed certificates as findings. This is observational only —
it establishes normal TLS handshakes and reads the certificate; it does not
attempt downgrade attacks or exploit weak ciphers.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from core.base import BaseModule
from models.schemas import ModuleResult, ScanContext, SSLFinding

TLS_VERSIONS: list[tuple[str, int]] = [
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
]


class SSLModule(BaseModule):
    name = "ssl"
    category = "ssl"

    async def run(self, ctx: ScanContext) -> ModuleResult:
        if not ctx.target.url.startswith("https"):
            self.log.info("ssl.skip_non_https", url=ctx.target.url)
            return ModuleResult(module=self.name, data=[], items=0)

        host = ctx.target.host
        port = ctx.target.port
        finding = await asyncio.to_thread(self._inspect, host, port, ctx.timeout)
        data = [finding.model_dump()] if finding else []
        return ModuleResult(module=self.name, data=data, items=len(data))

    def _inspect(self, host: str, port: int, timeout: float) -> SSLFinding | None:
        cert_der = self._fetch_cert(host, port, timeout)
        if cert_der is None:
            return None

        cert = x509.load_der_x509_certificate(cert_der)
        not_before = cert.not_valid_before_utc
        not_after = cert.not_valid_after_utc
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        san: list[str] = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            pass

        now = datetime.now(UTC)
        is_expired = not_after < now
        is_self_signed = cert.issuer == cert.subject
        tls_versions = self._probe_tls_versions(host, port, timeout)

        severity = "info"
        notes: list[str] = []
        if is_expired:
            severity = "high"
            notes.append("certificate is expired")
        if is_self_signed:
            severity = "high" if severity != "high" else severity
            notes.append("certificate is self-signed")
        if any(v in tls_versions for v in ("TLSv1.0", "TLSv1.1")):
            severity = "medium" if severity == "info" else severity
            notes.append("legacy TLS version supported")
        summary = "; ".join(notes) or "no certificate issues detected"

        return SSLFinding(
            host=host,
            port=port,
            issuer=issuer,
            subject=subject,
            not_before=not_before,
            not_after=not_after,
            san_entries=san,
            tls_versions=tls_versions,
            is_expired=is_expired,
            is_self_signed=is_self_signed,
            severity=severity,
            summary=summary,
        )

    def _fetch_cert(self, host: str, port: int, timeout: float) -> bytes | None:
        """Fetch the leaf certificate (DER) without verifying the chain.

        Verification is disabled deliberately so we can still inspect expired /
        self-signed certs (that's the point of the check).
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    der = ssock.getpeercert(binary_form=True)
                    return der
        except (OSError, ssl.SSLError) as exc:
            self.log.warning("ssl.fetch_failed", host=host, port=port, error=str(exc))
            return None

    def _probe_tls_versions(self, host: str, port: int, timeout: float) -> list[str]:
        supported: list[str] = []
        for label, version in TLS_VERSIONS:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.minimum_version = version
                ctx.maximum_version = version
            except ValueError:
                continue  # version not supported by local OpenSSL
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                        if ssock.version():
                            supported.append(label)
            except (OSError, ssl.SSLError):
                continue
        return supported


def _pem(cert: x509.Certificate) -> str:
    """Helper retained for debugging/tests: render a cert as PEM."""
    return cert.public_bytes(Encoding.PEM).decode()
