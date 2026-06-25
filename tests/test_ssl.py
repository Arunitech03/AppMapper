"""Tests for Module 4: SSL/TLS analysis (cert parsing & severity logic)."""

from __future__ import annotations

import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from modules.ssl.ssl_scanner import SSLModule


def _self_signed_der(host: str = "self.example.com") -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)  # self-signed: issuer == subject
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(host)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.DER)


def test_self_signed_cert_flagged(monkeypatch):
    module = SSLModule()
    monkeypatch.setattr(module, "_fetch_cert", lambda host, port, timeout: _self_signed_der())
    monkeypatch.setattr(
        module, "_probe_tls_versions", lambda host, port, timeout: ["TLSv1.2", "TLSv1.3"]
    )

    finding = module._inspect("self.example.com", 443, 2.0)
    assert finding is not None
    assert finding.is_self_signed is True
    assert finding.is_expired is False
    assert finding.severity == "high"
    assert "self.example.com" in finding.san_entries


async def test_run_skips_http(ctx_factory):
    result = await SSLModule().run(ctx_factory(url="http://plain.local"))
    assert result.ok
    assert result.items == 0
