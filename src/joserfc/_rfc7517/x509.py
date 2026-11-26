import base64
import binascii
import hmac
import os
import ssl
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization

from ..errors import InvalidCertificateChainError, KeyParameterError

CertificateDigestMethod = Literal["sha1", "sha256"]


def _decode_base64(value: str) -> bytes:
    data = "".join(value.split())
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        try:
            return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        except (binascii.Error, ValueError) as error:
            raise KeyParameterError("'x5c' contains an invalid certificate") from error


def _load_x5c_certificate(value: str) -> x509.Certificate:
    if not isinstance(value, str):
        raise KeyParameterError("'x5c' must be a list of strings")

    if "BEGIN CERTIFICATE" in value:
        try:
            return x509.load_pem_x509_certificate(value.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as error:
            raise KeyParameterError("'x5c' contains an invalid certificate") from error

    raw = _decode_base64(value)
    try:
        return x509.load_der_x509_certificate(raw)
    except ValueError as error:
        raise KeyParameterError("'x5c' contains an invalid certificate") from error


def load_certificate_chain(value: list[str]) -> list[x509.Certificate]:
    if not value:
        raise KeyParameterError("'x5c' must contain at least one certificate")
    return [_load_x5c_certificate(item) for item in value]


def certificate_thumbprint(cert: x509.Certificate, digest_method: CertificateDigestMethod = "sha256") -> str:
    if digest_method == "sha1":
        digest = cert.fingerprint(hashes.SHA1())
    elif digest_method == "sha256":
        digest = cert.fingerprint(hashes.SHA256())
    else:  # pragma: no cover
        raise ValueError(f"Unsupported digest method: {digest_method}")
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _decode_fingerprint(value: str) -> bytes | None:
    data = value.strip()
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError):
        pass
    return None


def fingerprints_equal(left: str, right: str) -> bool:
    left_bytes = _decode_fingerprint(left)
    right_bytes = _decode_fingerprint(right)
    if left_bytes is not None and right_bytes is not None:
        return hmac.compare_digest(left_bytes, right_bytes)
    return hmac.compare_digest(left.rstrip("=").encode("utf-8"), right.rstrip("=").encode("utf-8"))


def public_key_der(key: Any) -> bytes:
    value: bytes = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return value


def certificate_matches_public_key(cert: x509.Certificate, public_key: Any) -> bool:
    try:
        key_der = public_key_der(public_key)
    except (AttributeError, TypeError, ValueError):
        return False
    return hmac.compare_digest(public_key_der(cert.public_key()), key_der)


def check_certificate_matches_public_key(cert: x509.Certificate, public_key: Any) -> None:
    if not certificate_matches_public_key(cert, public_key):
        raise KeyParameterError("'x5c' certificate does not match the key")


def _load_certificates_from_bytes(value: bytes) -> list[x509.Certificate]:
    if b"BEGIN CERTIFICATE" in value:
        try:
            return list(x509.load_pem_x509_certificates(value))
        except ValueError as error:
            raise KeyParameterError("Invalid X.509 certificate") from error

    try:
        return [x509.load_der_x509_certificate(value)]
    except ValueError as error:
        raise KeyParameterError("Invalid X.509 certificate") from error


def _load_trust_value(value: Any) -> list[x509.Certificate]:
    if isinstance(value, x509.Certificate):
        return [value]
    certificates = getattr(value, "x5c_certificates", None)
    if certificates:
        return list(certificates)
    if isinstance(value, (bytes, bytearray)):
        return _load_certificates_from_bytes(bytes(value))
    if isinstance(value, str):
        if "BEGIN CERTIFICATE" in value:
            return _load_certificates_from_bytes(value.encode("utf-8"))
        path = Path(value).expanduser()
        if path.is_file():
            return _load_certificates_from_bytes(path.read_bytes())
        return [_load_x5c_certificate(value)]
    if isinstance(value, os.PathLike):
        return _load_certificates_from_bytes(Path(value).expanduser().read_bytes())
    if isinstance(value, dict):
        chain = value.get("x5c")
        if isinstance(chain, list):
            return load_certificate_chain(chain)
        raise KeyParameterError("Invalid X.509 certificate")
    if isinstance(value, Iterable):
        certs: list[x509.Certificate] = []
        for item in value:
            certs.extend(_load_trust_value(item))
        return certs
    raise KeyParameterError("Invalid X.509 certificate")


def load_trust_anchors(value: Any) -> list[x509.Certificate]:
    if value is None:
        return []
    return _load_trust_value(value)


@lru_cache(maxsize=1)
def _system_trust_anchors() -> tuple[x509.Certificate, ...]:
    certs: list[x509.Certificate] = []
    context = ssl.create_default_context()
    for value in context.get_ca_certs(binary_form=True):
        try:
            certs.append(x509.load_der_x509_certificate(value))
        except ValueError:  # pragma: no cover
            continue
    return tuple(certs)


def _certificate_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _is_trust_anchor(cert: x509.Certificate, anchors: list[x509.Certificate]) -> bool:
    cert_der = _certificate_der(cert)
    return any(hmac.compare_digest(cert_der, _certificate_der(anchor)) for anchor in anchors)


def _check_validity(cert: x509.Certificate, at_time: datetime) -> None:
    if at_time < cert.not_valid_before_utc or at_time > cert.not_valid_after_utc:
        raise InvalidCertificateChainError("X.509 certificate is expired or not yet valid")


def _check_issuer_constraints(issuer: x509.Certificate) -> None:
    try:
        basic_constraints = issuer.extensions.get_extension_for_class(x509.BasicConstraints).value
    except x509.ExtensionNotFound:
        basic_constraints = None

    if basic_constraints is not None and not basic_constraints.ca:
        raise InvalidCertificateChainError("X.509 certificate issuer is not a CA")

    try:
        key_usage = issuer.extensions.get_extension_for_class(x509.KeyUsage).value
    except x509.ExtensionNotFound:
        key_usage = None

    if key_usage is not None and not key_usage.key_cert_sign:
        raise InvalidCertificateChainError("X.509 certificate issuer can not sign certificates")


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
    except (InvalidSignature, TypeError, ValueError):
        return False
    return True


def _find_issuer(cert: x509.Certificate, candidates: list[x509.Certificate]) -> x509.Certificate | None:
    for candidate in candidates:
        if _issued_by(cert, candidate):
            return candidate
    return None


def verify_certificate_chain(
    certificates: list[x509.Certificate],
    trust_anchors: Any = None,
    at_time: datetime | None = None,
) -> None:
    if not certificates:
        return

    anchors = load_trust_anchors(trust_anchors)
    if not anchors:
        anchors = list(_system_trust_anchors())
    if not anchors:
        raise InvalidCertificateChainError("No X.509 trust anchors are available")

    now = at_time or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    for cert in certificates:
        _check_validity(cert, now)

    for index, cert in enumerate(certificates[:-1]):
        issuer = certificates[index + 1]
        if not _issued_by(cert, issuer):
            raise InvalidCertificateChainError("Invalid X.509 certificate chain")
        _check_issuer_constraints(issuer)

    last = certificates[-1]
    if _is_trust_anchor(last, anchors):
        return

    anchor = _find_issuer(last, anchors)
    if anchor is None:
        raise InvalidCertificateChainError("X.509 certificate chain is not trusted")

    _check_validity(anchor, now)
    _check_issuer_constraints(anchor)
