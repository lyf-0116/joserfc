from .._rfc7797.util import is_rfc7797_enabled
from ..errors import (
    DecodeError,
    InvalidHeaderValueError,
    MissingAlgorithmError,
    UnsupportedHeaderError,
)
from ..registry import Header, reject_unprotected_crit_header
from ..util import json_b64decode, urlsafe_b64decode, urlsafe_b64encode
from .model import HeaderMember
from .registry import JWSRegistry

__all__ = [
    "build_signing_input",
    "decode_payload",
    "decode_protected_header",
    "encode_payload",
    "parse_header_member",
    "payload_is_base64_encoded",
    "prepare_member",
    "validate_member",
]


def build_signing_input(protected_segment: bytes, payload_segment: bytes) -> bytes:
    """Build the JWS Signing Input shared by compact and JSON serializations."""
    return protected_segment + b"." + payload_segment


def encode_payload(payload: bytes, is_base64_encoded: bool) -> bytes:
    if is_base64_encoded:
        return urlsafe_b64encode(payload)
    return payload


def decode_payload(payload_segment: bytes, is_base64_encoded: bool) -> bytes:
    if not is_base64_encoded:
        return payload_segment
    try:
        return urlsafe_b64decode(payload_segment)
    except (TypeError, ValueError) as err:
        raise DecodeError("Invalid payload") from err


def decode_protected_header(protected_segment: bytes, require_alg: bool = False) -> Header:
    try:
        protected = json_b64decode(protected_segment)
        if not isinstance(protected, dict):
            raise DecodeError("Invalid header")
        if require_alg and "alg" not in protected:
            raise MissingAlgorithmError()
    except (TypeError, ValueError) as err:
        raise DecodeError("Invalid header") from err
    return protected


def parse_header_member(
    protected_segment: bytes | None,
    header: Header | None,
    registry: JWSRegistry,
    require_alg: bool = False,
) -> HeaderMember:
    member = HeaderMember()
    if protected_segment:
        registry.validate_header_size(protected_segment)
        member.protected = decode_protected_header(protected_segment, require_alg)
    if header is not None:
        if not isinstance(header, dict):
            raise InvalidHeaderValueError("Invalid 'header' value: must be a JSON object")
        member.header = header
    return member


def payload_is_base64_encoded(member: HeaderMember) -> bool:
    # RFC7797: the "b64" header parameter MUST be protected.
    if member.header and "b64" in member.header:
        raise UnsupportedHeaderError("'b64' header MUST be protected")
    return not is_rfc7797_enabled(member.protected or {})


def prepare_member(member: HeaderMember, registry: JWSRegistry) -> tuple[Header, bool]:
    reject_unprotected_crit_header(member.header, member.protected)
    headers = member.headers()
    registry.check_header(headers)
    return headers, payload_is_base64_encoded(member)


def validate_member(member: HeaderMember, registry: JWSRegistry) -> Header:
    headers, _ = prepare_member(member, registry)
    return headers
