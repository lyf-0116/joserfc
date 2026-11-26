import re
from typing import Any

from .._rfc7515.message import (
    build_signing_input,
    decode_payload,
    encode_payload,
    parse_header_member,
    payload_is_base64_encoded,
)
from .._rfc7515.model import CompactSignature, JWSAlgModel
from .._rfc7515.registry import JWSRegistry, default_registry
from ..errors import DecodeError
from ..util import (
    json_b64encode,
    to_bytes,
    to_str,
    urlsafe_b64encode,
)


def sign_rfc7515_compact(obj: CompactSignature, alg: JWSAlgModel, key: Any) -> bytes:
    header_segment = json_b64encode(obj.headers())
    signing_input = build_signing_input(header_segment, obj.payload)
    signature = urlsafe_b64encode(alg.sign(signing_input, key))

    # if need to detach payload
    if __is_urlsafe_characters(obj.payload):
        out = signing_input + b"." + signature
    else:
        out = header_segment + b".." + signature
    return out


def extract_rfc7515_compact(
    value: bytes, payload: bytes | str | None = None, registry: JWSRegistry | None = None
) -> CompactSignature:
    """Extract the JWS Compact Serialization from bytes to object.

    :param value: JWS in bytes
    :param payload: optional payload, required with detached content
    :param registry: optional JWSRegistry instance
    :raise DecodeError: when decoding fails
    """
    if registry is None:
        registry = default_registry

    registry.validate_compact_value_size(value)

    parts = value.split(b".")
    if len(parts) != 3:
        raise DecodeError("Invalid JSON Web Signature")

    header_segment, payload_segment, signature_segment = parts
    registry.validate_signature_size(signature_segment)
    if payload_segment:
        registry.validate_payload_size(payload_segment)

    member = parse_header_member(header_segment, None, registry, require_alg=True)
    is_base64_encoded = payload_is_base64_encoded(member)

    if not payload_segment and payload is not None:
        payload_value = to_bytes(payload)
        registry.validate_payload_size(payload_value)
        payload_segment = encode_payload(payload_value, is_base64_encoded)
    else:
        payload_value = decode_payload(payload_segment, is_base64_encoded)

    obj = CompactSignature(member.protected or {}, payload_value)
    obj.member = member
    obj.segments.update(
        {
            "header": header_segment,
            "payload": payload_segment,
            "signature": signature_segment,
        }
    )
    return obj


# https://datatracker.ietf.org/doc/html/rfc7797#section-5.2
# the application MUST ensure that the payload contains only the URL-safe
# characters 'a'-'z', 'A'-'Z', '0'-'9', dash ('-'), underscore ('_'),
# and tilde ('~')
_re_urlsafe = re.compile("^[a-zA-Z0-9-_~]+$")


def __is_urlsafe_characters(s: bytes | str) -> bool:
    return bool(_re_urlsafe.fullmatch(to_str(s)))
