from typing import Any

from ..util import (
    json_b64encode,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from .message import build_signing_input, decode_protected_header, encode_payload
from .model import CompactSignature, JWSAlgModel

__all__ = [
    "sign_compact",
    "verify_compact",
    "detach_compact_content",
    "decode_header",
]


def sign_compact(obj: CompactSignature, alg: JWSAlgModel, key: Any) -> bytes:
    header_segment = json_b64encode(obj.headers())
    payload_segment = encode_payload(obj.payload, True)
    signing_input = build_signing_input(header_segment, payload_segment)
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    return signing_input + b"." + signature


def verify_compact(obj: CompactSignature, alg: JWSAlgModel, key: Any) -> bool:
    signing_input = build_signing_input(obj.segments["header"], obj.segments["payload"])
    try:
        sig = urlsafe_b64decode(obj.segments["signature"])
    except (TypeError, ValueError):
        return False
    return alg.verify(signing_input, sig, key)


def detach_compact_content(value: str) -> str:
    # https://www.rfc-editor.org/rfc/rfc7515#appendix-F
    parts = value.split(".")
    parts[1] = ""
    return ".".join(parts)


def decode_header(header_segment: bytes) -> dict[str, Any]:
    return decode_protected_header(header_segment, require_alg=True)
