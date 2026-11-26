import copy
from collections.abc import Callable
from typing import Any

from ..errors import DecodeError, InvalidHeaderValueError
from ..util import (
    json_b64encode,
    to_bytes,
    urlsafe_b64decode,
    urlsafe_b64encode,
)
from .message import (
    build_signing_input,
    decode_payload,
    parse_header_member,
    prepare_member,
    validate_member,
)
from .model import (
    FlattenedJSONSignature,
    GeneralJSONSignature,
    HeaderMember,
)
from .registry import JWSRegistry
from .types import (
    FlattenedJSONSerialization,
    GeneralJSONSerialization,
    JSONSignatureDict,
)

__all__ = [
    "FindKey",
    "sign_general_json",
    "sign_flattened_json",
    "sign_json_member",
    "extract_general_json",
    "verify_general_json",
    "verify_flattened_json",
    "detach_json_content",
]

FindKey = Callable[[HeaderMember], Any]


def sign_general_json(
    members: list[HeaderMember],
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> GeneralJSONSerialization:
    payload_segment = urlsafe_b64encode(payload)
    signatures: list[JSONSignatureDict] = [
        sign_json_member(payload_segment, member, registry, find_key) for member in members
    ]
    return {
        "payload": payload_segment.decode("utf-8"),
        "signatures": signatures,
    }


def sign_flattened_json(
    member: HeaderMember,
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> FlattenedJSONSerialization:
    payload_segment = urlsafe_b64encode(payload)
    signature = sign_json_member(payload_segment, member, registry, find_key)
    data: FlattenedJSONSerialization = {"payload": payload_segment.decode("utf-8"), **signature}
    return data


def sign_json_member(
    payload_segment: bytes, member: HeaderMember, registry: JWSRegistry, find_key: FindKey
) -> JSONSignatureDict:
    headers, _ = prepare_member(member, registry)
    alg = registry.get_alg(headers["alg"])
    key = find_key(member)
    alg.check_key(key)
    if member.protected:
        protected_segment = json_b64encode(member.protected)
    else:
        protected_segment = b""
    signing_input = build_signing_input(protected_segment, payload_segment)
    signature = urlsafe_b64encode(alg.sign(signing_input, key))
    rv: JSONSignatureDict = {"signature": signature.decode("utf-8")}
    if member.protected:
        rv["protected"] = protected_segment.decode("utf-8")
    if member.header:
        rv["header"] = member.header
    return rv


def extract_general_json(value: GeneralJSONSerialization, registry: JWSRegistry) -> GeneralJSONSignature:
    payload_segment, signatures, members = extract_general_json_parts(value, registry)
    obj = GeneralJSONSignature(members, b"")
    obj.signatures = signatures
    obj.segments = {"payload": payload_segment}
    validate_json_signature(obj, registry)
    obj.payload = decode_payload(payload_segment, True)
    return obj


def __signature_to_member(sig: JSONSignatureDict, registry: JWSRegistry) -> HeaderMember:
    if not isinstance(sig, dict):
        raise InvalidHeaderValueError("Invalid 'signatures' member: must be a JSON object")
    protected_segment = to_bytes(sig["protected"]) if "protected" in sig else None
    header = sig.get("header")
    if "header" in sig and not isinstance(header, dict):
        raise InvalidHeaderValueError("Invalid 'header' value: must be a JSON object")
    return parse_header_member(protected_segment, header, registry)


def verify_general_json(obj: GeneralJSONSignature, registry: JWSRegistry, find_key: FindKey) -> bool:
    payload_segment = obj.segments["payload"]
    if not obj.signatures:
        return False

    validate_json_signature(obj, registry)
    for index, signature in enumerate(obj.signatures):
        member = obj.members[index]
        if not verify_signature(member, signature, payload_segment, registry, find_key):
            return False
    return True


def verify_flattened_json(obj: FlattenedJSONSignature, registry: JWSRegistry, find_key: FindKey) -> bool:
    payload_segment = obj.segments["payload"]
    assert obj.signature is not None
    validate_json_signature(obj, registry)
    return verify_signature(obj.member, obj.signature, payload_segment, registry, find_key)


def verify_signature(
    member: HeaderMember,
    signature: JSONSignatureDict,
    payload_segment: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> bool:
    headers = validate_member(member, registry)
    alg = registry.get_alg(headers["alg"])
    key = find_key(member)
    alg.check_key(key)

    if "protected" in signature:
        protected_segment = to_bytes(signature["protected"])
    else:
        protected_segment = b""

    signature_segment = to_bytes(signature["signature"])
    registry.validate_signature_size(signature_segment)

    sig = urlsafe_b64decode(signature_segment)
    signing_input = build_signing_input(protected_segment, payload_segment)
    return alg.verify(signing_input, sig, key)


def extract_general_json_parts(
    value: GeneralJSONSerialization, registry: JWSRegistry
) -> tuple[bytes, list[JSONSignatureDict], list[HeaderMember]]:
    if "payload" not in value or not isinstance(value["payload"], str):
        raise DecodeError("Invalid 'payload' member")
    payload_segment = value["payload"].encode("utf-8")
    registry.validate_payload_size(payload_segment)
    signatures = value["signatures"]
    if not isinstance(signatures, list):
        raise InvalidHeaderValueError("Invalid 'signatures' value: must be a list")
    members = [__signature_to_member(signature, registry) for signature in signatures]
    return payload_segment, signatures, members


def check_json_member_headers(member: HeaderMember, registry: JWSRegistry) -> dict[str, Any]:
    return validate_member(member, registry)


def validate_json_signature(
    obj: GeneralJSONSignature | FlattenedJSONSignature, registry: JWSRegistry
) -> None:
    for member in obj.members:
        validate_member(member, registry)


def detach_json_content(value: dict[str, Any]) -> dict[str, Any]:
    # https://www.rfc-editor.org/rfc/rfc7515#appendix-F
    rv = copy.deepcopy(value)  # don't alter original value
    if "payload" in rv:
        del rv["payload"]
    return rv
