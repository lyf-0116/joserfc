from .._rfc7515.json import (
    FindKey,
    extract_general_json_parts,
    sign_json_member,
    validate_json_signature,
)
from .._rfc7515.json import sign_flattened_json as _sign_flattened_json
from .._rfc7515.json import sign_general_json as _sign_general_json
from .._rfc7515.message import (
    decode_payload,
    parse_header_member,
    payload_is_base64_encoded,
    prepare_member,
    validate_member,
)
from .._rfc7515.model import FlattenedJSONSignature, GeneralJSONSignature, HeaderMember
from .._rfc7515.registry import JWSRegistry
from .._rfc7515.types import FlattenedJSONSerialization, GeneralJSONSerialization, JSONSignatureDict
from ..errors import DecodeError, InvalidHeaderValueError
from ..util import to_bytes


def sign_flattened_json(
    member: HeaderMember,
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> FlattenedJSONSerialization:
    if _is_payload_base64_encoded(member, registry):
        return _sign_flattened_json(member, payload, registry, find_key)
    return sign_rfc7797_json(member, payload, registry, find_key)


def sign_general_json(
    members: list[HeaderMember],
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> GeneralJSONSerialization:
    payload_is_encoded = _validate_general_members(members, registry)
    if payload_is_encoded:
        return _sign_general_json(members, payload, registry, find_key)

    signatures: list[JSONSignatureDict] = [sign_json_member(payload, member, registry, find_key) for member in members]
    return {"payload": payload.decode("utf-8"), "signatures": signatures}


def extract_general_json(value: GeneralJSONSerialization, registry: JWSRegistry) -> GeneralJSONSignature:
    payload_segment, signatures, members = extract_general_json_parts(value, registry)
    obj = GeneralJSONSignature(members, b"")
    obj.signatures = signatures
    obj.segments = {"payload": payload_segment}
    validate_json_signature(obj, registry)

    payload_is_encoded = _get_general_payload_encoding(members)
    obj.payload = decode_payload(payload_segment, payload_is_encoded)
    return obj


def sign_rfc7797_json(
    member: HeaderMember,
    payload: bytes,
    registry: JWSRegistry,
    find_key: FindKey,
) -> FlattenedJSONSerialization:
    _is_payload_base64_encoded(member, registry)
    signature = sign_json_member(payload, member, registry, find_key)
    data: FlattenedJSONSerialization = {"payload": payload.decode("utf-8"), **signature}
    return data


def extract_rfc7797_json(value: FlattenedJSONSerialization, registry: JWSRegistry) -> FlattenedJSONSignature:
    if "payload" not in value or not isinstance(value["payload"], str):
        raise DecodeError("Invalid 'payload' member")
    protected_segment = to_bytes(value["protected"]) if "protected" in value else None
    header = value.get("header")
    if "header" in value and not isinstance(header, dict):
        raise InvalidHeaderValueError("Invalid 'header' value: must be a JSON object")
    member = parse_header_member(protected_segment, header, registry)

    payload_segment: bytes = value["payload"].encode("utf-8")
    registry.validate_payload_size(payload_segment)

    obj = FlattenedJSONSignature(member, b"")
    if "signature" not in value:
        raise DecodeError("Missing 'signature' member")
    _sig: JSONSignatureDict = {"signature": value["signature"]}
    if "protected" in value:
        _sig["protected"] = value["protected"]
    if "header" in value:
        _sig["header"] = value["header"]
    obj.signature = _sig
    obj.segments = {"payload": payload_segment}
    validate_json_signature(obj, registry)

    payload_is_encoded = payload_is_base64_encoded(member)
    obj.payload = decode_payload(payload_segment, payload_is_encoded)
    return obj


def _validate_general_members(members: list[HeaderMember], registry: JWSRegistry) -> bool:
    for member in members:
        validate_member(member, registry)
    return _get_general_payload_encoding(members)


def _get_general_payload_encoding(members: list[HeaderMember]) -> bool:
    payload_encodings = [payload_is_base64_encoded(member) for member in members]
    if payload_encodings and any(encoded != payload_encodings[0] for encoded in payload_encodings[1:]):
        raise InvalidHeaderValueError("'b64' MUST have the same value for all signatures")
    return payload_encodings[0] if payload_encodings else True


def _is_payload_base64_encoded(member: HeaderMember, registry: JWSRegistry) -> bool:
    _, is_encoded = prepare_member(member, registry)
    return is_encoded
