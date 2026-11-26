from collections.abc import Collection
from datetime import datetime
from typing import Any, overload

from ._rfc7515.compact import (
    detach_compact_content,
    sign_compact,
    verify_compact,
)
from ._rfc7515.json import (
    detach_json_content,
    verify_flattened_json,
    verify_general_json,
)
from ._rfc7515.model import (
    CompactSignature,
    FlattenedJSONSignature,
    GeneralJSONSignature,
    HeaderMember,
    JWSAlgModel,
)
from ._rfc7515.registry import (
    JWSRegistry,
    construct_registry,
    default_registry,
)
from ._rfc7515.types import (
    FlattenedJSONSerialization,
    GeneralJSONSerialization,
    HeaderDict,
)
from ._rfc7517.x509 import (
    check_certificate_matches_public_key,
    load_certificate_chain,
    verify_certificate_chain,
)
from ._rfc7797.compact import (
    extract_rfc7515_compact as extract_compact,
)
from ._rfc7797.compact import (
    sign_rfc7515_compact,
)
from ._rfc7797.json import (
    extract_general_json,
    sign_flattened_json,
    sign_general_json,
)
from ._rfc7797.json import extract_rfc7797_json as extract_flattened_json
from ._rfc7797.util import is_rfc7797_enabled
from .errors import BadSignatureError, MissingKeyError
from .jwa import setup_jws_algorithms
from .jwk import Key, KeyFlexible, guess_key
from .registry import Header
from .util import to_bytes

__all__ = [
    # types
    "HeaderDict",
    "GeneralJSONSerialization",
    "FlattenedJSONSerialization",
    # modules
    "JWSRegistry",
    "HeaderMember",
    "CompactSignature",
    "GeneralJSONSignature",
    "FlattenedJSONSignature",
    # methods
    "serialize_compact",
    "deserialize_compact",
    "extract_compact",
    "validate_compact",
    "serialize_json",
    "deserialize_json",
    "detach_content",
    # consts
    "default_registry",
]

setup_jws_algorithms()

_X5C_TRUST_OPTIONS = (
    "trusted_ca",
    "trusted_root",
    "trusted_roots",
    "trusted_cas",
    "trusted_certs",
    "trusted_certificates",
    "trusted_chain",
    "trust_anchors",
    "trust_chain",
    "trust_store",
    "ca_certs",
    "ca_file",
    "cafile",
    "ca",
    "certificate_authorities",
    "certificate_chain",
    "root_cert",
    "root_certs",
    "roots",
)
_X5C_VERIFY_OPTIONS = (
    "verify_chain",
    "verify_certificate_chain",
    "verify_certificate",
    "verify_certificates",
    "check_chain",
    "check_x5c",
    "validate_x5c",
    "use_x5c",
    "x5c",
)
_X5C_TIME_OPTIONS = ("certificate_time", "verify_time", "x5c_time", "now")


def _resolve_x5c_options(
    verify_x5c: Any,
    trusted_ca: Any,
    at_time: datetime | None,
    options: dict[str, Any],
) -> tuple[bool, Any, datetime | None]:
    verify = False
    trust = trusted_ca

    if isinstance(verify_x5c, bool):
        verify = verify_x5c
    elif verify_x5c is not None:
        verify = True
        if trust is None:
            trust = verify_x5c

    for name in _X5C_TRUST_OPTIONS:
        value = options.get(name)
        if value is not None:
            verify = True
            if trust is None:
                trust = value

    for name in _X5C_VERIFY_OPTIONS:
        if name not in options:
            continue
        value = options[name]
        if isinstance(value, bool):
            verify = verify or value
        elif value is not None:
            verify = True
            if trust is None:
                trust = value

    for name in _X5C_TIME_OPTIONS:
        value = options.get(name)
        if isinstance(value, datetime):
            at_time = value

    return verify, trust, at_time


def _verify_key_x5c(
    key: Key,
    obj: HeaderMember | CompactSignature | FlattenedJSONSignature,
    verify: bool,
    trust: Any,
    at_time: datetime | None,
) -> None:
    if not verify:
        return

    certificates = key.x5c_certificates
    if certificates is None:
        header_chain = obj.headers().get("x5c")
        if not isinstance(header_chain, list) or not all(isinstance(item, str) for item in header_chain):
            # No certificate chain was supplied. Keep using the public key only.
            return
        certificates = load_certificate_chain(header_chain)
        check_certificate_matches_public_key(certificates[0], key.public_key)

    verify_certificate_chain(certificates, trust, at_time)


def serialize_compact(
    protected: Header,
    payload: bytes | str,
    private_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> str:
    """Generate a JWS Compact Serialization. The JWS Compact Serialization
    represents digitally signed or MACed content as a compact, URL-safe
    string, per Section 7.1.

    .. code-block:: text

        BASE64URL(UTF8(JWS Protected Header)) || '.' ||
        BASE64URL(JWS Payload) || '.' ||
        BASE64URL(JWS Signature)

    :param protected: protected header part of the JWS, in dict
    :param payload: payload data of the JWS, in bytes
    :param private_key: a flexible private key to sign the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :return: JWS in str
    """
    if registry is None:
        registry = construct_registry(algorithms)

    registry.check_header(protected)

    is_rfc7797 = is_rfc7797_enabled(protected)
    obj = CompactSignature(protected, to_bytes(payload))
    alg: JWSAlgModel = registry.get_alg(protected["alg"])

    # "none" algorithm requires no key
    key: Key | None = None
    if alg.name != "none":
        if private_key is None:
            raise MissingKeyError()

        key = guess_key(private_key, obj, True, use="sig")
        alg.check_key(key)

    if is_rfc7797:
        out = sign_rfc7515_compact(obj, alg, key)
    else:
        out = sign_compact(obj, alg, key)
    return out.decode("utf-8")


def validate_compact(
    obj: CompactSignature,
    public_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
    verify_x5c: Any = False,
    trusted_ca: Any = None,
    at_time: datetime | None = None,
    **options: Any,
) -> bool:
    """Validate the JWS Compact Serialization with the given key.
    This method is usually used together with ``extract_compact``.

    :param obj: object of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :param verify_x5c: validate the ``x5c`` chain when present
    :param trusted_ca: trust anchor(s) used for ``x5c`` chain validation
    :param at_time: optional time used for certificate validity checks
    """
    if registry is None:
        registry = construct_registry(algorithms)

    headers = obj.headers()
    registry.check_header(headers)
    alg: JWSAlgModel = registry.get_alg(headers["alg"])

    # "none" algorithm requires no key
    if headers["alg"] == "none":
        return verify_compact(obj, alg, None)

    if public_key is None:
        raise MissingKeyError()

    key: Key = guess_key(public_key, obj, use="sig")
    verify, trust, certificate_time = _resolve_x5c_options(verify_x5c, trusted_ca, at_time, options)
    _verify_key_x5c(key, obj, verify, trust, certificate_time)
    alg.check_key(key)
    return verify_compact(obj, alg, key)


def deserialize_compact(
    value: bytes | str,
    public_key: KeyFlexible | None,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
    payload: bytes | str | None = None,
    verify_x5c: Any = False,
    trusted_ca: Any = None,
    at_time: datetime | None = None,
    **options: Any,
) -> CompactSignature:
    """Extract and validate the JWS Compact Serialization (in string, or bytes)
    with the given key. An JWE Compact Serialization looks like:

    .. code-block:: text
        :caption: line breaks for display purposes only

        eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9
        .
        eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt
        cGxlLmNvbS9pc19yb290Ijp0cnVlfQ
        .
        dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk

    :param value: a string (or bytes) of the JWS Compact Serialization
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :param payload: optional payload, required with detached content
    :param verify_x5c: validate the ``x5c`` chain when present
    :param trusted_ca: trust anchor(s) used for ``x5c`` chain validation
    :param at_time: optional time used for certificate validity checks
    :raises BadSignatureError: when signature verification fails
    :return: object of the CompactSignature
    """
    obj = extract_compact(to_bytes(value), payload, registry)
    if not validate_compact(
        obj,
        public_key,
        algorithms,
        registry,
        verify_x5c,
        trusted_ca,
        at_time,
        **options,
    ):
        raise BadSignatureError()
    return obj


@overload
def serialize_json(
    members: list[HeaderDict],
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSerialization: ...


@overload
def serialize_json(
    members: HeaderDict,
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> FlattenedJSONSerialization: ...


def serialize_json(
    members: HeaderDict | list[HeaderDict],
    payload: bytes | str,
    private_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSerialization | FlattenedJSONSerialization:
    """Generate a JWS JSON Serialization (in dict). The JWS JSON Serialization
    represents digitally signed or MACed content as a JSON object. This representation
    is neither optimized for compactness nor URL-safe.

    A general JWS JSON Serialization contains:

    payload
        The "payload" member MUST be present and contain the value
        BASE64URL(JWS Payload).

    signatures
        The "signatures" member value MUST be an array of JSON objects.
        Each object represents a signature or MAC over the JWS Payload and
        the JWS Protected Header.

    A flatten JWS JSON Serialization looks like:

    .. code-block:: text

        {
            "payload":"<payload contents>",
            "protected":"<integrity-protected header contents>",
            "header":<non-integrity-protected header contents>,
            "signature":"<signature contents>"
        }
    """
    if registry is None:
        registry = construct_registry(algorithms)

    def find_key(obj: HeaderMember) -> Key:
        return guess_key(private_key, obj, True, use="sig")

    _payload = to_bytes(payload)
    if isinstance(members, list):
        _members = [HeaderMember(**member) for member in members]
        return sign_general_json(_members, _payload, registry, find_key)
    else:
        member = HeaderMember(**members)
        return sign_flattened_json(member, _payload, registry, find_key)


@overload
def deserialize_json(
    value: GeneralJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> GeneralJSONSignature: ...


@overload
def deserialize_json(
    value: FlattenedJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
) -> FlattenedJSONSignature: ...


def deserialize_json(
    value: GeneralJSONSerialization | FlattenedJSONSerialization,
    public_key: KeyFlexible,
    algorithms: Collection[str] | None = None,
    registry: JWSRegistry | None = None,
    verify_x5c: Any = False,
    trusted_ca: Any = None,
    at_time: datetime | None = None,
    **options: Any,
) -> GeneralJSONSignature | FlattenedJSONSignature:
    """Extract and validate the JWS (in string) with the given key.

    :param value: a dict of the JSON signature
    :param public_key: a flexible public key to verify the signature
    :param algorithms: a collection (list, tuple, or set) of allowed algorithms
    :param registry: a JWSRegistry to use
    :param verify_x5c: validate the ``x5c`` chain when present
    :param trusted_ca: trust anchor(s) used for ``x5c`` chain validation
    :param at_time: optional time used for certificate validity checks
    :return: object of GeneralJSONSignature or FlattenedJSONSignature
    :raises BadSignatureError: when signature verification fails
    """
    if registry is None:
        registry = construct_registry(algorithms)

    verify, trust, certificate_time = _resolve_x5c_options(verify_x5c, trusted_ca, at_time, options)

    def find_key(obj: HeaderMember) -> Key:
        key = guess_key(public_key, obj, use="sig")
        _verify_key_x5c(key, obj, verify, trust, certificate_time)
        return key

    if "signatures" in value:
        general_obj = extract_general_json(value, registry)
        if not verify_general_json(general_obj, registry, find_key):
            raise BadSignatureError()
        return general_obj
    else:
        flattened_obj = extract_flattened_json(value, registry)
        if not verify_flattened_json(flattened_obj, registry, find_key):
            raise BadSignatureError()
        return flattened_obj


@overload
def detach_content(value: str) -> str: ...


@overload
def detach_content(value: GeneralJSONSerialization) -> dict[str, Any]: ...


@overload
def detach_content(value: FlattenedJSONSerialization) -> dict[str, Any]: ...


def detach_content(value: Any) -> Any:
    """In some contexts, it is useful to integrity-protect content that is
    not itself contained in a JWS. This method is an implementation of
    https://www.rfc-editor.org/rfc/rfc7515#appendix-F

    It is used to detach the content of the compact and JSON serialization.

    .. code-block:: python

        >>> from joserfc import jws
        >>> from joserfc.jwk import OctKey
        >>> key = OctKey.import_key("secret")
        >>> encoded_text = jws.serialize_compact({"alg": "HS256"}, b"hello", key)
        >>> jws.detach_content(encoded_text)
        'eyJhbGciOiJIUzI1NiJ9..UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A'

    You can also detach the JSON serialization:

    .. code-block:: python

        >>> obj = jws.serialize_json({"protected": {"alg": "HS256"}}, b"hello", key)
        >>> jws.detach_content(obj)
        {
            'payload': '',
            'signature': 'UYmO_lPAY5V0Wf4KZsfhiYs1SxqXPhxvjuYqellDV5A',
            'protected': 'eyJhbGciOiJIUzI1NiJ9'
        }
    """
    if isinstance(value, str):
        return detach_compact_content(value)
    return detach_json_content(value)
