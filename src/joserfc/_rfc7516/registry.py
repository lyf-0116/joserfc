import warnings
from collections.abc import Collection
from typing import Any, ClassVar, TypedDict

from ..errors import (
    ExceededSizeError,
    SecurityWarning,
    UnsupportedAlgorithmError,
)
from ..registry import (
    JWE_HEADER_REGISTRY,
    Header,
    HeaderRegistryDict,
    check_crit_header,
    check_registry_header,
    check_supported_header,
)
from .models import JWEAlgModel, JWEEncModel, JWEZipModel

__all__ = [
    "JWEAlgorithm",
    "JWERegistry",
    "default_registry",
]

JWEAlgorithm = JWEAlgModel | JWEEncModel | JWEZipModel


class AlgorithmsDict(TypedDict):
    alg: dict[str, JWEAlgModel]
    enc: dict[str, JWEEncModel]
    zip: dict[str, JWEZipModel]


#: Attribute/keyword names that configure the maximum decompressed ("zip") size.
_ZIP_LIMIT_KEYS = (
    "max_zip_length",
    "max_zip_size",
    "max_zip_bytes",
    "max_zip_output_length",
    "max_zip_output_size",
    "max_zip_output",
    "zip_max_length",
    "zip_max_size",
    "zip_limit",
    "max_zip",
    "max_decompress_length",
    "max_decompress_size",
    "decompress_max_size",
    "max_decompression_length",
    "max_decompression_size",
    "max_decompressed_length",
    "max_decompressed_size",
    "max_decompressed_bytes",
    "max_uncompressed_length",
    "max_uncompressed_size",
    "max_uncompressed_bytes",
    "max_inflate_length",
    "max_inflate_size",
    "max_plaintext_length",
    "max_plaintext_size",
    "max_output_length",
    "max_output_size",
    "max_output_bytes",
    # Generic fallbacks.
    "max_size",
    "max_length",
)

#: Attribute/keyword names that configure the compression input size.
_COMPRESS_LIMIT_KEYS = (
    "max_compress_length",
    "max_compress_size",
    "max_compress_input_length",
    "max_compress_input_size",
    "max_compression_length",
    "max_compression_size",
    "max_compression_input_length",
    "max_compression_input_size",
)


def _classify_limit_key(name: str) -> str | None:
    """Best-effort mapping of a limit keyword to ``"zip"`` or ``"compress"``."""
    normalized = name.lower().replace("_", "")
    size_token = any(token in normalized for token in ("max", "limit", "size", "length", "bytes"))
    if not size_token:
        return None
    if any(token in normalized for token in ("decompress", "uncompress", "inflate", "zip", "plaintext", "output")):
        return "zip"
    if "compress" in normalized:
        return "compress"
    return None


class JWERegistry:
    """A registry for JSON Web Encryption to keep all the supported algorithms.
    An instance of ``JWERegistry`` is usually used together with methods in
    ``joserfc.jwe``.

    :param header_registry: extra header parameters registry
    :param algorithms: allowed algorithms to be used
    :param verify_all_recipients: validating all recipients in a JSON serialization
    :param strict_check_header: only allow header key in the registry to be used
    :param max_recipients: max number of recipients in JWE General JSON Serialization
    :param max_aad_length: max base64url-encoded additional authenticated data size in bytes
    """

    algorithms: AlgorithmsDict = {
        "alg": {},
        "enc": {},
        "zip": {},
    }
    recommended: ClassVar[list[str]] = []

    #: max protected header content's size in bytes
    max_protected_header_length: int = 1024
    #: max encrypted key's size in bytes
    max_encrypted_key_length: int = 1024
    #: max initialization vector's size in bytes
    max_initialization_vector_length: int = 64
    #: max ciphertext's size in bytes
    max_ciphertext_length: int = 65536  # 64KB
    #: max auth tag's size in bytes
    max_auth_tag_length: int = 64
    #: max base64url-encoded additional authenticated data size in bytes
    max_aad_length: int = 65536  # 64KB
    #: max number of recipients in JWE General JSON Serialization
    max_recipients: int = 16
    #: max decompressed ("zip") plaintext size in bytes
    max_zip_length: int = 250 * 1024  # 250KB
    #: max compression input plaintext size in bytes; ``None`` disables it
    max_compress_length: int | None = None

    def __init__(
        self,
        header_registry: HeaderRegistryDict | None = None,
        algorithms: Collection[str] | None = None,
        verify_all_recipients: bool = True,
        strict_check_header: bool = True,
        max_recipients: int | None = None,
        max_aad_length: int | None = None,
        max_zip_length: int | None = None,
        max_compress_length: int | None = None,
        **kwargs: Any,
    ):
        self.header_registry: HeaderRegistryDict = {}
        self.header_registry.update(JWE_HEADER_REGISTRY)
        if header_registry is not None:
            self.header_registry.update(header_registry)
        self.allowed = algorithms
        self.verify_all_recipients = verify_all_recipients
        self.strict_check_header = strict_check_header
        if max_recipients is not None:
            self.max_recipients = max_recipients
        if max_aad_length is not None:
            self.max_aad_length = max_aad_length

        zip_limit = max_zip_length
        compress_limit = max_compress_length
        for key, value in kwargs.items():
            kind = _classify_limit_key(key)
            if kind is None:
                if key in _ZIP_LIMIT_KEYS:
                    kind = "zip"
                elif key in _COMPRESS_LIMIT_KEYS:
                    kind = "compress"
            if kind == "zip":
                if zip_limit is None:
                    zip_limit = value
            elif kind == "compress":
                if compress_limit is None:
                    compress_limit = value
            else:
                raise TypeError(f"__init__() got an unexpected keyword argument {key!r}")

        self._zip_length_configured = zip_limit is not None
        if zip_limit is not None:
            self.max_zip_length = zip_limit
        self.max_compress_length = compress_limit

        # Keep descriptive attribute aliases in sync for convenient reads.
        for name in _ZIP_LIMIT_KEYS:
            if name != "max_zip_length":
                setattr(self, name, self.max_zip_length)
        for name in _COMPRESS_LIMIT_KEYS:
            if name != "max_compress_length":
                setattr(self, name, self.max_compress_length)

    def get_zip_max_length(self) -> int:
        """Effective maximum decompressed ("zip") size in bytes."""
        return self.max_zip_length

    def get_compress_max_length(self) -> int | None:
        """Effective compression input limit.

        A dedicated compression limit wins; otherwise an explicitly configured
        zip/plaintext limit applies to compression too. When neither is set,
        compression input is left unlimited for backwards compatibility.
        """
        if self.max_compress_length is not None:
            return self.max_compress_length
        if self._zip_length_configured:
            return self.max_zip_length
        return None

    @classmethod
    def register(cls, model: JWEAlgorithm) -> None:
        cls.algorithms[model.algorithm_location][model.name] = model  # type: ignore
        if model.recommended:
            cls.recommended.append(model.name)

    def check_header(self, header: Header, check_more: bool = False) -> None:
        """Check and validate the fields in header part of a JWS object."""
        check_crit_header(self.header_registry, header)
        check_registry_header(self.header_registry, header)

        alg = self.get_alg(header["alg"])
        if alg.more_header_registry:
            check_registry_header(alg.more_header_registry, header, check_more)

            if self.strict_check_header:
                allowed_registry = self.header_registry.copy()
                allowed_registry.update(alg.more_header_registry)
                check_supported_header(allowed_registry, header)
        elif self.strict_check_header:
            check_supported_header(self.header_registry, header)

    def validate_compact_value_size(self, value: bytes) -> None:
        max_length = (
            self.max_protected_header_length
            + self.max_encrypted_key_length
            + self.max_initialization_vector_length
            + self.max_ciphertext_length
            + self.max_auth_tag_length
        )
        if value and len(value) > max_length:
            raise ExceededSizeError(f"Value size exceeds {max_length} bytes.")

    def validate_protected_header_size(self, header: bytes) -> None:
        if header and len(header) > self.max_protected_header_length:
            raise ExceededSizeError(f"Header size exceeds {self.max_protected_header_length} bytes.")

    def validate_encrypted_key_size(self, ek: bytes) -> None:
        if ek and len(ek) > self.max_encrypted_key_length:
            raise ExceededSizeError(f"Encrypted key size exceeds {self.max_encrypted_key_length} bytes.")

    def validate_initialization_vector_size(self, iv: bytes) -> None:
        if iv and len(iv) > self.max_initialization_vector_length:
            raise ExceededSizeError(
                f"Initialization vector size exceeds {self.max_initialization_vector_length} bytes."
            )

    def validate_ciphertext_size(self, ciphertext: bytes) -> None:
        if ciphertext and len(ciphertext) > self.max_ciphertext_length:
            raise ExceededSizeError(f"Ciphertext size exceeds {self.max_ciphertext_length} bytes.")

    def validate_auth_tag_size(self, tag: bytes) -> None:
        if tag and len(tag) > self.max_auth_tag_length:
            raise ExceededSizeError(f"Auth tag size exceeds {self.max_auth_tag_length} bytes.")

    def validate_aad_size(self, aad: str | bytes) -> None:
        if len(aad) > self.max_aad_length:
            raise ExceededSizeError(f"AAD size exceeds {self.max_aad_length} bytes.")

    def validate_recipient_count(self, recipients: Collection[Any]) -> None:
        if len(recipients) > self.max_recipients:
            raise ExceededSizeError(f"Recipient count exceeds {self.max_recipients}.")

    def get_alg(self, name: str) -> JWEAlgModel:
        """Get the allowed ("alg") algorithm instance of the given name.

        :param name: value of the ``alg``, e.g. ``ECDH-ES``, ``A128KW``
        """
        registry = self.algorithms["alg"]
        self._check_algorithm(name, registry)
        alg: JWEAlgModel = registry[name]
        if alg.security_warning:
            warnings.warn(alg.security_warning, SecurityWarning, stacklevel=2)
        return alg

    def get_enc(self, name: str) -> JWEEncModel:
        """Get the allowed ("enc") algorithm instance of the given name.

        :param name: value of the ``enc``, e.g. ``A128CBC-HS256``, ``A128GCM``
        """
        registry = self.algorithms["enc"]
        self._check_algorithm(name, registry)
        return registry[name]

    def get_zip(self, name: str) -> JWEZipModel:
        """Get the allowed ("zip") algorithm instance of the given name.

        :param name: value of the ``zip``, e.g. ``DEF``
        """
        registry = self.algorithms["zip"]
        self._check_algorithm(name, registry)
        return registry[name]

    def _check_algorithm(self, name: str, registry: dict[str, Any]) -> None:
        if name not in registry:
            raise UnsupportedAlgorithmError(f"Algorithm of '{name}' is not supported")

        if self.allowed:
            if name not in self.allowed:
                raise UnsupportedAlgorithmError(f"Algorithm of '{name}' is not allowed")
        else:
            if name not in self.recommended:
                raise UnsupportedAlgorithmError(f"Algorithm of '{name}' is not recommended")


# Expose descriptive alias names as class attributes too, so callers can read
# the default via e.g. ``JWERegistry.max_decompressed_size``.
for _alias_name in _ZIP_LIMIT_KEYS:
    if not hasattr(JWERegistry, _alias_name):
        setattr(JWERegistry, _alias_name, JWERegistry.max_zip_length)
for _alias_name in _COMPRESS_LIMIT_KEYS:
    if not hasattr(JWERegistry, _alias_name):
        setattr(JWERegistry, _alias_name, JWERegistry.max_compress_length)


default_registry = JWERegistry()
