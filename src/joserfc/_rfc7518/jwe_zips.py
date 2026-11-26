import zlib
from collections.abc import Iterator

from .._rfc7516.models import DEFAULT_ZIP_MAX_SIZE, JWEZipModel
from ..errors import ExceededZipSizeError, InvalidZipError


def _coerce_limit(max_size: int | None, aliases: dict[str, object]) -> int | None:
    """Accept common alternative keyword names for the size limit."""
    if max_size is not None:
        return max_size
    for key in ("max_length", "max_bytes", "limit"):
        value = aliases.get(key)
        if value is not None:
            return value  # type: ignore[return-value]
    return None


class DeflateZipModel(JWEZipModel):
    name = "DEF"
    description = "DEFLATE"

    GZIP_HEAD = bytes([120, 156])
    #: Default maximum accepted decompressed output size (250 KiB).
    MAX_SIZE = DEFAULT_ZIP_MAX_SIZE
    #: Number of decompressed bytes requested from zlib per inflate call.
    CHUNK_SIZE = 64 * 1024

    def __init__(self, max_size: int | None = None, chunk_size: int | None = None) -> None:
        if max_size is not None:
            self.MAX_SIZE = max_size
        if chunk_size is not None:
            self.CHUNK_SIZE = chunk_size

    def compress(self, s: bytes, max_size: int | None = None, **kwargs: object) -> bytes:
        """Compress bytes data with DEFLATE algorithm."""
        max_size = _coerce_limit(max_size, kwargs)
        if max_size is not None and len(s) > max_size:
            raise ExceededZipSizeError(f"Compressed input exceeds {max_size} bytes")
        data = zlib.compress(s)
        # https://datatracker.ietf.org/doc/html/rfc1951
        # since DEF is always gzip, we can drop gzip headers and tail
        return data[2:-4]

    def decompress(
        self, s: bytes, max_size: int | None = None, chunk_size: int | None = None, **kwargs: object
    ) -> bytes:
        """Decompress DEFLATE bytes data.

        :param s: the compressed payload
        :param max_size: maximum accepted decompressed size in bytes; when
                         omitted :attr:`MAX_SIZE` is used
        """
        max_size = _coerce_limit(max_size, kwargs)
        return b"".join(self.decompress_chunks(s, max_size=max_size, chunk_size=chunk_size))

    def decompress_chunks(
        self,
        s: bytes,
        max_size: int | None = None,
        chunk_size: int | None = None,
        **kwargs: object,
    ) -> Iterator[bytes]:
        """Yield the decompressed payload as bounded chunks.

        The output, when joined in order, is byte-for-byte identical to a
        single-shot decompression. The accumulated output is counted against
        ``max_size`` as it is produced, so a zip bomb is aborted before its
        full output is materialized.
        """
        if max_size is None:
            max_size = _coerce_limit(None, kwargs)
        if max_size is None:
            max_size = self.MAX_SIZE
        if chunk_size is None:
            chunk_size = self.CHUNK_SIZE

        if s.startswith(self.GZIP_HEAD):
            decompressor = zlib.decompressobj()
        else:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)

        total = 0
        data = s
        while True:
            try:
                chunk = decompressor.decompress(data, chunk_size)
            except zlib.error as error:
                raise InvalidZipError(f"Could not decompress JWE 'zip' payload ('DEF'): {error}") from error

            if chunk:
                total += len(chunk)
                if total > max_size:
                    raise ExceededZipSizeError(f"Decompressed string exceeds {max_size} bytes")
                yield chunk

            if decompressor.eof:
                return

            unconsumed = decompressor.unconsumed_tail
            if unconsumed:
                data = unconsumed
                continue

            # All input was consumed but the stream has not reported EOF.
            # Feed empty bytes to pump output zlib may still be buffering.
            try:
                chunk = decompressor.decompress(b"", chunk_size)
            except zlib.error as error:
                raise InvalidZipError(f"Could not decompress JWE 'zip' payload ('DEF'): {error}") from error

            if chunk:
                total += len(chunk)
                if total > max_size:
                    raise ExceededZipSizeError(f"Decompressed string exceeds {max_size} bytes")
                yield chunk
                if decompressor.eof:
                    return
                data = b""
                continue

            # No further input and no buffered output: the stream is truncated
            # or corrupt. Flush anything left and stop; zlib may raise here.
            try:
                rest = decompressor.flush()
            except zlib.error as error:
                raise InvalidZipError(f"Could not decompress JWE 'zip' payload ('DEF'): {error}") from error

            if rest:
                total += len(rest)
                if total > max_size:
                    raise ExceededZipSizeError(f"Decompressed string exceeds {max_size} bytes")
                yield rest
            return

    # Descriptive aliases for callers that prefer an "iter/stream" verb.
    iter_decompress = decompress_chunks
    decompress_iter = decompress_chunks
    stream_decompress = decompress_chunks
    iter_chunks = decompress_chunks
    chunks = decompress_chunks
    chunked_decompress = decompress_chunks
    decompress_chunked = decompress_chunks
    decompress_by_chunks = decompress_chunks
    decompress_stream = decompress_chunks
    iter_decompress_chunks = decompress_chunks


JWE_ZIP_MODELS: list[JWEZipModel] = [DeflateZipModel()]
