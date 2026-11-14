"""
Envelope encryption with chunked (streaming) AES-256-GCM.

KEY HIERARCHY
    master key (32 B, Docker secret)  --wraps-->  per-file data key (32 B, random)
    data key                          --encrypts-> file contents, chunk by chunk

    Only the *wrapped* data key is stored (in PostgreSQL). The master key lives in a
    Docker secret, never next to the ciphertext. Rotating the master key only requires
    re-wrapping 48-byte keys, not re-encrypting gigabytes of data.

ON-DISK FORMAT (no header; everything needed is in the DB row)
    chunk_0 || chunk_1 || ... || chunk_n
    chunk_i = AES-256-GCM( plaintext_i ) = ciphertext_i || 16-byte tag
    Every chunk holds CHUNK_SIZE plaintext bytes except the last one (1..CHUNK_SIZE,
    or 0 for an empty file).

NONCE (96 bit) = base_nonce (8 random bytes, stored in DB) || chunk_counter (4 bytes BE)
    Unique per chunk within a file; the data key is unique per file, so a
    (key, nonce) pair is never reused. Max 2**32 chunks = 4 PiB at 1 MiB/chunk.

ASSOCIATED DATA (authenticated, not encrypted), per chunk:
    file_uuid (16 B) || chunk_counter (8 B) || is_final (1 B)
    - counter in the AAD + nonce : chunks can't be reordered or duplicated
    - is_final flag              : dropping the last chunk(s) (truncation) or appending
                                   data after the last chunk fails authentication
    - file_uuid                  : a valid chunk can't be transplanted into another file
"""
from __future__ import annotations

import base64
import os
import uuid
from functools import lru_cache
from typing import BinaryIO, Callable, Iterable, Iterator

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ALGORITHM = "AES-256-GCM (chunked, envelope)"
KEY_SIZE = 32
TAG_SIZE = 16
BASE_NONCE_SIZE = 8
WRAP_NONCE_SIZE = 12
CHUNK_SIZE = 1024 * 1024  # 1 MiB of plaintext per chunk
MAX_CHUNKS = 2**32


class IntegrityError(Exception):
    """Ciphertext failed authentication (tampered, truncated, reordered or wrong key)."""


class MasterKeyError(RuntimeError):
    """The master key is missing or malformed."""


# --------------------------------------------------------------------------- master key
@lru_cache(maxsize=1)
def get_master_key() -> bytes:
    """Load the 256-bit master key from a Docker secret file, or MASTER_KEY env var.

    The key is base64 encoded. It is never hard-coded and never written anywhere.
    """
    path = os.environ.get("MASTER_KEY_FILE")
    if path:
        try:
            with open(path, "r", encoding="ascii") as fh:
                raw = fh.read().strip()
        except OSError as exc:
            raise MasterKeyError(f"Cannot read master key file {path}: {exc}") from exc
    else:
        raw = os.environ.get("MASTER_KEY", "").strip()
    if not raw:
        raise MasterKeyError("No master key: set MASTER_KEY_FILE (Docker secret) or MASTER_KEY.")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:  # binascii.Error
        raise MasterKeyError("Master key is not valid base64.") from exc
    if len(key) != KEY_SIZE:
        raise MasterKeyError(f"Master key must be {KEY_SIZE} bytes, got {len(key)}.")
    return key


# --------------------------------------------------------------------------- key wrapping
def generate_file_secrets() -> tuple[bytes, bytes]:
    """Return (random 256-bit data key, random 64-bit base nonce)."""
    return AESGCM.generate_key(bit_length=256), os.urandom(BASE_NONCE_SIZE)


def wrap_key(data_key: bytes, file_id: uuid.UUID, master_key: bytes | None = None) -> tuple[bytes, bytes]:
    """Encrypt the data key under the master key. Returns (wrapped_key, wrap_nonce).

    The file id is bound as AAD so a wrapped key can't be swapped between DB rows.
    """
    nonce = os.urandom(WRAP_NONCE_SIZE)
    wrapped = AESGCM(master_key or get_master_key()).encrypt(nonce, data_key, b"wrap:" + file_id.bytes)
    return wrapped, nonce


def unwrap_key(wrapped: bytes, wrap_nonce: bytes, file_id: uuid.UUID, master_key: bytes | None = None) -> bytes:
    try:
        return AESGCM(master_key or get_master_key()).decrypt(
            bytes(wrap_nonce), bytes(wrapped), b"wrap:" + file_id.bytes
        )
    except InvalidTag as exc:
        raise IntegrityError("Cannot unwrap data key (wrong master key or corrupted key record).") from exc


# --------------------------------------------------------------------------- helpers
def _nonce(base_nonce: bytes, counter: int) -> bytes:
    return bytes(base_nonce) + counter.to_bytes(4, "big")


def _aad(file_id: uuid.UUID, counter: int, final: bool) -> bytes:
    return file_id.bytes + counter.to_bytes(8, "big") + (b"\x01" if final else b"\x00")


def iter_plain_chunks(read: Callable[[int], bytes], chunk_size: int = CHUNK_SIZE) -> Iterator[bytes]:
    """Yield exactly chunk_size bytes per item (last one may be shorter), from any read()."""
    while True:
        buf = bytearray()
        while len(buf) < chunk_size:
            part = read(chunk_size - len(buf))
            if not part:
                break
            buf += part
        if not buf:
            return
        yield bytes(buf)
        if len(buf) < chunk_size:
            return


def ciphertext_size(plaintext_size: int, chunk_size: int = CHUNK_SIZE) -> int:
    """Exact on-disk size for a given plaintext size."""
    chunks = max(1, -(-plaintext_size // chunk_size))
    return plaintext_size + chunks * TAG_SIZE


# --------------------------------------------------------------------------- encrypt
def encrypt_chunks(
    plain_chunks: Iterable[bytes], data_key: bytes, base_nonce: bytes, file_id: uuid.UUID
) -> Iterator[bytes]:
    """Streaming encryption. Holds at most two chunks in memory (one-chunk lookahead is
    needed to know which chunk is the final one before sealing it)."""
    aes = AESGCM(data_key)
    prev: bytes | None = None
    counter = 0
    for chunk in plain_chunks:
        if prev is not None:
            yield aes.encrypt(_nonce(base_nonce, counter), prev, _aad(file_id, counter, False))
            counter += 1
            if counter >= MAX_CHUNKS:
                raise ValueError("File too large for the 32-bit chunk counter.")
        prev = chunk
    yield aes.encrypt(_nonce(base_nonce, counter), prev if prev is not None else b"", _aad(file_id, counter, True))


# --------------------------------------------------------------------------- decrypt
def decrypt_chunks(
    read: Callable[[int], bytes],
    data_key: bytes,
    base_nonce: bytes,
    file_id: uuid.UUID,
    chunk_size: int = CHUNK_SIZE,
) -> Iterator[bytes]:
    """Streaming decryption. Raises IntegrityError on the first chunk that fails
    authentication. Callers that must never emit partial data should run verify_stream()
    first (see views.download)."""
    aes = AESGCM(data_key)
    ct_size = chunk_size + TAG_SIZE

    def read_full(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            part = read(n - len(buf))
            if not part:
                break
            buf += part
        return bytes(buf)

    cur = read_full(ct_size)
    if len(cur) < TAG_SIZE:
        raise IntegrityError("Ciphertext is empty or truncated.")
    counter = 0
    while True:
        nxt = read_full(ct_size) if len(cur) == ct_size else b""
        final = not nxt
        try:
            plain = aes.decrypt(_nonce(base_nonce, counter), cur, _aad(file_id, counter, final))
        except InvalidTag as exc:
            raise IntegrityError(f"Authentication failed at chunk {counter}.") from exc
        yield plain
        if final:
            return
        cur = nxt
        counter += 1


def verify_stream(
    fh: BinaryIO, data_key: bytes, base_nonce: bytes, file_id: uuid.UUID,
    expected_plaintext_size: int, chunk_size: int = CHUNK_SIZE,
) -> None:
    """Authenticate every chunk without keeping or emitting plaintext."""
    total = 0
    for plain in decrypt_chunks(fh.read, data_key, base_nonce, file_id, chunk_size):
        total += len(plain)
    if total != expected_plaintext_size:
        raise IntegrityError("Decrypted size does not match the recorded size.")
