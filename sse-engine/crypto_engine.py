"""Cryptographic primitives for the SSE engine.

Key hierarchy
-------------
master.key (32 random bytes)
  -> HKDF-SHA256(info=b"enc")   = K_enc   document / metadata encryption (AES-256-GCM)
  -> HKDF-SHA256(info=b"idx")   = K_idx   index label PRF
  -> HKDF-SHA256(info=b"tok")   = K_tok   keyword trapdoor PRF
  -> HKDF-SHA256(info=b"blind") = K_blind blind index for structured fields

Per keyword w:
  T     = HMAC-SHA256(K_tok, w)
  L_c   = HMAC-SHA256(K_idx, T || c)          c = 64-bit big-endian counter
  K_w   = HKDF-SHA256(T, info=b"posting")     per-keyword posting key
  P_c   = AES-GCM(K_w, doc_id, aad=L_c)       binds each posting to its label

Nothing in this module logs or prints.
"""
from __future__ import annotations

import hashlib
import hmac
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


class IntegrityError(Exception):
    """Raised when an AES-GCM tag does not verify (tampering, wrong key or wrong AAD)."""


@dataclass(frozen=True)
class DerivedKeys:
    enc: bytes
    idx: bytes
    tok: bytes
    blind: bytes

    def __repr__(self) -> str:  # never expose key material in reprs or tracebacks
        return "DerivedKeys(<redacted>)"


def generate_master_key() -> bytes:
    return secrets.token_bytes(KEY_LEN)


def load_or_create_master_key(path: str | os.PathLike) -> bytes:
    """Load master.key, creating it (mode 0600) on first run."""
    path = Path(path)
    if path.exists():
        key = path.read_bytes()
        if len(key) != KEY_LEN:
            raise ValueError("master.key is corrupt: expected 32 bytes")
        return key
    key = generate_master_key()
    path.parent.mkdir(parents=True, exist_ok=True)
    # O_EXCL so two processes racing on first run cannot overwrite each other.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


def hkdf(ikm: bytes, info: bytes, length: int = KEY_LEN) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(ikm)


def derive_keys(master_key: bytes) -> DerivedKeys:
    if len(master_key) != KEY_LEN:
        raise ValueError("master key must be 32 bytes")
    return DerivedKeys(
        enc=hkdf(master_key, b"enc"),
        idx=hkdf(master_key, b"idx"),
        tok=hkdf(master_key, b"tok"),
        blind=hkdf(master_key, b"blind"),
    )


# --- AES-256-GCM -------------------------------------------------------------

def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Return nonce || ciphertext || tag."""
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise IntegrityError("blob too short")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], aad)
    except InvalidTag as exc:
        raise IntegrityError("authentication tag mismatch") from exc


def split_blob(blob: bytes) -> tuple[bytes, bytes, bytes]:
    """Split a blob into (nonce, ciphertext, tag) for display and checks."""
    return blob[:NONCE_LEN], blob[NONCE_LEN:-TAG_LEN], blob[-TAG_LEN:]


def doc_aad(doc_id: str) -> bytes:
    return doc_id.encode("ascii")


def meta_aad(doc_id: str) -> bytes:
    # Distinct from doc_aad so a metadata blob can never be swapped in for a document.
    return b"meta:" + doc_id.encode("ascii")


# --- Searchable-encryption PRFs ---------------------------------------------

def _hmac(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def trapdoor(k_tok: bytes, normalized_word: str) -> bytes:
    """T = HMAC-SHA256(K_tok, w). Deterministic: equal words -> equal trapdoors."""
    return _hmac(k_tok, normalized_word.encode("utf-8"))


def index_label(k_idx: bytes, t: bytes, counter: int) -> bytes:
    """L = HMAC-SHA256(K_idx, T || counter). T is fixed-length, so the encoding is unambiguous."""
    return _hmac(k_idx, t + counter.to_bytes(8, "big"))


def posting_key(t: bytes) -> bytes:
    return hkdf(t, b"posting")


def encrypt_posting(t: bytes, label: bytes, doc_id: str) -> bytes:
    return encrypt(posting_key(t), doc_id.encode("ascii"), label)


def decrypt_posting(t: bytes, label: bytes, posting: bytes) -> str:
    return decrypt(posting_key(t), posting, label).decode("ascii")


def blind_index(k_blind: bytes, field: str, normalized_value: str) -> bytes:
    """Exact-match blind index token for a structured field (field name is domain-separated)."""
    return _hmac(k_blind, field.encode("utf-8") + b"\x00" + normalized_value.encode("utf-8"))


def fingerprint(data: bytes, n_hex: int = 16) -> str:
    """Short SHA-256 fingerprint used for audit "label hashes"."""
    return hashlib.sha256(data).hexdigest()[:n_hex]


def new_doc_id() -> str:
    return secrets.token_hex(16)
