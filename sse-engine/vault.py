"""Portal service layer: ties keys, index, storage, audit log and settings together.

Trust model: this process is the *portal*. It holds master.key and sees plaintext
briefly while encrypting, indexing and decrypting on request. Everything it writes
to the storage provider, search_index.json, documents.json and audit.log is
ciphertext, PRF output, sizes, timestamps or random IDs.
"""
from __future__ import annotations

import json
import secrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import crypto_engine as ce
from audit_logger import AuditLogger
from config_manager import ConfigManager
from drive_client import DriveAuth, DriveNotConnected, DriveStorage
from local_storage import LocalStorage
from sse_index import (
    STRUCTURED_FIELDS,
    SSEIndex,
    _atomic_write,
    normalize_field_value,
    tokenize,
)
from storage_provider import StorageError, StorageProvider

MAX_DOCUMENT_BYTES = 5 * 1024 * 1024
MAX_FILENAME_LEN = 200
MAX_FIELD_LEN = 64
MAX_DECRYPTED_CHARS = 100_000
STAGING_TTL_SECONDS = 15 * 60
MAX_STAGED = 20


class VaultError(Exception):
    """User-facing error; the message is safe to display and contains no plaintext."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


@dataclass
class Staged:
    doc_id: str
    blob: bytes
    meta_blob: bytes
    blind: dict[str, str]
    tokens: set[str] = field(repr=False)
    created: float = field(default_factory=time.monotonic)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Vault:
    def __init__(self, base_dir: str | Path):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.config = ConfigManager(self.base_dir)
        self.audit = AuditLogger(self.base_dir / "audit.log")
        key_path = self.base_dir / "master.key"
        created = not key_path.exists()
        self.keys = ce.derive_keys(ce.load_or_create_master_key(key_path))
        if created:
            self.audit.log("key_created")
        self.index = SSEIndex(self.keys, self.base_dir / "search_index.json", self.base_dir / "index_state.bin")
        self.manifest_path = self.base_dir / "documents.json"
        self.manifest: dict[str, dict] = (
            json.loads(self.manifest_path.read_text("utf-8")) if self.manifest_path.exists() else {}
        )
        self.local = LocalStorage(self.base_dir / "local_store")
        self.drive_auth = DriveAuth(self.base_dir / "credentials.json", self.base_dir / "token.json")
        self._drive: DriveStorage | None = None
        self._staged: dict[str, Staged] = {}
        self._lock = threading.RLock()

    # --- providers ---------------------------------------------------------------

    def provider_for(self, name: str) -> StorageProvider:
        if name == "local":
            return self.local
        if name == "drive":
            if not self.drive_auth.is_connected():
                raise VaultError("Google Drive is not connected. Use “Connect Google Drive” first.", 409)
            if self._drive is None:
                self._drive = DriveStorage(self.drive_auth, api_key=self.config.api_key)
            return self._drive
        raise VaultError("unknown storage provider", 500)

    def reset_drive(self) -> None:
        self._drive = None

    @property
    def active_provider_name(self) -> str:
        return self.config.storage

    def storage_status(self) -> dict:
        choice = self.config.storage
        connected = self.drive_auth.is_connected()
        return {
            "choice": choice,
            "drive_connected": connected,
            "has_credentials": self.drive_auth.has_client(),
            "ready": choice == "local" or connected,
            "label": "Local storage" if choice == "local" else "Google Drive",
        }

    # --- upload --------------------------------------------------------------------

    def _clean_fields(self, fields: dict[str, str] | None) -> dict[str, str]:
        clean = {}
        for name in STRUCTURED_FIELDS:
            value = " ".join(((fields or {}).get(name) or "").split())
            if len(value) > MAX_FIELD_LEN:
                raise VaultError(f"{name} is too long (max {MAX_FIELD_LEN} characters)")
            if value and normalize_field_value(value):
                clean[name] = value
        return clean

    def stage(self, filename: str, data: bytes, fields: dict[str, str] | None = None) -> dict:
        """Encrypt a document and hold it in memory until the user confirms the upload."""
        if not data:
            raise VaultError("the file is empty")
        if len(data) > MAX_DOCUMENT_BYTES:
            raise VaultError("the file is larger than 5 MB", 413)
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise VaultError("only UTF-8 text documents are supported") from None
        filename = (filename or "untitled.txt").replace("\\", "/").rsplit("/", 1)[-1][:MAX_FILENAME_LEN]
        clean = self._clean_fields(fields)
        tokens = tokenize(text)

        doc_id = ce.new_doc_id()
        blob = ce.encrypt(self.keys.enc, text.encode("utf-8"), ce.doc_aad(doc_id))
        meta = {"filename": filename, "fields": clean, "chars": len(text)}
        meta_blob = ce.encrypt(self.keys.enc, json.dumps(meta).encode(), ce.meta_aad(doc_id))
        blind = {
            name: ce.blind_index(self.keys.blind, name, normalize_field_value(value)).hex()
            for name, value in clean.items()
        }
        staging_id = secrets.token_urlsafe(18)
        with self._lock:
            self._expire_staged()
            if len(self._staged) >= MAX_STAGED:
                oldest = min(self._staged, key=lambda k: self._staged[k].created)
                del self._staged[oldest]
            self._staged[staging_id] = Staged(doc_id, blob, meta_blob, blind, tokens)

        nonce, ciphertext, tag = ce.split_blob(blob)
        return {
            "staging_id": staging_id,
            "doc_id": doc_id,
            "blob_size": len(blob),
            "nonce_hex": nonce.hex(),
            "ciphertext_head": ciphertext.hex()[:64],
            "tag_hex": tag.hex(),
            "keyword_count": len(tokens),
            "blind_fields": sorted(blind),
            "expires_in": STAGING_TTL_SECONDS,
        }

    def _expire_staged(self) -> None:
        cutoff = time.monotonic() - STAGING_TTL_SECONDS
        for key in [k for k, s in self._staged.items() if s.created < cutoff]:
            del self._staged[key]

    def discard(self, staging_id: str) -> None:
        with self._lock:
            self._staged.pop(staging_id, None)

    def commit(self, staging_id: str) -> dict:
        with self._lock:
            self._expire_staged()
            staged = self._staged.pop(staging_id, None)
            if staged is None:
                raise VaultError("this preview has expired; choose the file again", 410)
            try:
                return self._commit(staged)
            except VaultError:
                raise
            except DriveNotConnected as exc:
                self.audit.log("upload", status="error")
                raise VaultError(str(exc), 409) from None
            except StorageError as exc:
                self.audit.log("upload", status="error")
                raise VaultError(f"storage failed: {exc}", 502) from None

    def _commit(self, staged: Staged) -> dict:
        provider_name = self.active_provider_name
        provider = self.provider_for(provider_name)
        file_id = provider.upload_bytes(f"{staged.doc_id}.bin", staged.blob)
        try:
            update = self.index.add_document(staged.doc_id, staged.tokens)
        except BaseException:
            provider.delete_file(file_id)
            raise
        record = {
            "doc_id": staged.doc_id,
            "provider": provider_name,
            "file_id": file_id,
            "blob_size": len(staged.blob),
            "blob_head": staged.blob[:8].hex(),
            "uploaded_at": _now(),
            "meta": staged.meta_blob.hex(),
            "blind": staged.blind,
        }
        try:
            self.manifest[staged.doc_id] = record
            self._save_manifest()
        except BaseException:
            self.manifest.pop(staged.doc_id, None)
            self.index.rollback(update)
            provider.delete_file(file_id)
            raise
        self.audit.log("upload", blob_ids=[staged.doc_id], labels=update.labels, result_count=1)
        return {
            "doc_id": staged.doc_id,
            "provider": provider_name,
            "blob_size": record["blob_size"],
            "postings_added": len(update.labels),
        }

    def upload(self, filename: str, data: bytes, fields: dict[str, str] | None = None) -> dict:
        """One-shot encrypt + store + index (used by API clients and tests)."""
        return self.commit(self.stage(filename, data, fields)["staging_id"])

    def _save_manifest(self) -> None:
        _atomic_write(self.manifest_path, json.dumps(self.manifest, indent=1, sort_keys=True).encode())

    # --- search ----------------------------------------------------------------------

    def _field_lookup(self, field_name: str, normalized_value: str) -> set[str]:
        token = ce.blind_index(self.keys.blind, field_name, normalized_value).hex()
        return {d for d, rec in self.manifest.items() if rec.get("blind", {}).get(field_name) == token}

    def search(self, query: str, decrypt: set[str] | bool = False) -> dict:
        universe = set(self.manifest)
        result = self.index.search(query, universe, self._field_lookup)
        doc_ids = sorted(result.doc_ids, key=lambda d: self.manifest[d]["uploaded_at"], reverse=True)
        self.audit.log(
            "search",
            labels=result.labels,
            result_count=len(doc_ids),
            terms=len(result.terms),
            field_lookups=result.field_lookups,
            verified=result.verified,
        )
        response = {
            "count": len(doc_ids),
            "doc_ids": doc_ids,
            "results": [self._public_record(d) for d in doc_ids],
            "verified": result.verified,
            "problems": result.problems,
            "keyword_lookups": len(result.terms),
            "labels_read": len(result.labels),
            "field_lookups": result.field_lookups,
        }
        if decrypt:
            wanted = doc_ids if decrypt is True else [d for d in doc_ids if d in decrypt]
            response["decrypted"] = {d: self.decrypt_document(d, audit=False) for d in wanted}
            self.audit.log("decrypt", blob_ids=wanted, result_count=len(wanted))
        return response

    def _public_record(self, doc_id: str) -> dict:
        rec = self.manifest[doc_id]
        return {
            "doc_id": doc_id,
            "provider": rec["provider"],
            "blob_size": rec["blob_size"],
            "uploaded_at": rec["uploaded_at"],
        }

    def decrypt_document(self, doc_id: str, *, audit: bool = True) -> dict:
        rec = self._record(doc_id)
        try:
            blob = self.provider_for(rec["provider"]).download_bytes(rec["file_id"])
            text = ce.decrypt(self.keys.enc, blob, ce.doc_aad(doc_id)).decode("utf-8")
            meta = json.loads(ce.decrypt(self.keys.enc, bytes.fromhex(rec["meta"]), ce.meta_aad(doc_id)))
        except ce.IntegrityError:
            if audit:
                self.audit.log("decrypt", status="fail", blob_ids=[doc_id])
            return {"ok": False, "error": "integrity check failed: the blob was modified or swapped"}
        except StorageError as exc:
            return {"ok": False, "error": f"storage failed: {exc}"}
        if audit:
            self.audit.log("decrypt", blob_ids=[doc_id], result_count=1)
        return {
            "ok": True,
            "filename": meta["filename"],
            "fields": meta["fields"],
            "text": text[:MAX_DECRYPTED_CHARS],
            "truncated": len(text) > MAX_DECRYPTED_CHARS,
        }

    def _record(self, doc_id: str) -> dict:
        rec = self.manifest.get(doc_id)
        if rec is None:
            raise VaultError("unknown document ID", 404)
        return rec

    # --- verification ----------------------------------------------------------------

    def verify(self, doc_id: str) -> dict:
        rec = self._record(doc_id)
        checks: list[dict] = []

        def check(name: str, ok: bool, detail: str) -> bool:
            checks.append({"name": name, "ok": bool(ok), "detail": detail})
            return ok

        blob = None
        try:
            blob = self.provider_for(rec["provider"]).download_bytes(rec["file_id"])
            check("blob_present", True, f"{len(blob)} bytes fetched from {rec['provider']}")
        except (StorageError, VaultError) as exc:
            check("blob_present", False, str(exc))

        text = None
        if blob is not None:
            check("blob_size", len(blob) == rec["blob_size"], f"expected {rec['blob_size']}, got {len(blob)}")
            try:
                text = ce.decrypt(self.keys.enc, blob, ce.doc_aad(doc_id)).decode("utf-8")
                check("gcm_tag", True, "AES-256-GCM tag valid with document ID as AAD")
            except ce.IntegrityError:
                check("gcm_tag", False, "tag mismatch: blob was modified, truncated or swapped")

        meta = None
        try:
            meta = json.loads(ce.decrypt(self.keys.enc, bytes.fromhex(rec["meta"]), ce.meta_aad(doc_id)))
            check("metadata_tag", True, "encrypted metadata authenticates")
        except (ce.IntegrityError, ValueError):
            check("metadata_tag", False, "metadata ciphertext failed authentication")

        if text is not None:
            stats = self.index.verify_document(doc_id, tokenize(text))
            check(
                "index_entries",
                stats["missing"] == 0 and stats["tampered"] == 0,
                f"{stats['found']}/{stats['keywords']} keyword postings found, {stats['tampered']} tampered",
            )
        if meta is not None:
            expected = {
                name: ce.blind_index(self.keys.blind, name, normalize_field_value(value)).hex()
                for name, value in meta["fields"].items()
            }
            check("blind_index", expected == rec.get("blind", {}), f"{len(expected)} structured field token(s)")

        passed = all(c["ok"] for c in checks) and any(c["name"] == "index_entries" for c in checks)
        self.audit.log("verify", status="ok" if passed else "fail", blob_ids=[doc_id], passed=passed)
        return {"doc_id": doc_id, "status": "pass" if passed else "fail", "checks": checks}

    # --- views -----------------------------------------------------------------------

    def documents(self) -> list[dict]:
        docs = [self._public_record(d) for d in self.manifest]
        return sorted(docs, key=lambda r: r["uploaded_at"], reverse=True)

    def stats(self) -> dict:
        return {
            "documents": len(self.manifest),
            "postings": len(self.index),
            "stored_bytes": sum(r["blob_size"] for r in self.manifest.values()),
        }

    def server_view(self, audit_limit: int = 100) -> dict:
        """Exactly the kind of data an honest-but-curious server holds. No plaintext."""
        blobs = [
            {
                "blob_id": rec["file_id"],
                "provider": rec["provider"],
                "size": rec["blob_size"],
                "head": rec["blob_head"],
                "uploaded_at": rec["uploaded_at"],
                "blind": rec.get("blind", {}),
            }
            for rec in sorted(self.manifest.values(), key=lambda r: r["uploaded_at"], reverse=True)
        ]
        return {
            "blobs": blobs,
            "labels": self.index.labels(),
            "audit": self.audit.tail(audit_limit),
            "stats": self.stats(),
        }
