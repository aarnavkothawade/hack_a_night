"""Abstract storage provider. Providers only ever see opaque ciphertext blobs."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod

BLOB_NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}(\.[A-Za-z0-9]{1,8})?$")


class StorageError(Exception):
    """A provider operation failed. Messages must never contain plaintext."""


class BlobNotFound(StorageError):
    pass


class StorageProvider(ABC):
    name: str = "abstract"
    label: str = "Storage"

    @abstractmethod
    def upload_bytes(self, name: str, data: bytes) -> str:
        """Store data under a blob name and return the provider's file ID."""

    @abstractmethod
    def download_bytes(self, file_id: str) -> bytes:
        """Return the stored bytes. Raises BlobNotFound."""

    @abstractmethod
    def delete_file(self, file_id: str) -> None:
        """Delete the blob. Deleting a missing blob is not an error."""

    @staticmethod
    def check_name(name: str) -> str:
        if not BLOB_NAME_RE.fullmatch(name):
            raise StorageError("invalid blob name")
        return name
