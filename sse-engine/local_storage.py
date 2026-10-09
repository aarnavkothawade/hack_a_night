"""Filesystem provider rooted at ./local_store/ (the default for the demo)."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from storage_provider import BlobNotFound, StorageError, StorageProvider


class LocalStorage(StorageProvider):
    name = "local"
    label = "Local storage"

    def __init__(self, root: str | os.PathLike):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, file_id: str) -> Path:
        path = (self.root / self.check_name(file_id)).resolve()
        if path.parent != self.root:  # defence in depth on top of the name regex
            raise StorageError("invalid blob name")
        return path

    def upload_bytes(self, name: str, data: bytes) -> str:
        path = self._path(name)
        if path.exists():
            raise StorageError("blob already exists")
        fd, tmp = tempfile.mkstemp(dir=self.root, prefix=".upload-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            os.replace(tmp, path)
        except OSError as exc:
            Path(tmp).unlink(missing_ok=True)
            raise StorageError("could not write blob") from exc
        return name

    def download_bytes(self, file_id: str) -> bytes:
        try:
            return self._path(file_id).read_bytes()
        except FileNotFoundError as exc:
            raise BlobNotFound("blob not found") from exc

    def delete_file(self, file_id: str) -> None:
        self._path(file_id).unlink(missing_ok=True)
