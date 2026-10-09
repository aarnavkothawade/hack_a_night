import json

import pytest

from audit_logger import AuditLogger
from local_storage import LocalStorage
from storage_provider import BlobNotFound, StorageError


def test_local_storage_round_trip_and_delete(tmp_path):
    store = LocalStorage(tmp_path / "local_store")
    fid = store.upload_bytes("abc123.bin", b"\x00\x01ciphertext")
    assert store.download_bytes(fid) == b"\x00\x01ciphertext"
    store.delete_file(fid)
    store.delete_file(fid)  # idempotent
    with pytest.raises(BlobNotFound):
        store.download_bytes(fid)


@pytest.mark.parametrize("name", ["../escape", "a/b", "", ".hidden", "x" * 200, "a b"])
def test_local_storage_rejects_unsafe_names(tmp_path, name):
    with pytest.raises(StorageError):
        LocalStorage(tmp_path).upload_bytes(name, b"x")


def test_local_storage_refuses_overwrite(tmp_path):
    store = LocalStorage(tmp_path)
    store.upload_bytes("a.bin", b"1")
    with pytest.raises(StorageError):
        store.upload_bytes("a.bin", b"2")


def test_audit_log_is_json_lines_with_hashed_labels(tmp_path):
    log = AuditLogger(tmp_path / "audit.log")
    log.log("search", labels=[b"\x01" * 32, b"\x02" * 32], result_count=3, terms=2)
    log.log("upload", blob_ids=["0123456789abcdef0123"], result_count=1)
    lines = (tmp_path / "audit.log").read_text().splitlines()
    first = json.loads(lines[0])
    assert first["op"] == "search" and first["label_count"] == 2 and first["terms"] == 2
    assert all(len(h) == 16 for h in first["label_hashes"])
    assert log.tail(1)[0]["op"] == "upload"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"op": "keyword: merger"},
        {"op": "search", "status": "merger"},
        {"op": "upload", "blob_ids": ["secret plan.txt"]},
        {"op": "search", "query": "merger"},
    ],
)
def test_audit_log_rejects_free_text(tmp_path, kwargs):
    with pytest.raises(ValueError):
        AuditLogger(tmp_path / "audit.log").log(**kwargs)
    assert not (tmp_path / "audit.log").exists()
