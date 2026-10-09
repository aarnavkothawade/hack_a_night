import io
import json
import re

import pytest
from pypdf import PdfReader, PdfWriter

from app import create_app
from document_reader import DocumentError, read_document, text_from_stored
from tests.pdf_fixture import make_pdf

LINES = ["Quarterly pangolin acquisition memo", "Zircon budget approved for Bismuth division"]
SECRET_WORDS = ["pangolin", "zircon", "bismuth"]


def encrypted_pdf() -> bytes:
    writer = PdfWriter()
    writer.append(PdfReader(io.BytesIO(make_pdf(LINES))))
    writer.encrypt("secret-password")
    buf = io.BytesIO()
    writer.write(buf)
    return buf.getvalue()


# --- document_reader --------------------------------------------------------------

def test_reads_pdf_text_and_keeps_original_bytes():
    data = make_pdf(LINES)
    doc = read_document(data)
    assert doc.kind == "pdf" and doc.pages == 1 and doc.stored == data
    assert "pangolin" in doc.text.lower() and "zircon" in doc.text.lower()
    assert text_from_stored("pdf", doc.stored) == doc.text


def test_text_files_still_work():
    doc = read_document("﻿hello world".encode("utf-8"))
    assert doc.kind == "text" and doc.text == "hello world" and doc.stored == b"hello world"


@pytest.mark.parametrize(
    "data,message",
    [
        (make_pdf([]), "no text layer"),
        (b"%PDF-1.7\n this is not really a pdf", "could not be read"),
        (b"\xff\xfe\x00binary", "UTF-8 text files and PDFs"),
    ],
)
def test_unreadable_inputs_are_rejected_with_clear_messages(data, message):
    with pytest.raises(DocumentError, match=message):
        read_document(data)


def test_password_protected_pdf_is_rejected():
    with pytest.raises(DocumentError, match="password-protected"):
        read_document(encrypted_pdf())


# --- end to end over HTTP ------------------------------------------------------------

@pytest.fixture
def portal(tmp_path):
    app = create_app(tmp_path)
    client = app.test_client()
    html = client.get("/").get_data(as_text=True)
    token = re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)
    return client, token, tmp_path


def upload(client, token, data, name):
    return client.post("/upload", data={"file": (io.BytesIO(data), name)}, headers={"X-CSRF-Token": token})


def test_pdf_upload_search_decrypt_download_verify(portal):
    client, token, base = portal
    original = make_pdf(LINES)
    preview = client.post("/preview", data={"file": (io.BytesIO(original), "memo.pdf")},
                          headers={"X-CSRF-Token": token}).get_json()
    assert preview["kind"] == "pdf" and preview["pages"] == 1
    assert preview["blob_size"] == 12 + len(original) + 16  # the whole PDF is encrypted
    doc_id = client.post("/upload", json={"staging_id": preview["staging_id"]},
                         headers={"X-CSRF-Token": token}).get_json()["doc_id"]

    found = client.get("/search", query_string={"q": "pangolin AND zircon"}).get_json()
    assert found["doc_ids"] == [doc_id] and found["verified"]

    decrypted = client.get("/search", query_string={"q": "bismuth", "decrypt": "1"}).get_json()["decrypted"][doc_id]
    assert decrypted["ok"] and decrypted["kind"] == "pdf" and decrypted["filename"] == "memo.pdf"
    assert "pangolin" in decrypted["text"].lower()

    resp = client.get(f"/documents/{doc_id}/download")
    assert resp.status_code == 200 and resp.data == original
    assert resp.mimetype == "application/pdf" and "memo.pdf" in resp.headers["Content-Disposition"]

    report = client.get(f"/verify/{doc_id}").get_json()
    assert report["status"] == "pass", report


def test_pdf_never_leaks_to_server_side(portal):
    client, token, base = portal
    assert upload(client, token, make_pdf(LINES), "memo.pdf").status_code == 201
    client.get("/search", query_string={"q": "pangolin", "decrypt": "1"})
    blob = next((base / "local_store").iterdir()).read_bytes().lower()
    audit = (base / "audit.log").read_text().lower()
    view = client.get("/server-view").get_data(as_text=True).lower()
    for word in SECRET_WORDS + ["memo.pdf", "%pdf"]:
        assert word.encode() not in blob, word
        assert word not in audit and word not in view, word


def test_tampered_pdf_fails_verify_and_download(portal):
    client, token, base = portal
    doc_id = upload(client, token, make_pdf(LINES), "memo.pdf").get_json()["doc_id"]
    path = base / "local_store" / f"{doc_id}.bin"
    raw = bytearray(path.read_bytes())
    raw[40] ^= 0x01
    path.write_bytes(bytes(raw))
    assert client.get(f"/verify/{doc_id}").get_json()["status"] == "fail"
    resp = client.get(f"/documents/{doc_id}/download")
    assert resp.status_code == 422 and b"integrity" in resp.data


@pytest.mark.parametrize("data", [make_pdf([]), encrypted_pdf(), b"%PDF-1.4 garbage"])
def test_bad_pdfs_are_reported(portal, data):
    client, token, _ = portal
    resp = client.post("/preview", data={"file": (io.BytesIO(data), "x.pdf")}, headers={"X-CSRF-Token": token})
    assert resp.status_code == 400 and resp.get_json()["error"]


def test_text_documents_download_too(portal):
    client, token, _ = portal
    doc_id = upload(client, token, b"plain text body", "note.txt").get_json()["doc_id"]
    resp = client.get(f"/documents/{doc_id}/download")
    assert resp.data == b"plain text body" and resp.mimetype == "text/plain"


def test_download_rejects_bad_ids(portal):
    client, _, _ = portal
    assert client.get("/documents/" + "0" * 32 + "/download").status_code == 404
    assert client.get("/documents/nothex/download").status_code == 404
