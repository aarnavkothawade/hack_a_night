import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from app import create_app
from tests.corpus import ABSENT, VOCAB, make_corpus

PROJECT = Path(__file__).resolve().parent.parent
DEPARTMENTS = ["Treasury", "Logistics", "Human Resources"]


def csrf(client) -> str:
    html = client.get("/").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


@pytest.fixture(scope="module")
def populated(tmp_path_factory):
    """Upload the 50-document corpus over HTTP, then exercise search, decrypt, verify and server-view."""
    base = tmp_path_factory.mktemp("portal")
    app = create_app(base)
    client = app.test_client()
    token = csrf(client)
    corpus = make_corpus(50)
    baseline, departments = {}, {}
    for i, (text, words) in enumerate(corpus):
        dept = DEPARTMENTS[i % 3]
        data = {"file": (io.BytesIO(text.encode()), f"memo-{i}.txt"), "department": dept, "classification": "Internal"}
        if i % 2 == 0:  # two-step: preview, then commit the staged ciphertext
            preview = client.post("/preview", data=data, headers={"X-CSRF-Token": token}).get_json()
            resp = client.post("/upload", json={"staging_id": preview["staging_id"]}, headers={"X-CSRF-Token": token})
            assert resp.get_json()["doc_id"] == preview["doc_id"]
        else:  # one-shot API upload
            resp = client.post("/upload", data=data, headers={"X-CSRF-Token": token})
        assert resp.status_code == 201, resp.get_json()
        doc_id = resp.get_json()["doc_id"]
        baseline[doc_id] = words
        departments[doc_id] = dept

    # Exercise every read path so the leak checks below cover them.
    for q in ("quokka", "quokka AND walrus", "nebula OR tundra", "NOT basalt", "(lynx OR krill) AND NOT sorrel"):
        assert client.get("/search", query_string={"q": q}).status_code == 200
    client.get("/search", query_string={"q": "zephyr", "decrypt": "1"})
    for doc_id in list(baseline)[:5]:
        assert client.get(f"/verify/{doc_id}").get_json()["status"] == "pass"
    return {"app": app, "client": client, "base": base, "baseline": baseline, "departments": departments, "token": token}


def search_ids(client, q):
    resp = client.get("/search", query_string={"q": q})
    assert resp.status_code == 200, resp.get_json()
    data = resp.get_json()
    assert data["verified"]
    return set(data["doc_ids"])


@pytest.mark.parametrize(
    "q,predicate",
    [
        ("obsidian", lambda w: "obsidian" in w),
        ("obsidian AND fjord", lambda w: {"obsidian", "fjord"} <= w),
        ("obsidian OR fjord", lambda w: bool({"obsidian", "fjord"} & w)),
        ("NOT obsidian", lambda w: "obsidian" not in w),
        ("(obsidian OR fjord) AND NOT (sphinx OR kumquat)",
         lambda w: bool({"obsidian", "fjord"} & w) and not ({"sphinx", "kumquat"} & w)),
        (f"{ABSENT} OR pelican", lambda w: "pelican" in w),
    ],
)
def test_http_boolean_search_matches_baseline(populated, q, predicate):
    expected = {d for d, w in populated["baseline"].items() if predicate(w)}
    assert search_ids(populated["client"], q) == expected


def test_blind_index_field_search(populated):
    client, depts, baseline = populated["client"], populated["departments"], populated["baseline"]
    assert search_ids(client, "department:human-resources") == {d for d, v in depts.items() if v == "Human Resources"}
    expected = {d for d, v in depts.items() if v == "Treasury" and "lagoon" in baseline[d]}
    assert search_ids(client, "department:TREASURY AND lagoon") == expected
    assert search_ids(client, "classification:internal") == set(baseline)


def test_search_returns_ids_only_unless_decrypt_requested(populated):
    client = populated["client"]
    plain = client.get("/search", query_string={"q": "wombat"}).get_json()
    assert "decrypted" not in plain and plain["count"] == len(plain["doc_ids"]) > 0
    target = plain["doc_ids"][0]
    one = client.get("/search", query_string={"q": "wombat", "decrypt": target}).get_json()
    assert list(one["decrypted"]) == [target]
    doc = one["decrypted"][target]
    assert doc["ok"] and "wombat" in doc["text"].lower() and doc["filename"].startswith("memo-")


def test_bad_query_reports_error(populated):
    resp = populated["client"].get("/search", query_string={"q": "quokka AND ("})
    assert resp.status_code == 400 and "Query error" in resp.get_json()["error"]
    resp = populated["client"].get("/search", query_string={"q": "the"})
    assert resp.status_code == 400


def test_verify_detects_tampered_blob(populated):
    client, base = populated["client"], populated["base"]
    token = populated["token"]
    doc_id = client.post(
        "/upload", data={"file": (io.BytesIO(b"tamper target text"), "t.txt")}, headers={"X-CSRF-Token": token}
    ).get_json()["doc_id"]
    assert client.get(f"/verify/{doc_id}").get_json()["status"] == "pass"
    blob_path = base / "local_store" / f"{doc_id}.bin"
    raw = bytearray(blob_path.read_bytes())
    raw[20] ^= 0xFF
    blob_path.write_bytes(bytes(raw))
    report = client.get(f"/verify/{doc_id}").get_json()
    assert report["status"] == "fail"
    assert {c["name"]: c["ok"] for c in report["checks"]}["gcm_tag"] is False
    decrypted = client.get("/search", query_string={"q": "tamper", "decrypt": "1"}).get_json()["decrypted"]
    assert decrypted[doc_id]["ok"] is False


def test_verify_unknown_and_malformed_ids(populated):
    assert populated["client"].get("/verify/" + "0" * 32).status_code == 404
    assert populated["client"].get("/verify/../etc").status_code == 404


def test_audit_log_contains_no_corpus_keyword(populated):
    raw = (populated["base"] / "audit.log").read_text().lower()
    assert raw.count("\n") > 50
    leaked = [w for w in VOCAB if w in raw]
    assert leaked == [], f"audit.log leaks: {leaked}"
    for line in raw.splitlines():
        json.loads(line)  # every line is a JSON object


def test_server_view_contains_no_corpus_keyword(populated):
    client = populated["client"]
    for url in ("/server-view", "/server-view?format=json"):
        body = client.get(url).get_data(as_text=True).lower()
        leaked = [w for w in VOCAB if w in body]
        assert leaked == [], f"{url} leaks: {leaked}"
        assert "memo-" not in body and "treasury" not in body  # filenames and field values stay encrypted
    view = client.get("/server-view?format=json").get_json()
    assert len(view["labels"]) == sum(len(w) for w in populated["baseline"].values()) + 3
    assert all(len(b["head"]) == 16 for b in view["blobs"])


def test_disk_state_contains_no_corpus_keyword(populated):
    base = populated["base"]
    for name in ("search_index.json", "documents.json", "index_state.bin"):
        data = (base / name).read_bytes().lower()
        assert not [w for w in VOCAB if w.encode() in data], name
    for blob in (base / "local_store").iterdir():
        assert not [w for w in VOCAB if w.encode() in blob.read_bytes().lower()]


def test_dashboard_lists_ids_not_plaintext(populated):
    html = populated["client"].get("/").get_data(as_text=True).lower()
    assert "save to local storage" in html
    assert not [w for w in VOCAB if w in html]


def test_security_headers_and_csrf(populated):
    client = populated["client"]
    resp = client.get("/")
    assert "default-src 'self'" in resp.headers["Content-Security-Policy"]
    assert resp.headers["Cache-Control"] == "no-store"
    fresh = populated["app"].test_client()
    fresh.get("/")
    assert fresh.post("/upload", data={"file": (io.BytesIO(b"x"), "x.txt")}).status_code == 400


def test_preview_never_returns_plaintext(populated):
    client, token = populated["client"], populated["token"]
    secret = b"zebracorn quarterly secret plan"
    preview = client.post(
        "/preview", data={"file": (io.BytesIO(secret), "plan.txt")}, headers={"X-CSRF-Token": token}
    ).get_json()
    body = json.dumps(preview).lower()
    assert "zebracorn" not in body and "plan.txt" not in body
    assert len(preview["ciphertext_head"]) == 2 * len(secret) and len(preview["nonce_hex"]) == 24
    assert preview["blob_size"] == 12 + len(secret) + 16


def test_upload_rejects_binary_and_empty(populated):
    client, token = populated["client"], populated["token"]
    for payload in (b"", b"\xff\xfe\x00\x81binary"):
        resp = client.post("/preview", data={"file": (io.BytesIO(payload), "x.bin")}, headers={"X-CSRF-Token": token})
        assert resp.status_code == 400 and resp.get_json()["error"]


# --- setup & Drive -------------------------------------------------------------------

GOOD_CREDS = {
    "web": {
        "client_id": "1234-abcdefgh.apps.googleusercontent.com",
        "client_secret": "GOCSPX-supersecretvalue9z1Q",
        "redirect_uris": ["http://localhost:5000/oauth2callback"],
    }
}


@pytest.fixture
def fresh(tmp_path):
    app = create_app(tmp_path)
    client = app.test_client()
    return app, client, csrf(client), tmp_path


def test_setup_page_warns_and_has_password_field(fresh):
    _, client, _, _ = fresh
    html = client.get("/setup").get_data(as_text=True)
    assert "Local demo only" in html and "for local demos" in html
    assert 'type="password" name="api_key"' in html


def test_setup_validates_before_saving(fresh):
    _, client, token, base = fresh
    resp = client.post("/setup", data={"csrf_token": token, "storage": "drive", "credentials_json": '{"web": {}}'},
                       follow_redirects=True)
    assert "missing client_id" in resp.get_data(as_text=True)
    assert not (base / "credentials.json").exists() and not (base / ".env").exists()


def test_setup_saves_and_never_echoes_secrets(fresh):
    _, client, token, base = fresh
    resp = client.post(
        "/setup",
        data={"csrf_token": token, "storage": "drive", "credentials_json": json.dumps(GOOD_CREDS), "api_key": "AIzaSyTopSecretKey7788"},
        follow_redirects=True,
    )
    html = resp.get_data(as_text=True)
    assert "Settings saved" in html
    assert "supersecret" not in html and "TopSecret" not in html
    assert "9z1Q" in html and "7788" in html  # last 4 characters only
    assert (base / "credentials.json").exists()
    # Drive selected but not connected: the dashboard offers to connect, never logs in by itself.
    dash = client.get("/").get_data(as_text=True)
    assert "Connect Google Drive" in dash and "Send to Google Drive" not in dash
    assert not (base / "token.json").exists()


def test_drive_connect_redirects_to_google_only_on_post(fresh):
    _, client, token, base = fresh
    (base / "credentials.json").write_text(json.dumps(GOOD_CREDS))
    assert client.get("/drive/connect").status_code == 405
    resp = client.post("/drive/connect", data={"csrf_token": token})
    assert resp.status_code == 302 and resp.headers["Location"].startswith("https://accounts.google.com/")
    assert "drive.file" in resp.headers["Location"]
    assert not (base / "token.json").exists()  # nothing is saved until Google calls back


def test_drive_connect_with_broken_credentials_is_reported(fresh):
    _, client, token, base = fresh
    (base / "credentials.json").write_text('{"web": {"client_id": "x"}}')
    resp = client.post("/drive/connect", data={"csrf_token": token}, follow_redirects=True)
    assert resp.status_code == 200 and "Cannot start Google sign-in" in resp.get_data(as_text=True)


def test_upload_to_unconnected_drive_is_reported(fresh):
    _, client, token, base = fresh
    (base / ".env").write_text('SSE_STORAGE="drive"\n')
    preview = client.post("/preview", data={"file": (io.BytesIO(b"hello world"), "a.txt")},
                          headers={"X-CSRF-Token": token}).get_json()
    resp = client.post("/upload", json={"staging_id": preview["staging_id"]}, headers={"X-CSRF-Token": token})
    assert resp.status_code == 409 and "not connected" in resp.get_json()["error"]


def test_import_and_page_load_do_not_start_oauth(tmp_path):
    code = (
        "import sys; from app import create_app; c = create_app(sys.argv[1]).test_client();"
        "assert c.get('/').status_code == 200; assert c.get('/setup').status_code == 200;"
        "assert 'google_auth_oauthlib.flow' not in sys.modules, 'oauth flow imported';"
        "print('ok')"
    )
    out = subprocess.run([sys.executable, "-c", code, str(tmp_path)], cwd=PROJECT, capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert not (tmp_path / "token.json").exists()


def test_preview_head_is_64_hex_for_longer_documents(populated):
    client, token = populated["client"], populated["token"]
    preview = client.post(
        "/preview", data={"file": (io.BytesIO(b"x" * 500), "long.txt")}, headers={"X-CSRF-Token": token}
    ).get_json()
    assert re.fullmatch(r"[0-9a-f]{64}", preview["ciphertext_head"])
    assert preview["blob_size"] == 12 + 500 + 16
