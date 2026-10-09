"""Flask portal for the Verifiable SSE Engine.

Run:  python app.py        (serves http://localhost:5000)
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.exceptions import HTTPException

from boolean_parser import QueryError
from config_manager import STORAGE_CHOICES, ConfigError, validate_api_key, validate_credentials
from drive_client import DriveNotConnected
from sse_index import STRUCTURED_FIELDS
from vault import MAX_DOCUMENT_BYTES, Vault, VaultError

DOC_ID_RE = re.compile(r"^[0-9a-f]{32}$")
API_PREFIXES = ("/preview", "/upload", "/search", "/verify/")
CLASSIFICATIONS = ("Public", "Internal", "Confidential", "Restricted")
OAUTH_PENDING_TTL = 600

log = logging.getLogger("sse")

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'self' https://accounts.google.com",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
])


def create_app(base_dir: str | os.PathLike | None = None) -> Flask:
    base = Path(base_dir or os.environ.get("SSE_HOME") or Path(__file__).resolve().parent)
    vault = Vault(base)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=vault.config.flask_secret or secrets.token_hex(32),
        MAX_CONTENT_LENGTH=MAX_DOCUMENT_BYTES + 512 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
    )
    app.extensions["vault"] = vault
    pending_oauth: dict[str, tuple[str, str, float]] = {}

    # --- helpers --------------------------------------------------------------------

    def wants_json() -> bool:
        if request.path.startswith(API_PREFIXES):
            return True
        best = request.accept_mimetypes.best_match(["text/html", "application/json"])
        return best == "application/json"

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def error_response(message: str, status: int):
        if wants_json():
            return jsonify({"error": message, "status": status}), status
        return render_template("error.html", message=message, status=status), status

    def oauth_redirect_uri() -> str:
        summary = vault.config.credentials_summary()
        if summary and summary.get("valid"):
            data = json.loads(vault.config.credentials_path.read_text("utf-8"))
            client = data.get("web") or data.get("installed")
            for uri in client["redirect_uris"]:
                if urlsplit(uri).path.rstrip("/") == "/oauth2callback":
                    return uri
        return url_for("oauth2callback", _external=True)

    # --- request hooks ----------------------------------------------------------------

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
            expected = session.get("csrf")
            if not expected or not secrets.compare_digest(sent, expected):
                return error_response("Your session expired or the request was forged. Reload the page.", 400)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if not request.path.startswith("/static/"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    @app.template_filter("filesize")
    def filesize(n: int) -> str:
        if n < 1024:
            return f"{n} B"
        if n < 1024 * 1024:
            return f"{n / 1024:.1f} KB"
        return f"{n / 1024 / 1024:.2f} MB"

    @app.template_filter("when")
    def when(iso: str | None) -> str:
        return (iso or "").replace("T", " ")[:16] + " UTC" if iso else "—"

    @app.context_processor
    def inject_globals():
        return {
            "csrf_token": csrf_token,
            "storage": vault.storage_status(),
            "stats": vault.stats(),
        }

    # --- errors -------------------------------------------------------------------------

    @app.errorhandler(VaultError)
    def on_vault_error(exc: VaultError):
        return error_response(str(exc), exc.status)

    @app.errorhandler(QueryError)
    def on_query_error(exc: QueryError):
        return error_response(f"Query error: {exc}", 400)

    @app.errorhandler(HTTPException)
    def on_http_error(exc: HTTPException):
        messages = {
            404: "That page or document does not exist.",
            405: "That method is not allowed here.",
            413: "The upload is larger than 5 MB.",
        }
        return error_response(messages.get(exc.code, exc.description or exc.name), exc.code or 500)

    @app.errorhandler(Exception)
    def on_unexpected(exc: Exception):
        # Log the type only: exception messages can contain document text or keywords.
        log.error("unhandled %s in %s", type(exc).__name__, request.endpoint)
        return error_response(f"Internal error ({type(exc).__name__}). Details are not logged to protect plaintext.", 500)

    # --- pages ----------------------------------------------------------------------------

    @app.get("/")
    def dashboard():
        return render_template(
            "dashboard.html",
            documents=vault.documents()[:200],
            classifications=CLASSIFICATIONS,
            fields=STRUCTURED_FIELDS,
            page="dashboard",
        )

    @app.get("/server-view")
    def server_view():
        view = vault.server_view()
        if request.args.get("format") == "json":
            return jsonify(view)
        return render_template("server_view.html", view=view, page="server-view")

    # --- API -------------------------------------------------------------------------------

    def _fields_from_form() -> dict[str, str]:
        return {name: request.form.get(name, "") for name in STRUCTURED_FIELDS}

    def _uploaded_file():
        file = request.files.get("file")
        if file is None or not file.filename:
            raise VaultError("choose a text file first")
        return file.filename, file.read(MAX_DOCUMENT_BYTES + 1)

    @app.post("/preview")
    def preview():
        filename, data = _uploaded_file()
        return jsonify(vault.stage(filename, data, _fields_from_form()))

    @app.post("/preview/discard")
    def discard_preview():
        vault.discard((request.get_json(silent=True) or {}).get("staging_id", ""))
        return jsonify({"ok": True})

    @app.post("/upload")
    def upload():
        body = request.get_json(silent=True) or {}
        staging_id = body.get("staging_id") or request.form.get("staging_id")
        if staging_id:
            result = vault.commit(str(staging_id))
        else:
            filename, data = _uploaded_file()
            result = vault.upload(filename, data, _fields_from_form())
        return jsonify(result), 201

    @app.get("/search")
    def search():
        query = request.args.get("q", "")
        decrypt_arg = request.args.get("decrypt", "").strip()
        decrypt: set[str] | bool = False
        if decrypt_arg in ("1", "true", "all"):
            decrypt = True
        elif decrypt_arg:
            decrypt = {d for d in decrypt_arg.split(",") if DOC_ID_RE.fullmatch(d)}
        return jsonify(vault.search(query, decrypt))

    @app.get("/verify/<doc_id>")
    def verify(doc_id: str):
        if not DOC_ID_RE.fullmatch(doc_id):
            abort(404)
        return jsonify(vault.verify(doc_id))

    # --- setup --------------------------------------------------------------------------------

    @app.get("/setup")
    def setup():
        return render_template(
            "setup.html",
            config=vault.config.summary(),
            redirect_uri=oauth_redirect_uri(),
            page="setup",
        )

    @app.post("/setup")
    def save_setup():
        cfg = vault.config
        errors: list[str] = []
        storage = request.form.get("storage", "local")
        pasted = request.form.get("credentials_json", "").strip()
        upload_file = request.files.get("credentials_file")
        raw = upload_file.read(70 * 1024) if upload_file and upload_file.filename else pasted.encode()
        api_key = request.form.get("api_key", "")

        # Validate everything before writing anything.
        if storage not in STORAGE_CHOICES:
            errors.append("Choose Local storage or Google Drive.")
        if raw:
            try:
                validate_credentials(raw)
            except ConfigError as exc:
                errors.append(str(exc).capitalize() + ".")
        if storage == "drive" and not raw and not cfg.credentials_path.exists():
            errors.append("Google Drive needs a credentials.json OAuth client.")
        if api_key.strip():
            try:
                validate_api_key(api_key)
            except ConfigError as exc:
                errors.append(str(exc) + ".")

        if errors:
            for message in errors:
                flash(message, "error")
            return redirect(url_for("setup"))

        changed = 0
        if raw:
            cfg.save_credentials(raw)
            vault.reset_drive()
            changed += 1
        if api_key.strip():
            cfg.set_api_key(api_key)
            vault.reset_drive()
            changed += 1
        elif request.form.get("clear_api_key"):
            cfg.clear_api_key()
            vault.reset_drive()
            changed += 1
        if storage != cfg.storage:
            cfg.set_storage(storage)
            changed += 1
        vault.audit.log("setup", result_count=changed)
        flash("Settings saved." if changed else "Nothing changed.", "success")
        return redirect(url_for("setup"))

    # --- Google Drive OAuth (only on an explicit click) ------------------------------------

    @app.post("/drive/connect")
    def drive_connect():
        if not vault.drive_auth.has_client():
            flash("Add a credentials.json OAuth client before connecting Google Drive.", "error")
            return redirect(url_for("setup"))
        redirect_uri = oauth_redirect_uri()
        try:
            url, state, verifier = vault.drive_auth.start(redirect_uri)
        except (ConfigError, DriveNotConnected) as exc:
            flash(f"Cannot start Google sign-in: {exc}.", "error")
            return redirect(url_for("setup"))
        now = time.time()
        for key in [k for k, v in pending_oauth.items() if now - v[2] > OAUTH_PENDING_TTL]:
            del pending_oauth[key]
        pending_oauth[state] = (verifier, redirect_uri, now)
        session["oauth_state"] = state
        return redirect(url)

    @app.get("/oauth2callback")
    def oauth2callback():
        state = request.args.get("state", "")
        pending = pending_oauth.pop(state, None)
        if request.args.get("error"):
            flash("Google sign-in was cancelled or denied.", "error")
            return redirect(url_for("setup"))
        if not pending or not secrets.compare_digest(state, session.pop("oauth_state", "")):
            flash("Google sign-in could not be verified (state mismatch). Try again.", "error")
            return redirect(url_for("setup"))
        verifier, redirect_uri, _ = pending
        if urlsplit(redirect_uri).hostname in ("localhost", "127.0.0.1"):
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # plain http is acceptable on loopback only
        try:
            vault.drive_auth.finish(redirect_uri, request.url, verifier)
        except Exception as exc:  # oauthlib raises many types; never surface token material
            log.error("drive oauth failed: %s", type(exc).__name__)
            vault.audit.log("drive_connect", status="fail")
            flash(f"Could not finish Google sign-in ({type(exc).__name__}).", "error")
            return redirect(url_for("setup"))
        vault.reset_drive()
        vault.audit.log("drive_connect")
        flash("Google Drive connected. New uploads go to the “SSE Engine Vault” folder.", "success")
        return redirect(url_for("dashboard"))

    @app.post("/drive/disconnect")
    def drive_disconnect():
        vault.drive_auth.disconnect()
        vault.reset_drive()
        vault.audit.log("drive_disconnect")
        flash("Google Drive disconnected and token.json removed.", "success")
        return redirect(url_for("setup"))

    return app


def _quiet_request_handler():
    """Werkzeug handler that logs method, path and status but never the query string."""
    from werkzeug.serving import WSGIRequestHandler

    class Handler(WSGIRequestHandler):
        def log_request(self, code="-", size="-"):
            path = urlsplit(self.path).path
            self.log("info", '"%s %s" %s', self.command, path, code)

    return Handler


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    port = int(os.environ.get("PORT", "5000"))
    create_app().run(host="127.0.0.1", port=port, debug=False, request_handler=_quiet_request_handler())
