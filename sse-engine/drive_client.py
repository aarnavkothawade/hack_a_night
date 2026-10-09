"""Google Drive storage provider (scope: drive.file).

Nothing here touches the network or starts a login on import or construction.
OAuth starts only from DriveAuth.start(), which app.py calls when the user clicks
"Connect Google Drive". The flow is the standard web-server flow with PKCE; the
resulting token is written to token.json with mode 0600.
"""
from __future__ import annotations

import io
import json
import os
from pathlib import Path

from config_manager import validate_credentials
from storage_provider import BlobNotFound, StorageError, StorageProvider

SCOPES = ["https://www.googleapis.com/auth/drive.file"]
FOLDER_NAME = "SSE Engine Vault"
FOLDER_MIME = "application/vnd.google-apps.folder"


class DriveNotConnected(StorageError):
    pass


class DriveAuth:
    def __init__(self, credentials_path: str | os.PathLike, token_path: str | os.PathLike):
        self.credentials_path = Path(credentials_path)
        self.token_path = Path(token_path)

    def has_client(self) -> bool:
        return self.credentials_path.exists()

    def is_connected(self) -> bool:
        """True when token.json exists and holds a usable credential. No network calls."""
        if not self.token_path.exists():
            return False
        try:
            data = json.loads(self.token_path.read_text("utf-8"))
        except (OSError, json.JSONDecodeError):
            return False
        return bool(data.get("refresh_token") or data.get("token"))

    def _flow(self, redirect_uri: str, code_verifier: str | None = None):
        from google_auth_oauthlib.flow import Flow

        if not self.has_client():
            raise DriveNotConnected("credentials.json is missing; add it on the Setup page")
        # Same validation as the Setup page; also fills in Google's standard endpoints if absent.
        config = validate_credentials(self.credentials_path.read_bytes())
        return Flow.from_client_config(config, scopes=SCOPES, redirect_uri=redirect_uri, code_verifier=code_verifier)

    def start(self, redirect_uri: str) -> tuple[str, str, str]:
        """Return (authorization_url, state, code_verifier). Called only on an explicit user click."""
        flow = self._flow(redirect_uri)
        url, state = flow.authorization_url(access_type="offline", prompt="consent", include_granted_scopes="true")
        return url, state, flow.code_verifier

    def finish(self, redirect_uri: str, authorization_response: str, code_verifier: str) -> None:
        flow = self._flow(redirect_uri, code_verifier=code_verifier)
        flow.fetch_token(authorization_response=authorization_response)
        self._save(flow.credentials)

    def _save(self, creds) -> None:
        fd = os.open(self.token_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(creds.to_json())

    def disconnect(self) -> None:
        self.token_path.unlink(missing_ok=True)

    def credentials(self):
        """Load token.json, refreshing it if expired. Never starts an interactive login."""
        if not self.is_connected():
            raise DriveNotConnected("Google Drive is not connected")
        import google_auth_httplib2
        import httplib2
        from google.auth.exceptions import RefreshError
        from google.oauth2.credentials import Credentials

        creds = Credentials.from_authorized_user_file(str(self.token_path), SCOPES)
        if not creds.valid:
            if not creds.refresh_token:
                raise DriveNotConnected("Drive session expired; reconnect Google Drive")
            try:
                creds.refresh(google_auth_httplib2.Request(httplib2.Http()))
            except RefreshError as exc:
                raise DriveNotConnected("Drive session expired; reconnect Google Drive") from exc
            self._save(creds)
        return creds


class DriveStorage(StorageProvider):
    name = "drive"
    label = "Google Drive"

    def __init__(self, auth: DriveAuth, api_key: str | None = None):
        self.auth = auth
        self.api_key = api_key
        self._service = None
        self._folder_id: str | None = None

    def _drive(self):
        if self._service is None:
            from googleapiclient.discovery import build

            self._service = build(
                "drive", "v3", credentials=self.auth.credentials(), developerKey=self.api_key, cache_discovery=False
            )
        return self._service

    def _call(self, request):
        from googleapiclient.errors import HttpError

        try:
            return request.execute(num_retries=2)
        except HttpError as exc:
            status = getattr(exc.resp, "status", 0)
            if status == 404:
                raise BlobNotFound("blob not found on Google Drive") from None
            raise StorageError(f"Google Drive request failed (HTTP {status})") from None

    def _folder(self) -> str:
        if self._folder_id is None:
            q = f"name = '{FOLDER_NAME}' and mimeType = '{FOLDER_MIME}' and trashed = false"
            found = self._call(self._drive().files().list(q=q, spaces="drive", fields="files(id)", pageSize=1))
            if found.get("files"):
                self._folder_id = found["files"][0]["id"]
            else:
                body = {"name": FOLDER_NAME, "mimeType": FOLDER_MIME}
                self._folder_id = self._call(self._drive().files().create(body=body, fields="id"))["id"]
        return self._folder_id

    def upload_bytes(self, name: str, data: bytes) -> str:
        from googleapiclient.http import MediaIoBaseUpload

        media = MediaIoBaseUpload(io.BytesIO(data), mimetype="application/octet-stream", resumable=False)
        body = {"name": self.check_name(name), "parents": [self._folder()], "mimeType": "application/octet-stream"}
        return self._call(self._drive().files().create(body=body, media_body=media, fields="id"))["id"]

    def download_bytes(self, file_id: str) -> bytes:
        from googleapiclient.http import MediaIoBaseDownload

        self.check_name(file_id)
        buf = io.BytesIO()
        downloader = MediaIoBaseDownload(buf, self._drive().files().get_media(fileId=file_id))
        done = False
        while not done:
            _, done = self._next_chunk(downloader)
        return buf.getvalue()

    def _next_chunk(self, downloader):
        from googleapiclient.errors import HttpError

        try:
            return downloader.next_chunk(num_retries=2)
        except HttpError as exc:
            status = getattr(exc.resp, "status", 0)
            if status == 404:
                raise BlobNotFound("blob not found on Google Drive") from None
            raise StorageError(f"Google Drive download failed (HTTP {status})") from None

    def delete_file(self, file_id: str) -> None:
        try:
            self._call(self._drive().files().delete(fileId=self.check_name(file_id)))
        except BlobNotFound:
            pass
