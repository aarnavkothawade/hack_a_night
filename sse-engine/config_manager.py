"""Settings stored in .env plus validation of Google's credentials.json.

Secrets are never returned in full: summaries show at most the last 4 characters.
"""
from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from dotenv import dotenv_values, set_key, unset_key

STORAGE_CHOICES = ("local", "drive")
MAX_CREDENTIALS_BYTES = 64 * 1024
MAX_API_KEY_LEN = 256
# Standard Google endpoints, filled in when a pasted client omits them.
DEFAULT_ENDPOINTS = {
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
}


class ConfigError(ValueError):
    """Invalid configuration. Messages never include the submitted values."""


def mask_secret(value: str | None) -> str:
    if not value:
        return ""
    if len(value) < 8:  # too short: even 4 characters would reveal half of it
        return "•" * 4
    return "•" * 8 + value[-4:]


def validate_credentials(raw: str | bytes) -> dict:
    """Parse and validate an OAuth client file. Returns the parsed JSON."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if not raw.strip():
        raise ConfigError("credentials.json is empty")
    if len(raw) > MAX_CREDENTIALS_BYTES:
        raise ConfigError("credentials.json is too large (max 64 KB)")
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ConfigError("credentials.json is not valid JSON") from None
    if not isinstance(data, dict):
        raise ConfigError("credentials.json must be a JSON object")
    kinds = [k for k in ("web", "installed") if k in data]
    if len(kinds) != 1 or not isinstance(data[kinds[0]], dict):
        raise ConfigError('credentials.json must contain exactly one "web" or "installed" client object')
    client = data[kinds[0]]
    for key in ("client_id", "client_secret"):
        if not isinstance(client.get(key), str) or not client[key].strip():
            raise ConfigError(f"credentials.json is missing {key}")
    uris = client.get("redirect_uris")
    if not isinstance(uris, list) or not uris:
        raise ConfigError("credentials.json is missing redirect_uris")
    if not all(isinstance(u, str) and u.startswith(("http://", "https://")) for u in uris):
        raise ConfigError("every redirect URI must be an http(s) URL")
    for key, default in DEFAULT_ENDPOINTS.items():
        if not isinstance(client.get(key), str) or not client[key].startswith("https://"):
            client[key] = default
    return data


def validate_api_key(value: str) -> str:
    value = value.strip()
    if not value or len(value) > MAX_API_KEY_LEN or not value.isprintable() or not value.isascii() \
            or any(c.isspace() or c in "\"'\\" for c in value):
        raise ConfigError("API key must be a single token of printable ASCII (max 256 characters)")
    return value


def _write_private(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        os.chmod(tmp, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class ConfigManager:
    def __init__(self, base_dir: str | os.PathLike):
        self.base_dir = Path(base_dir)
        self.env_path = self.base_dir / ".env"
        self.credentials_path = self.base_dir / "credentials.json"

    def _env(self) -> dict[str, str | None]:
        return dotenv_values(self.env_path) if self.env_path.exists() else {}

    def _set(self, key: str, value: str) -> None:
        if not self.env_path.exists():
            _write_private(self.env_path, b"")
        set_key(self.env_path, key, value, quote_mode="always")

    # --- storage choice ---------------------------------------------------------

    @property
    def storage(self) -> str:
        choice = (self._env().get("SSE_STORAGE") or "local").strip().lower()
        return choice if choice in STORAGE_CHOICES else "local"

    def set_storage(self, choice: str) -> None:
        if choice not in STORAGE_CHOICES:
            raise ConfigError("storage must be 'local' or 'drive'")
        self._set("SSE_STORAGE", choice)

    # --- optional API key -------------------------------------------------------

    @property
    def api_key(self) -> str | None:
        return self._env().get("SSE_API_KEY") or None

    def set_api_key(self, value: str) -> None:
        self._set("SSE_API_KEY", validate_api_key(value))

    def clear_api_key(self) -> None:
        if self.env_path.exists() and "SSE_API_KEY" in self._env():
            unset_key(self.env_path, "SSE_API_KEY")

    @property
    def flask_secret(self) -> str | None:
        return self._env().get("FLASK_SECRET_KEY") or None

    # --- credentials.json ---------------------------------------------------------

    def save_credentials(self, raw: str | bytes) -> dict:
        data = validate_credentials(raw)
        _write_private(self.credentials_path, json.dumps(data, indent=2).encode())
        return self.credentials_summary()

    def credentials_summary(self) -> dict | None:
        if not self.credentials_path.exists():
            return None
        try:
            data = validate_credentials(self.credentials_path.read_bytes())
        except ConfigError as exc:
            return {"valid": False, "error": str(exc)}
        kind = "web" if "web" in data else "installed"
        client = data[kind]
        return {
            "valid": True,
            "type": kind,
            "client_id": mask_secret(client["client_id"]),
            "client_secret": mask_secret(client["client_secret"]),
            "redirect_uri_count": len(client["redirect_uris"]),
        }

    def summary(self) -> dict:
        return {
            "storage": self.storage,
            "api_key": mask_secret(self.api_key),
            "credentials": self.credentials_summary(),
        }
