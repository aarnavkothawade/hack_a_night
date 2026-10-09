import json
import os
import stat
import sys

import pytest

from config_manager import ConfigError, ConfigManager, mask_secret, validate_credentials
from drive_client import DriveAuth, DriveNotConnected, DriveStorage

GOOD = {
    "web": {
        "client_id": "1234-abcdefgh.apps.googleusercontent.com",
        "client_secret": "GOCSPX-supersecretvalue9z1Q",
        "redirect_uris": ["http://localhost:5000/oauth2callback"],
    }
}


def test_mask_shows_only_last_four():
    assert mask_secret("GOCSPX-supersecretvalue9z1Q").endswith("9z1Q")
    assert "supersecret" not in mask_secret("GOCSPX-supersecretvalue9z1Q")
    assert mask_secret("short") == "•" * 4
    assert mask_secret(None) == ""


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "not json",
        "[]",
        json.dumps({"other": {}}),
        json.dumps({"web": {"client_id": "x", "redirect_uris": ["http://x"]}}),
        json.dumps({"web": {"client_id": "x", "client_secret": "y"}}),
        json.dumps({"web": {"client_id": "x", "client_secret": "y", "redirect_uris": []}}),
        json.dumps({"web": {"client_id": "x", "client_secret": "y", "redirect_uris": ["javascript:x"]}}),
        json.dumps({"web": GOOD["web"], "installed": GOOD["web"]}),
    ],
)
def test_invalid_credentials_rejected(raw):
    with pytest.raises(ConfigError) as exc:
        validate_credentials(raw)
    assert "supersecret" not in str(exc.value)


def test_save_credentials_is_private_and_summary_masked(tmp_path):
    cfg = ConfigManager(tmp_path)
    summary = cfg.save_credentials(json.dumps(GOOD))
    assert stat.S_IMODE(os.stat(cfg.credentials_path).st_mode) == 0o600
    assert summary["valid"] and summary["type"] == "web"
    assert "supersecret" not in json.dumps(summary) and summary["client_secret"].endswith("9z1Q")


def test_env_settings_round_trip(tmp_path):
    cfg = ConfigManager(tmp_path)
    assert cfg.storage == "local" and cfg.api_key is None
    cfg.set_storage("drive")
    cfg.set_api_key("AIzaSyExampleKey1234")
    assert cfg.storage == "drive" and cfg.api_key == "AIzaSyExampleKey1234"
    assert cfg.summary()["api_key"].endswith("1234") and "Example" not in cfg.summary()["api_key"]
    assert stat.S_IMODE(os.stat(cfg.env_path).st_mode) == 0o600
    cfg.clear_api_key()
    assert cfg.api_key is None
    with pytest.raises(ConfigError):
        cfg.set_storage("dropbox")
    with pytest.raises(ConfigError):
        cfg.set_api_key("has space")


def test_drive_is_not_connected_and_never_logs_in_without_token(tmp_path):
    auth = DriveAuth(tmp_path / "credentials.json", tmp_path / "token.json")
    assert not auth.is_connected()
    storage = DriveStorage(auth)  # construction must not touch the network
    with pytest.raises(DriveNotConnected):
        storage.upload_bytes("abc.bin", b"x")
    with pytest.raises(DriveNotConnected):
        auth.start("http://localhost:5000/oauth2callback")  # no credentials.json yet


def test_drive_start_builds_consent_url_without_network(tmp_path):
    ConfigManager(tmp_path).save_credentials(json.dumps(GOOD))
    auth = DriveAuth(tmp_path / "credentials.json", tmp_path / "token.json")
    url, state, verifier = auth.start("http://localhost:5000/oauth2callback")
    assert url.startswith("https://accounts.google.com/") and "drive.file" in url
    assert "code_challenge=" in url and state and len(verifier) >= 43
    assert not (tmp_path / "token.json").exists()
