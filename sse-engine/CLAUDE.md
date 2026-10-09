# SSE Engine: notes for Claude Code

Verifiable Searchable Symmetric Encryption demo: a Flask portal that encrypts text and
PDF documents (AES-256-GCM), stores ciphertext locally or on Google Drive, and supports
keyword and boolean search over an encrypted HMAC-label index. See README.md for the
full design and leakage table.

## Commands

- Run the app (Windows): `.\run.bat` in PowerShell, or `run.bat` in cmd. Opens http://localhost:5000
- Run the app (macOS/Linux): `./run.sh`
- Tests: `.venv\Scripts\python -m pytest` (Windows) or `.venv/bin/python -m pytest`
- First-time setup without the launcher: `python -m venv .venv`, then install `requirements.txt`

Run the full test suite after every change and before reporting work as done.

## Layout

- `crypto_engine.py`: keys (HKDF), AES-GCM, trapdoors, labels, blind index
- `sse_index.py`: encrypted index, normalization, boolean evaluation
- `boolean_parser.py`: recursive-descent query parser
- `document_reader.py`: UTF-8 text and PDF (pypdf) input
- `vault.py`: service layer (stage, upload, search, decrypt, verify, server view)
- `app.py`: Flask routes, CSRF, CSP, error handling
- `storage_provider.py`, `local_storage.py`, `drive_client.py`: storage backends
- `audit_logger.py`, `config_manager.py`
- `templates/`, `static/`: UI (no external CDNs; CSP is `'self'` only)
- `tests/`: pytest suite; no Google login needed

## Rules for this project

- Never log, print or write plaintext, keywords, query text or secret values.
  `audit.log` takes only allow-listed operations, opaque IDs, label hashes and numbers.
- Never commit `master.key`, `.env`, `credentials.json`, `token.json`, `search_index.json`,
  `index_state.bin`, `documents.json`, `audit.log` or `local_store/` (all in .gitignore).
- Never start the Google OAuth login automatically; it runs only from the
  "Connect Google Drive" button.
- Ask the user before adding any dependency not already in `requirements.txt`.
- Keep the UI self-contained (system fonts, no CDN), and report errors in the UI, never silently.
- Losing `master.key` makes all stored data unrecoverable. Do not delete or regenerate it.
