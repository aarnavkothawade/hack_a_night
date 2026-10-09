# Verifiable Searchable Symmetric Encryption (SSE) Engine

A Flask portal that encrypts text documents before they reach third-party storage
(local folder by default, Google Drive optionally) and still supports keyword and
boolean search (`AND`, `OR`, `NOT`, parentheses). The storage provider and anyone
with access to it see only ciphertext, keyed-hash index labels, sizes and the
access pattern. They never see plaintext, keywords or keys.

## Project tree

```
sse-engine/
├── app.py               Flask routes, CSRF, CSP, error reporting, OAuth hand-off
├── vault.py             Service layer: staging, upload, search, verify, server view
├── crypto_engine.py     Keys, HKDF, AES-256-GCM, trapdoors, labels, blind index
├── sse_index.py         Encrypted inverted index, normalization, boolean evaluation
├── boolean_parser.py    Recursive-descent query parser
├── storage_provider.py  Abstract provider: upload_bytes / download_bytes / delete_file
├── local_storage.py     ./local_store/ provider (default)
├── drive_client.py      Google Drive provider (drive.file scope, explicit login only)
├── audit_logger.py      JSON-lines audit log with no free-text fields
├── config_manager.py    .env settings, credentials.json validation, secret masking
├── templates/           Jinja templates (dashboard, server view, setup, error)
├── static/              styles.css, core.js, dashboard.js, server-view.js, setup.js
├── samples/             Example documents for the demo
├── tests/               pytest suite (no Google login needed)
├── run.bat / run.sh     One-click launchers (venv, install, start, open browser)
├── requirements.txt
├── .env.example
└── .gitignore
```

Runtime files created next to `app.py` (all git-ignored): `master.key`,
`search_index.json`, `index_state.bin`, `documents.json`, `audit.log`,
`local_store/`, and optionally `.env`, `credentials.json`, `token.json`.

## Setup and run

**Quickest:** on Windows double-click `run.bat`; on macOS/Linux run `./run.sh`.
Either one creates the virtual environment, installs the requirements, starts the
portal and opens http://localhost:5000.

Manual steps:

```bash
cd sse-engine
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                      # http://localhost:5000
```

On first run the portal creates `master.key` (32 random bytes, mode 0600).
Upload a file from `samples/`, then search, for example: `merger OR budget`,
`finance AND NOT draft`, `department:finance`.

To keep runtime state elsewhere, set `SSE_HOME=/path/to/dir`.

## Tests

```bash
pytest
```

The suite (109 tests) covers:

- AES-GCM round trip, tampered blob, wrong document-ID AAD, wrong key
- trapdoor determinism and distinctness
- boolean search against a plaintext baseline on a generated 50-document corpus:
  fixed `AND`/`OR`/`NOT`/parentheses cases plus 300 random query trees
- detection of dropped and swapped index postings
- `audit.log` and `/server-view` (HTML and JSON) contain no corpus keyword
- index files, the manifest and blobs on disk contain no corpus keyword
- setup validation, secret masking, CSRF, security headers
- OAuth never starts on import or page load

## Cryptographic design

| Item | Construction |
| --- | --- |
| Master key | `master.key`, 32 bytes from `secrets`, never committed |
| Subkeys | HKDF-SHA256(master, info=`b"enc"`, `b"idx"`, `b"tok"`, `b"blind"`) |
| Documents | AES-256-GCM, random 12-byte nonce, AAD = document ID. Blob = `nonce ‖ ciphertext ‖ tag` |
| Metadata (filename, fields) | AES-256-GCM under K_enc, AAD = `"meta:" ‖ doc_id` |
| Trapdoor | `T = HMAC-SHA256(K_tok, normalized_word)` |
| Index label | `L_c = HMAC-SHA256(K_idx, T ‖ c)`, with c a 64-bit big-endian counter |
| Posting | `AES-GCM(K_w, doc_id, aad = L_c)`, where `K_w = HKDF(T, info=b"posting")` |
| Index file | `search_index.json`: `{hex label: hex posting}`, written with sorted keys |
| Counters | `index_state.bin`: per-keyword counts, AES-GCM encrypted. Used to fetch exactly the expected labels and to detect missing postings |
| Blind index | `HMAC-SHA256(K_blind, field ‖ 0x00 ‖ normalized_value)` for `department` and `classification`, exact match only |

**Normalization** is applied identically to documents and queries: Unicode NFKC,
then casefold. Apostrophes are removed (`don't` → `dont`). Every other
non-alphanumeric character, including `-` and `_`, splits words. A small stopword
list is dropped (`a an and are as at be but by for from had has have he her his i if in into is it its me my no not of on or our she so than that the their them then there these they this to us was we were will with you your`),
as are words longer than 64 characters. Blind-index values keep only letters and
digits, so `Human Resources`, `human-resources` and `HUMAN_RESOURCES` match.

**Query syntax:** `NOT` binds tighter than `AND`, which binds tighter than `OR`.
Adjacent terms mean `AND`. Operators are case-insensitive. Use `field:value` for
blind-index fields.

**What "verifiable" means here:**

- Every blob and posting is authenticated. A tampered, truncated or swapped blob
  fails its GCM tag. A posting moved to another label fails because the label is
  its AAD. The server cannot forge postings without `K_w`.
- Search results are checked for completeness: the portal knows how many postings
  each keyword should have, so a dropped or altered posting marks the result
  `Incomplete` instead of silently shrinking it.
- `GET /verify/<doc_id>` re-downloads the blob and checks: blob present, size, GCM
  tag, metadata tag, every keyword's posting in the index, and blind-index tokens.

## Routes

| Route | Purpose |
| --- | --- |
| `GET /` | Dashboard: file picker, encrypted preview (first 64 hex of ciphertext, blob size, nonce), save/send/connect button, search, vault table |
| `POST /preview` | Encrypt and stage a file in memory and return the preview. Plaintext is never returned |
| `POST /upload` | Commit a staged preview (`{"staging_id"}`) or encrypt a file in one shot. Returns `doc_id` |
| `GET /search?q=…[&decrypt=1\|<id,…>]` | Boolean search returns IDs. Decrypts only when `decrypt` is given |
| `GET /verify/<doc_id>` | Integrity and index checks, returns `pass` or `fail` |
| `GET /server-view[?format=json]` | Blob IDs, sizes, first 16 hex, blind tokens, index labels, audit log. No plaintext |
| `GET/POST /setup` | Storage choice, credentials.json upload or paste, optional API key. Everything is validated before saving |
| `POST /drive/connect`, `GET /oauth2callback`, `POST /drive/disconnect` | Google sign-in, only on an explicit click |

## Leakage

| The server **can** learn | The server **cannot** learn |
| --- | --- |
| Access pattern: which document IDs match a query and which blobs are downloaded | Document contents (AES-256-GCM) |
| Search pattern: whether two queries share a term (equal words give equal labels) | Filenames and field values (encrypted metadata) |
| Result counts: postings per term and the number of terms in a query | Plaintext keywords or query text (only HMAC outputs leave the portal) |
| Blob sizes (approximate document length), upload times | Boolean structure (AND/OR/NOT are evaluated in the portal) |
| Number of unique keywords per uploaded document (labels inserted together) | `master.key`, `K_enc`, `K_idx`, `K_tok`, `K_blind` |
| Blind index: which documents share the same `department` or `classification` value, even before any search | |

Logging rules: `audit.log` holds only timestamps, operation names, random blob IDs,
SHA-256 fingerprints of labels, counts and pass/fail flags. The logger refuses
free text. The web server's request log omits query strings. Unexpected
exceptions are logged by type only. Decrypted plaintext is sent only to the
browser that asked for it, with `Cache-Control: no-store`.

## Known limitations

- **No key recovery.** Lose `master.key` and every document and index entry is
  unrecoverable. Back it up offline. Losing `index_state.bin` makes the index
  unreadable for search.
- **Keys are held by the portal.** The Flask process holds the master key and sees
  plaintext while encrypting, indexing and decrypting. Anyone who controls the
  portal host controls the data. This protects against the storage provider and
  its insiders, not against the portal operator.
- **Substring and prefix search are not in core.** Only whole normalized tokens
  match. Prefix or n-gram search is a stretch goal and is not implemented,
  because it would leak much more (prefix overlap between queries).
- **No forward or backward privacy.** Uploads reveal how many labels each new
  document adds, and a repeated search reveals new matches. There is no document
  deletion route (the provider supports `delete_file`, used only to roll back
  failed uploads).
- **Single-user demo.** No user accounts or authentication beyond CSRF
  protection. Run it on localhost only. The dev server binds to 127.0.0.1.
- **Index location.** `search_index.json` lives next to the portal for the demo.
  It contains only labels and ciphertexts, so it could be hosted by the server.
  Search would then be one round trip per term.
- **Text only.** UTF-8 documents up to 5 MB.

## Switching to Google Drive

Nothing in this project starts a Google login automatically. Sign-in happens only
when you click **Connect Google Drive**.

1. In Google Cloud Console, enable the **Google Drive API**.
2. Create an **OAuth client ID** of type **Web application**. Add the authorized
   redirect URI shown on `/setup`, normally `http://localhost:5000/oauth2callback`.
3. Download the JSON. Either save it as `credentials.json` in the project root or
   upload or paste it on `/setup`. It must contain `client_id`, `client_secret`
   and `redirect_uris`.
4. On `/setup`, select **Google Drive** and save. Optionally add a Google API key;
   it is only attached to Drive calls for quota attribution.
5. Click **Connect Google Drive** and approve the `drive.file` scope. The token is
   stored in `token.json` (mode 0600). New uploads go to a Drive folder named
   "SSE Engine Vault". Documents already stored locally remain readable.

Plain `http` is allowed for the OAuth callback only when the redirect host is
`localhost` or `127.0.0.1`. **Disconnect** on `/setup` deletes `token.json`.

> Pasting secrets into a web page is for local demos only. In production, load
> OAuth clients and API keys from a secrets manager or environment.
