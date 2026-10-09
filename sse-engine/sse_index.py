"""Encrypted inverted index with boolean search.

On disk (server-visible)
    search_index.json   {hex label: hex posting}, written with sorted keys so the
                        file order reveals nothing about insertion order.
Portal-only state
    index_state.bin     per-keyword posting counters, AES-GCM encrypted under K_enc.
                        Knowing each counter lets search fetch exactly the expected
                        labels and detect dropped or tampered postings (completeness).

Normalization (applied identically to documents and query terms):
    1. Unicode NFKC, then casefold (aggressive lowercase).
    2. Apostrophes are removed inside words ("don't" -> "dont").
    3. Every other non-alphanumeric character (punctuation, "_", "-") splits words.
    4. Words in STOPWORDS and words longer than 64 characters are dropped.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

import crypto_engine as ce
from boolean_parser import And, FieldTerm, Node, Not, Or, QueryError, Term, parse_query

STOPWORDS = frozenset(
    """a an and are as at be but by for from had has have he her his i if in into is it
    its me my no not of on or our she so than that the their them then there these they
    this to us was we were will with you your""".split()
)
MAX_WORD_LEN = 64
STRUCTURED_FIELDS = ("department", "classification")

_APOSTROPHES = re.compile(r"['’`]")
_SPLIT = re.compile(r"[\W_]+")
_STATE_AAD = b"sse-index-state:v1"


def normalize_text(text: str) -> list[str]:
    """Return normalized tokens in document order (duplicates kept)."""
    text = _APOSTROPHES.sub("", unicodedata.normalize("NFKC", text).casefold())
    return [w for w in _SPLIT.split(text) if w and w not in STOPWORDS and len(w) <= MAX_WORD_LEN]


def tokenize(text: str) -> set[str]:
    return set(normalize_text(text))


def normalize_field_value(value: str) -> str:
    """Exact-match normalization for blind-indexed fields: casefold, keep only letters/digits."""
    return "".join(ch for ch in unicodedata.normalize("NFKC", value).casefold() if ch.isalnum())


@dataclass
class TermResult:
    doc_ids: set[str]
    labels: list[bytes]
    expected: int
    missing: int = 0
    tampered: int = 0

    @property
    def complete(self) -> bool:
        return self.missing == 0 and self.tampered == 0


@dataclass
class SearchResult:
    doc_ids: set[str]
    terms: list[TermResult] = field(default_factory=list)
    field_lookups: int = 0

    @property
    def labels(self) -> list[bytes]:
        return [label for t in self.terms for label in t.labels]

    @property
    def verified(self) -> bool:
        return all(t.complete for t in self.terms)

    @property
    def problems(self) -> dict[str, int]:
        return {
            "missing_postings": sum(t.missing for t in self.terms),
            "tampered_postings": sum(t.tampered for t in self.terms),
        }


@dataclass
class IndexUpdate:
    labels: list[bytes] = field(default_factory=list)
    previous_counters: dict[str, int | None] = field(default_factory=dict)


FieldLookup = Callable[[str, str], set[str]]


def _atomic_write(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


class SSEIndex:
    def __init__(self, keys: ce.DerivedKeys, index_path: str | os.PathLike, state_path: str | os.PathLike):
        self._keys = keys
        self.index_path = Path(index_path)
        self.state_path = Path(state_path)
        self._lock = threading.RLock()
        self._entries: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._load()

    # --- persistence ---------------------------------------------------------

    def _load(self) -> None:
        if self.index_path.exists():
            self._entries = json.loads(self.index_path.read_text("utf-8"))
        if self.state_path.exists():
            raw = ce.decrypt(self._keys.enc, self.state_path.read_bytes(), _STATE_AAD)
            self._counters = json.loads(raw)
        elif self._entries:
            raise RuntimeError("index_state.bin is missing for a non-empty index; restore it from backup")

    def save(self) -> None:
        with self._lock:
            # Index first: if the state write then fails, counters lag behind and
            # add_document() skips forward past labels that already exist.
            _atomic_write(self.index_path, json.dumps(self._entries, sort_keys=True, indent=0).encode())
            state = json.dumps(self._counters, sort_keys=True).encode()
            _atomic_write(self.state_path, ce.encrypt(self._keys.enc, state, _STATE_AAD))

    # --- updates ------------------------------------------------------------

    def add_document(self, doc_id: str, tokens: Iterable[str], *, save: bool = True) -> "IndexUpdate":
        """Insert one posting per unique token. Returns an update that can be rolled back."""
        update = IndexUpdate()
        with self._lock:
            for word in sorted(set(tokens)):
                t = ce.trapdoor(self._keys.tok, word)
                key = t.hex()
                update.previous_counters.setdefault(key, self._counters.get(key))
                counter = self._counters.get(key, 0)
                label = ce.index_label(self._keys.idx, t, counter)
                while label.hex() in self._entries:  # self-heal a lagging counter
                    counter += 1
                    label = ce.index_label(self._keys.idx, t, counter)
                self._entries[label.hex()] = ce.encrypt_posting(t, label, doc_id).hex()
                self._counters[key] = counter + 1
                update.labels.append(label)
            if save:
                try:
                    self.save()
                except BaseException:
                    self.rollback(update, save=False)
                    raise
        return update

    def build(self, documents: Iterable[tuple[str, str]]) -> int:
        """Bulk-index (doc_id, plaintext) pairs. Returns the number of postings added."""
        count = sum(len(self.add_document(d, tokenize(text), save=False).labels) for d, text in documents)
        self.save()
        return count

    def rollback(self, update: "IndexUpdate", *, save: bool = True) -> None:
        """Undo an add_document() whose surrounding upload failed."""
        with self._lock:
            for label in update.labels:
                self._entries.pop(label.hex(), None)
            for key, previous in update.previous_counters.items():
                if previous is None:
                    self._counters.pop(key, None)
                else:
                    self._counters[key] = previous
            if save:
                self.save()

    # --- search -------------------------------------------------------------

    def search_token(self, word: str) -> TermResult:
        t = ce.trapdoor(self._keys.tok, word)
        with self._lock:
            expected = self._counters.get(t.hex(), 0)
            result = TermResult(doc_ids=set(), labels=[], expected=expected)
            for counter in range(expected):
                label = ce.index_label(self._keys.idx, t, counter)
                result.labels.append(label)
                posting = self._entries.get(label.hex())
                if posting is None:
                    result.missing += 1
                    continue
                try:
                    result.doc_ids.add(ce.decrypt_posting(t, label, bytes.fromhex(posting)))
                except (ce.IntegrityError, ValueError):
                    result.tampered += 1
        return result

    def search(self, query: str | Node, universe: set[str], field_lookup: FieldLookup | None = None) -> SearchResult:
        node = parse_query(query) if isinstance(query, str) else query
        out = SearchResult(doc_ids=set())
        cache: dict[str, TermResult] = {}

        def word_docs(word: str) -> set[str]:
            if word not in cache:
                cache[word] = self.search_token(word)
                out.terms.append(cache[word])
            return cache[word].doc_ids

        def ev(n: Node) -> set[str]:
            if isinstance(n, Term):
                words = normalize_text(n.word)
                if not words:
                    raise QueryError("a term contains only stopwords or punctuation and is not indexed")
                return set.intersection(*(word_docs(w) for w in words))
            if isinstance(n, FieldTerm):
                if n.field not in STRUCTURED_FIELDS:
                    raise QueryError("unknown field; use " + " or ".join(STRUCTURED_FIELDS))
                if field_lookup is None:
                    raise QueryError("field filters are not available here")
                out.field_lookups += 1
                return field_lookup(n.field, normalize_field_value(n.value))
            if isinstance(n, Not):
                return universe - ev(n.child)
            if isinstance(n, And):
                return set.intersection(*(ev(c) for c in n.children))
            if isinstance(n, Or):
                return set.union(*(ev(c) for c in n.children))
            raise QueryError("unsupported query node")  # pragma: no cover

        out.doc_ids = ev(node) & universe
        return out

    # --- verification ---------------------------------------------------------

    def verify_document(self, doc_id: str, tokens: Iterable[str]) -> dict[str, int]:
        """Check every keyword of a document resolves to a valid posting for it."""
        words = set(tokens)
        found = tampered = 0
        for word in words:
            result = self.search_token(word)
            tampered += result.tampered
            found += doc_id in result.doc_ids
        return {"keywords": len(words), "found": found, "missing": len(words) - found, "tampered": tampered}

    # --- server-visible views ---------------------------------------------------

    def labels(self) -> list[str]:
        with self._lock:
            return sorted(self._entries)

    def __len__(self) -> int:
        return len(self._entries)
