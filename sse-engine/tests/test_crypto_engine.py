import os
import stat

import pytest

import crypto_engine as ce


@pytest.fixture
def keys():
    return ce.derive_keys(ce.generate_master_key())


def test_master_key_created_once_with_private_mode(tmp_path):
    path = tmp_path / "master.key"
    k1 = ce.load_or_create_master_key(path)
    k2 = ce.load_or_create_master_key(path)
    assert k1 == k2 and len(k1) == 32
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_derived_keys_are_distinct_and_deterministic():
    master = ce.generate_master_key()
    a, b = ce.derive_keys(master), ce.derive_keys(master)
    assert a == b
    assert len({a.enc, a.idx, a.tok, a.blind}) == 4
    assert "redacted" in repr(a)


def test_round_trip(keys):
    blob = ce.encrypt(keys.enc, b"quarterly forecast", ce.doc_aad("doc1"))
    nonce, ct, tag = ce.split_blob(blob)
    assert len(nonce) == 12 and len(tag) == 16 and len(ct) == len(b"quarterly forecast")
    assert ce.decrypt(keys.enc, blob, ce.doc_aad("doc1")) == b"quarterly forecast"


def test_nonce_is_fresh_per_encryption(keys):
    a = ce.encrypt(keys.enc, b"same", b"id")
    b = ce.encrypt(keys.enc, b"same", b"id")
    assert a[:12] != b[:12] and a != b


@pytest.mark.parametrize("position", [0, 12, -1])  # nonce, ciphertext, tag
def test_tampered_blob_fails(keys, position):
    blob = bytearray(ce.encrypt(keys.enc, b"payload", b"doc1"))
    blob[position] ^= 0x01
    with pytest.raises(ce.IntegrityError):
        ce.decrypt(keys.enc, bytes(blob), b"doc1")


def test_truncated_blob_fails(keys):
    with pytest.raises(ce.IntegrityError):
        ce.decrypt(keys.enc, b"\x00" * 10, b"doc1")


def test_wrong_document_id_aad_fails(keys):
    blob = ce.encrypt(keys.enc, b"payload", ce.doc_aad("doc1"))
    with pytest.raises(ce.IntegrityError):
        ce.decrypt(keys.enc, blob, ce.doc_aad("doc2"))


def test_wrong_key_fails(keys):
    blob = ce.encrypt(keys.enc, b"payload", b"doc1")
    with pytest.raises(ce.IntegrityError):
        ce.decrypt(keys.idx, blob, b"doc1")


def test_same_keyword_same_trapdoor(keys):
    assert ce.trapdoor(keys.tok, "merger") == ce.trapdoor(keys.tok, "merger")


def test_different_keywords_different_trapdoors(keys):
    assert ce.trapdoor(keys.tok, "merger") != ce.trapdoor(keys.tok, "mergers")


def test_trapdoor_depends_on_key():
    k1 = ce.derive_keys(ce.generate_master_key())
    k2 = ce.derive_keys(ce.generate_master_key())
    assert ce.trapdoor(k1.tok, "merger") != ce.trapdoor(k2.tok, "merger")


def test_labels_differ_per_counter_and_postings_bind_to_label(keys):
    t = ce.trapdoor(keys.tok, "merger")
    l0, l1 = ce.index_label(keys.idx, t, 0), ce.index_label(keys.idx, t, 1)
    assert l0 != l1
    posting = ce.encrypt_posting(t, l0, "abc123")
    assert ce.decrypt_posting(t, l0, posting) == "abc123"
    with pytest.raises(ce.IntegrityError):  # moved to another label
        ce.decrypt_posting(t, l1, posting)
    with pytest.raises(ce.IntegrityError):  # decrypted under another keyword
        ce.decrypt_posting(ce.trapdoor(keys.tok, "other"), l0, posting)


def test_blind_index_is_field_separated(keys):
    a = ce.blind_index(keys.blind, "department", "finance")
    assert a == ce.blind_index(keys.blind, "department", "finance")
    assert a != ce.blind_index(keys.blind, "classification", "finance")
