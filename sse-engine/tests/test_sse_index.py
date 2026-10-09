import json
import random

import pytest

import crypto_engine as ce
from boolean_parser import And, Not, Or, QueryError, Term, to_query_string
from sse_index import SSEIndex, normalize_field_value, normalize_text, tokenize
from tests.corpus import ABSENT, VOCAB, make_corpus


@pytest.fixture
def keys():
    return ce.derive_keys(ce.generate_master_key())


@pytest.fixture
def corpus_index(tmp_path, keys):
    corpus = make_corpus(50)
    docs = {f"{i:032x}": (text, words) for i, (text, words) in enumerate(corpus)}
    index = SSEIndex(keys, tmp_path / "search_index.json", tmp_path / "index_state.bin")
    index.build((doc_id, text) for doc_id, (text, _) in docs.items())
    baseline = {doc_id: words for doc_id, (_, words) in docs.items()}
    return index, baseline


def baseline_eval(node, baseline):
    universe = set(baseline)
    if isinstance(node, Term):
        return {d for d, words in baseline.items() if node.word in words}
    if isinstance(node, Not):
        return universe - baseline_eval(node.child, baseline)
    sets = [baseline_eval(c, baseline) for c in node.children]
    return set.intersection(*sets) if isinstance(node, And) else set.union(*sets)


def random_query(rng, depth=0):
    if depth >= 3 or rng.random() < 0.3:
        return Term(rng.choice(VOCAB + [ABSENT]))
    kind = rng.random()
    if kind < 0.2:
        return Not(random_query(rng, depth + 1))
    children = tuple(random_query(rng, depth + 1) for _ in range(rng.randint(2, 3)))
    return And(children) if kind < 0.6 else Or(children)


# --- normalization ------------------------------------------------------------

def test_normalization_rules():
    assert normalize_text("The QUOKKA, don't! e-mail_x  Ünïcode") == ["quokka", "dont", "e", "mail", "x", "ünïcode"]
    assert tokenize("and or not the a") == set()
    assert normalize_field_value("Human Resources") == normalize_field_value("human-resources") == "humanresources"


# --- corpus vs plaintext baseline ------------------------------------------------

@pytest.mark.parametrize(
    "query,expected",
    [
        ("quokka", lambda w: "quokka" in w),
        ("QUOKKA.", lambda w: "quokka" in w),
        ("quokka AND walrus", lambda w: "quokka" in w and "walrus" in w),
        ("quokka walrus", lambda w: "quokka" in w and "walrus" in w),
        ("quokka OR walrus", lambda w: "quokka" in w or "walrus" in w),
        ("NOT quokka", lambda w: "quokka" not in w),
        ("quokka AND NOT walrus", lambda w: "quokka" in w and "walrus" not in w),
        ("(quokka OR walrus) AND nebula", lambda w: ("quokka" in w or "walrus" in w) and "nebula" in w),
        ("quokka OR walrus AND nebula", lambda w: "quokka" in w or ("walrus" in w and "nebula" in w)),
        ("NOT (tundra OR basalt) AND (lynx OR NOT krill)",
         lambda w: not ("tundra" in w or "basalt" in w) and ("lynx" in w or "krill" not in w)),
        (ABSENT, lambda w: False),
        (f"NOT {ABSENT}", lambda w: True),
    ],
)
def test_boolean_search_matches_baseline(corpus_index, query, expected):
    index, baseline = corpus_index
    result = index.search(query, set(baseline))
    assert result.doc_ids == {d for d, words in baseline.items() if expected(words)}
    assert result.verified


def test_every_vocab_word_hits_some_but_not_all_docs(corpus_index):
    index, baseline = corpus_index
    for word in VOCAB:
        hits = index.search(word, set(baseline)).doc_ids
        assert 0 < len(hits) < len(baseline), word


def test_random_queries_match_baseline(corpus_index):
    index, baseline = corpus_index
    rng = random.Random(7)
    for _ in range(300):
        node = random_query(rng)
        expected = baseline_eval(node, baseline)
        assert index.search(to_query_string(node), set(baseline)).doc_ids == expected
        assert index.search(node, set(baseline)).doc_ids == expected


def test_stopword_only_term_is_rejected(corpus_index):
    index, baseline = corpus_index
    with pytest.raises(QueryError):
        index.search("quokka AND the", set(baseline))


# --- persistence, leakage shape, and verification ---------------------------------

def test_index_file_holds_only_labels_and_ciphertexts(tmp_path, corpus_index):
    index, baseline = corpus_index
    raw = (tmp_path / "search_index.json").read_text()
    data = json.loads(raw)
    assert len(data) == sum(len(w) for w in baseline.values())
    assert all(len(k) == 64 and len(v) == 2 * (12 + 32 + 16) for k, v in data.items())
    assert not any(word in raw for word in VOCAB)
    assert not any(word.encode() in (tmp_path / "index_state.bin").read_bytes() for word in VOCAB)


def test_index_reloads_from_disk(tmp_path, keys, corpus_index):
    index, baseline = corpus_index
    again = SSEIndex(keys, tmp_path / "search_index.json", tmp_path / "index_state.bin")
    assert again.search("quokka", set(baseline)).doc_ids == index.search("quokka", set(baseline)).doc_ids


def test_dropped_and_tampered_postings_are_detected(tmp_path, keys, corpus_index):
    index, baseline = corpus_index
    labels = index.search_token("quokka").labels
    path = tmp_path / "search_index.json"
    data = json.loads(path.read_text())
    del data[labels[0].hex()]
    data[labels[1].hex()] = data[labels[2].hex()]  # swap in another label's posting
    path.write_text(json.dumps(data))
    tampered = SSEIndex(keys, path, tmp_path / "index_state.bin")
    result = tampered.search("quokka", set(baseline))
    assert not result.verified
    assert result.problems == {"missing_postings": 1, "tampered_postings": 1}


def test_verify_document_and_rollback(tmp_path, keys):
    index = SSEIndex(keys, tmp_path / "i.json", tmp_path / "s.bin")
    index.add_document("d1", {"quokka", "walrus"})
    update = index.add_document("d2", {"quokka", "lynx"})
    assert index.verify_document("d2", {"quokka", "lynx"})["missing"] == 0
    index.rollback(update)
    assert index.search("quokka", {"d1", "d2"}).doc_ids == {"d1"}
    assert index.search("quokka", {"d1", "d2"}).verified
    assert index.verify_document("d2", {"quokka", "lynx"})["missing"] == 2
    assert len(index) == 2


def test_counter_self_heals_when_state_lags(tmp_path, keys):
    index = SSEIndex(keys, tmp_path / "i.json", tmp_path / "s.bin")
    index.add_document("d1", {"quokka"})
    stale_state = (tmp_path / "s.bin").read_bytes()
    index.add_document("d2", {"quokka"})
    (tmp_path / "s.bin").write_bytes(stale_state)  # simulate a crash between the two writes
    healed = SSEIndex(keys, tmp_path / "i.json", tmp_path / "s.bin")
    healed.add_document("d3", {"quokka"})
    assert len(healed) == 3
    assert healed.search("quokka", {"d1", "d2", "d3"}).doc_ids >= {"d1", "d3"}
