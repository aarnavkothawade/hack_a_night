"""Deterministic synthetic corpus with a plaintext baseline.

Vocabulary words are deliberately unusual so that a leak check can grep for them in
logs and HTML without false positives from ordinary page text or hex strings.
"""
import random

VOCAB = (
    "quokka zephyr obsidian fjord sphinx kumquat juniper walrus yttrium xylophone "
    "nebula quasar tundra vortex basalt marmot glacier lagoon pelican saffron "
    "tamarind mangrove wombat narwhal sequoia gondola pumice lynx ocelot platypus "
    "rhubarb sorrel tapir vellum wisteria yarrow zinnia krill jackal mongoose"
).split()
ABSENT = "dodoquill"  # never placed in any document
FILLER = "the a of and to is in it with for on this that".split()
PUNCT = ["", "", "", ",", ".", "!", "?", ";", ":"]


def _decorate(rng, word):
    style = rng.random()
    if style < 0.2:
        word = word.upper()
    elif style < 0.4:
        word = word.capitalize()
    return word + rng.choice(PUNCT)


def make_corpus(n_docs=50, seed=1337):
    """Return a list of (doc_text, set_of_vocab_words) tuples."""
    rng = random.Random(seed)
    docs = []
    for _ in range(n_docs):
        words = set(rng.sample(VOCAB, rng.randint(3, 10)))
        parts = []
        ordered = list(words)
        rng.shuffle(ordered)
        i = 0
        while i < len(ordered):
            if i + 1 < len(ordered) and rng.random() < 0.15:  # hyphenated pair splits into two words
                parts.append(f"{ordered[i]}-{ordered[i + 1]}")
                i += 2
            else:
                parts.append(_decorate(rng, ordered[i]))
                i += 1
            parts.extend(rng.choice(FILLER) for _ in range(rng.randint(0, 3)))
        docs.append((" ".join(parts), words))
    return docs
