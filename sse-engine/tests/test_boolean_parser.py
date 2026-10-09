import pytest

from boolean_parser import And, FieldTerm, Not, Or, QueryError, Term, parse_query, to_query_string


def test_single_term():
    assert parse_query("quokka") == Term("quokka")


def test_precedence_not_and_or():
    assert parse_query("a OR b AND NOT c") == Or((Term("a"), And((Term("b"), Not(Term("c"))))))


def test_parentheses_override_precedence():
    assert parse_query("(a OR b) AND c") == And((Or((Term("a"), Term("b"))), Term("c")))


def test_operators_case_insensitive_and_implicit_and():
    assert parse_query("a and b c or not d") == Or((And((Term("a"), Term("b"), Term("c"))), Not(Term("d"))))


def test_double_negation_and_nested_parens():
    assert parse_query("NOT NOT ((a))") == Not(Not(Term("a")))


def test_field_term():
    assert parse_query("Department:Finance AND x") == And((FieldTerm("department", "Finance"), Term("x")))


@pytest.mark.parametrize("bad", ["", "   ", "(a", "a)", "a AND", "OR a", "NOT", "()", "a AND OR b", ":x", "dept:"])
def test_invalid_queries_raise(bad):
    with pytest.raises(QueryError):
        parse_query(bad)


def test_error_messages_do_not_echo_terms():
    with pytest.raises(QueryError) as exc:
        parse_query("secretword )")
    assert "secretword" not in str(exc.value)


def test_limits():
    with pytest.raises(QueryError):
        parse_query("a " * 300)
    with pytest.raises(QueryError):
        parse_query(" ".join(f"t{i}" for i in range(40)))
    with pytest.raises(QueryError):
        parse_query("(" * 40 + "a" + ")" * 40)


def test_round_trip_rendering():
    node = parse_query("(a OR b) AND NOT (c OR d)")
    assert parse_query(to_query_string(node)) == node
