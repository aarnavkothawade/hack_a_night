"""Recursive-descent parser for boolean keyword queries.

Grammar (operators are case-insensitive; adjacent terms mean AND):

    query    := or_expr EOF
    or_expr  := and_expr ( "OR" and_expr )*
    and_expr := not_expr ( ["AND"] not_expr )*
    not_expr := "NOT" not_expr | primary
    primary  := TERM | FIELD ":" VALUE | "(" or_expr ")"

Precedence: NOT > AND > OR. The parser is purely syntactic; terms are
normalized later by the index. Error messages never repeat query text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

MAX_QUERY_LEN = 512
MAX_TERMS = 32
MAX_DEPTH = 32

_OPERATORS = {"AND", "OR", "NOT"}
_TOKEN_RE = re.compile(r"\(|\)|[^\s()]+")


class QueryError(ValueError):
    """Invalid query. The message is safe to show to the user and to log."""


@dataclass(frozen=True)
class Term:
    word: str


@dataclass(frozen=True)
class FieldTerm:
    field: str
    value: str


@dataclass(frozen=True)
class Not:
    child: "Node"


@dataclass(frozen=True)
class And:
    children: tuple["Node", ...]


@dataclass(frozen=True)
class Or:
    children: tuple["Node", ...]


Node = Term | FieldTerm | Not | And | Or


def _lex(query: str) -> list[str]:
    return _TOKEN_RE.findall(query)


class _Parser:
    def __init__(self, tokens: list[str]):
        self.tokens = tokens
        self.pos = 0
        self.terms = 0
        self.depth = 0

    def peek(self) -> str | None:
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def peek_op(self) -> str | None:
        tok = self.peek()
        return tok.upper() if tok is not None and tok.upper() in _OPERATORS else None

    def take(self) -> str:
        tok = self.tokens[self.pos]
        self.pos += 1
        return tok

    def parse(self) -> Node:
        if not self.tokens:
            raise QueryError("query is empty")
        node = self.or_expr()
        if self.peek() is not None:
            raise QueryError(f"unexpected token at position {self.pos + 1}")
        return node

    def or_expr(self) -> Node:
        children = [self.and_expr()]
        while self.peek_op() == "OR":
            self.take()
            children.append(self.and_expr())
        return children[0] if len(children) == 1 else Or(tuple(children))

    def and_expr(self) -> Node:
        children = [self.not_expr()]
        while True:
            op = self.peek_op()
            if op == "AND":
                self.take()
            elif op == "OR" or self.peek() in (None, ")"):
                break
            children.append(self.not_expr())
        return children[0] if len(children) == 1 else And(tuple(children))

    def not_expr(self) -> Node:
        if self.peek_op() == "NOT":
            self.take()
            return Not(self._nested(self.not_expr))
        return self.primary()

    def _nested(self, fn):
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise QueryError("query is nested too deeply")
        try:
            return fn()
        finally:
            self.depth -= 1

    def primary(self) -> Node:
        tok = self.peek()
        if tok is None:
            raise QueryError("query ends unexpectedly; expected a term")
        if tok == ")":
            raise QueryError(f"unexpected ')' at position {self.pos + 1}")
        if tok.upper() in _OPERATORS:
            raise QueryError(f"operator {tok.upper()} at position {self.pos + 1} needs a term")
        self.take()
        if tok == "(":
            node = self._nested(self.or_expr)
            if self.peek() != ")":
                raise QueryError("missing closing ')'")
            self.take()
            return node
        self.terms += 1
        if self.terms > MAX_TERMS:
            raise QueryError(f"too many terms (max {MAX_TERMS})")
        if ":" in tok:
            field, _, value = tok.partition(":")
            if not field or not value:
                raise QueryError(f"field filter at position {self.pos} must look like field:value")
            return FieldTerm(field.lower(), value)
        return Term(tok)


def parse_query(query: str) -> Node:
    if len(query) > MAX_QUERY_LEN:
        raise QueryError(f"query is too long (max {MAX_QUERY_LEN} characters)")
    return _Parser(_lex(query)).parse()


def to_query_string(node: Node) -> str:
    """Render an AST back to a fully parenthesized query (used by tests)."""
    if isinstance(node, Term):
        return node.word
    if isinstance(node, FieldTerm):
        return f"{node.field}:{node.value}"
    if isinstance(node, Not):
        return f"NOT {to_query_string(node.child)}"
    op = " AND " if isinstance(node, And) else " OR "
    return "(" + op.join(to_query_string(c) for c in node.children) + ")"
