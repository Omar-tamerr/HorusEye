"""Every module must load on every supported Python (3.8+).

Some modules are only imported deep inside a CLI run, so syntax newer than 3.8
(for example a backslash inside an f-string expression, which only Python 3.12
accepts) could hide there until a user hits it. CI runs this on 3.8, 3.11 and
3.12, so each of those versions compiles and imports everything.
"""
import importlib
import io
import pkgutil
import py_compile
import tokenize
from pathlib import Path

import pytest

import horuseye

ROOT = Path(__file__).resolve().parent.parent
SOURCES = sorted([*ROOT.joinpath("horuseye").rglob("*.py"), ROOT / "horuseye.py",
                  *ROOT.joinpath("scripts").glob("*.py")])


def _pep701_only(src):
    """f-string constructs only Python 3.12+ parses: a backslash or comment
    inside an expression, a reused enclosing quote, or a line break inside a
    single-quoted f-string. Yields (line, reason)."""
    stack = []                                   # [quote, is_triple, brace_depth]
    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.FSTRING_START:
            q = tok.string.lstrip("fFrRbBuU")
            if stack and stack[-1][2] and q[0] == stack[-1][0][0] and not stack[-1][1]:
                yield tok.start[0], "nested f-string reuses the enclosing quote"
            stack.append([q, len(q) == 3, 0])
        elif not stack:
            continue
        elif tok.type == tokenize.FSTRING_END:
            stack.pop()
        elif tok.type == tokenize.OP and tok.string in "{}":
            stack[-1][2] = max(0, stack[-1][2] + (1 if tok.string == "{" else -1))
        elif stack[-1][2]:
            quote, triple = stack[-1][0], stack[-1][1]
            if tok.type == tokenize.STRING:
                body = tok.string.lstrip("rRbBuU")
                if "\\" in tok.string:
                    yield tok.start[0], "backslash inside an f-string expression"
                if (body[:3] == quote) if triple else (body[:1] == quote[0]):
                    yield tok.start[0], "string reuses the f-string's quote"
            elif tok.type == tokenize.COMMENT:
                yield tok.start[0], "comment inside an f-string expression"
            elif tok.type in (tokenize.NL, tokenize.NEWLINE) and not triple:
                yield tok.start[0], "line break inside a single-quoted f-string"


@pytest.mark.skipif(not hasattr(tokenize, "FSTRING_START"),
                    reason="needs the Python 3.12+ tokenizer; older CI jobs compile instead")
def test_no_fstrings_that_need_python_312():
    found = [f"{p.relative_to(ROOT)}:{line}: {why}"
             for p in SOURCES for line, why in _pep701_only(p.read_text(encoding="utf-8"))]
    assert not found, "\n".join(found)


def test_every_source_file_compiles(tmp_path):
    failures = []
    for i, path in enumerate(SOURCES):
        try:
            py_compile.compile(str(path), cfile=str(tmp_path / f"{i}.pyc"), doraise=True)
        except py_compile.PyCompileError as e:
            failures.append(f"{path.relative_to(ROOT)}: {e.msg.strip().splitlines()[-1]}")
    assert not failures, "\n".join(failures)


def test_every_module_imports():
    failures = []
    for mod in pkgutil.walk_packages(horuseye.__path__, "horuseye."):
        try:
            importlib.import_module(mod.name)
        except Exception as e:  # report every broken module, not just the first
            failures.append(f"{mod.name}: {e!r}")
    assert not failures, "\n".join(failures)
