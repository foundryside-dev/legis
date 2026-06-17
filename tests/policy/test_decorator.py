import ast
import importlib.util

import pytest

from legis.policy.boundary_scan import _source_segment_with_decorators
from legis.policy.decorator import (
    PolicyBoundaryMetadata,
    fingerprint,
    fingerprint_source,
    policy_boundary,
)


# --- Q-L5: the runtime gate and the static scanner must agree ---

def _static_fingerprint(module_source: str, name: str) -> str:
    """Reproduce the static scanner's extraction: the decorated function source
    run through the shared canonicalization."""
    tree = ast.parse(module_source)
    node = next(
        n
        for n in ast.walk(tree)
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
    )
    segment = _source_segment_with_decorators(module_source, node)
    return fingerprint_source(segment)


def _runtime_fingerprint(tmp_path, module_source: str, name: str) -> str:
    """Reproduce the runtime gate's extraction: inspect.getsource of the live
    function (decorators included)."""
    path = tmp_path / "refmod.py"
    path.write_text(module_source, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("refmod_ql5", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return fingerprint(getattr(mod, name))


_DECORATED_TEST_MODULE = (
    "import functools\n"
    "\n"
    "def deco(f):\n"
    "    @functools.wraps(f)\n"
    "    def w(*a, **k):\n"
    "        return f(*a, **k)\n"
    "    return w\n"
    "\n"
    "@deco\n"
    "def referenced_test():\n"
    '    """exercises the boundary"""\n'
    "    assert True\n"
)


def test_runtime_and_static_fingerprints_agree_for_decorated_test(tmp_path):
    # The crux of Q-L5 after decorator-sensitive hashing: runtime and static
    # extraction must both include decorator lines so semantic test decorators
    # are pinned without making the two paths diverge.
    runtime = _runtime_fingerprint(tmp_path, _DECORATED_TEST_MODULE, "referenced_test")
    static = _static_fingerprint(_DECORATED_TEST_MODULE, "referenced_test")
    assert runtime == static


def test_runtime_and_static_fingerprints_agree_for_class_method(tmp_path):
    # Class methods are indented and may be decorated; dedent + decorated-source
    # extraction must still make the two paths agree.
    module = (
        "import functools\n"
        "\n"
        "def deco(f):\n"
        "    return f\n"
        "\n"
        "class TestThing:\n"
        "    @deco\n"
        "    def referenced_test(self):\n"
        "        assert 1 + 1 == 2\n"
    )
    path = tmp_path / "refmod.py"
    path.write_text(module, encoding="utf-8")
    spec = importlib.util.spec_from_file_location("refmod_ql5_cls", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    runtime = fingerprint(mod.TestThing.referenced_test)
    static = _static_fingerprint(module, "referenced_test")
    assert runtime == static


def test_fingerprint_source_is_crlf_invariant():
    lf = "def t():\n    assert True\n"
    crlf = lf.replace("\n", "\r\n")
    assert fingerprint_source(lf) == fingerprint_source(crlf)


def test_fingerprint_source_changes_when_decorators_change():
    undecorated = (
        "def test_x():\n"
        "    result = guarded({'p': 'PY-WL-101'})\n"
        "    assert result == 'ok', 'PY-WL-101'\n"
    )
    skipped = "@pytest.mark.skip(reason='later disabled')\n" + undecorated
    parametrized = "@pytest.mark.parametrize('n', [1, 2])\n" + undecorated
    wrapped = "@custom_wrapper\n" + undecorated

    base = fingerprint_source(undecorated)
    assert fingerprint_source(skipped) != base
    assert fingerprint_source(parametrized) != base
    assert fingerprint_source(wrapped) != base


def test_fingerprint_source_unparsable_fragment_falls_back():
    # A non-parseable fragment hashes the normalized text rather than raising —
    # both paths share this fallback, so they still agree.
    frag = "    assert broken(:\n"
    assert isinstance(fingerprint_source(frag), str)


def test_decorator_is_passthrough_and_attaches_metadata():
    @policy_boundary(
        source="external webhook payload",
        suppresses=("no-eval",),
        invariant="rejects non-dict payloads",
        test_ref="tests.policy.test_decorator::test_handler_rejects",
        test_fingerprint="abc123",
    )
    def handler(payload):
        return payload["ok"]

    assert handler({"ok": 42}) == 42  # strict passthrough
    meta = handler.__policy_boundary__
    assert isinstance(meta, PolicyBoundaryMetadata)
    assert meta.suppresses == ("no-eval",)
    assert meta.qualname.endswith("handler")
    assert meta.test_ref.endswith("test_handler_rejects")


def test_empty_suppresses_is_rejected_at_decoration():
    with pytest.raises(TypeError):

        @policy_boundary(source="s", suppresses=(), invariant="i")
        def f(x):
            return x


def test_stacking_is_rejected():
    with pytest.raises(TypeError):

        @policy_boundary(source="s", suppresses=("p",), invariant="i")
        @policy_boundary(source="s", suppresses=("p",), invariant="i")
        def f(x):
            return x
