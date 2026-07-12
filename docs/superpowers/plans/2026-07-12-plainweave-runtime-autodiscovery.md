# Plainweave Runtime Autodiscovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace project-rooted `PLAINWEAVE_MCP_CMD` launch bindings with Filigree-style runtime discovery from the active project, and migrate 1.5.0 project/global configuration without oscillation.

**Architecture:** The globally registered Legis executable inherits the active project cwd and calls the existing hardened `discover_plainweave(project_root())` boundary once during MCP runtime construction. Doctor treats `PLAINWEAVE_MCP_CMD` as a removable legacy key, preserves the existing race-safe JSON/TOML writers, and rejects a fixed global Codex `cwd` as operator-owned project binding.

**Tech Stack:** Python 3.11+, pytest, stdlib JSON/TOML/filesystem APIs, existing Legis doctor and Plainweave advisory client.

---

## File map

- `src/legis/mcp.py` — compose the Plainweave advisory client from runtime discovery instead of environment configuration.
- `src/legis/plainweave_preflight/client.py` — remove the retired environment-variable wording from the empty-command diagnostic.
- `src/legis/plainweave_binding.py` — inspect and surgically remove legacy project/global binding keys while preserving the hardened writer machinery; expose fixed-global-cwd state.
- `src/legis/doctor.py` — give the two binding checks their new project-agnostic meanings and post-verify migration.
- `tests/mcp/test_server.py` — runtime-discovery and stale-environment regressions.
- `tests/test_plainweave_binding.py` — remove-only writer, fixed-cwd, safety, idempotency, and preservation tests.
- `tests/test_doctor.py` — two-project convergence and doctor status/repair behavior.
- `README.md`, `CHANGELOG.md`, `docs/guide/configuration.md`, `docs/guide/cli-reference.md`, `docs/guide/reading-legis-output.md` — operator-facing behavior and migration guidance.
- `docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md`, `docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md` — mark the 1.5.0 binding design/plan as superseded rather than silently rewriting history.
- `tests/test_plainweave_docs.py`, `tests/test_plainweave_plan.py` — documentation contract updates.

### Task 1: Discover Plainweave when the MCP runtime starts

**Files:**
- Modify: `tests/mcp/test_server.py:3829`
- Modify: `src/legis/mcp.py:234`
- Modify: `src/legis/plainweave_preflight/client.py:205`

- [ ] **Step 1: Replace the environment-wiring tests with failing runtime-discovery tests**

Add this helper and the three focused tests in the Plainweave section of `tests/mcp/test_server.py`:

```python
def _runtime_plainweave_project(root: Path, executable: Path) -> None:
    state = root / ".plainweave"
    state.mkdir(parents=True)
    (state / "plainweave.db").touch()
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": str(executable),
                        "args": ["--root", str(root)],
                    }
                }
            }
        ),
        encoding="utf-8",
    )


def test_build_runtime_discovers_plainweave_from_active_project(
    monkeypatch, tmp_path
):
    from legis.mcp import build_runtime
    from legis.plainweave_preflight.client import PlainweaveMcpClient

    root = tmp_path / "project"
    root.mkdir()
    executable = tmp_path / "tools" / "plainweave-mcp"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    _runtime_plainweave_project(root, executable)
    monkeypatch.chdir(root)
    monkeypatch.delenv("PLAINWEAVE_MCP_CMD", raising=False)
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)

    runtime = build_runtime("agent-x")

    assert isinstance(runtime.plainweave, PlainweaveMcpClient)
    assert runtime.plainweave._repo == str(root)
    assert runtime.plainweave._invoke._command == [
        str(executable.resolve()),
        "--root",
        str(root),
    ]


def test_build_runtime_ignores_stale_plainweave_environment(
    monkeypatch, tmp_path
):
    from legis.mcp import build_runtime

    root = tmp_path / "project"
    root.mkdir()
    executable = tmp_path / "tools" / "plainweave-mcp"
    executable.parent.mkdir()
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o755)
    _runtime_plainweave_project(root, executable)
    monkeypatch.chdir(root)
    monkeypatch.setenv(
        "PLAINWEAVE_MCP_CMD",
        "/stale/plainweave-mcp --root /another/project",
    )
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)

    runtime = build_runtime("agent-x")

    assert runtime.plainweave is not None
    assert runtime.plainweave._invoke._command[0] == str(executable.resolve())
    assert runtime.plainweave._invoke._command[-1] == str(root)


def test_build_runtime_degrades_when_plainweave_discovery_fails(
    monkeypatch, tmp_path, caplog
):
    from legis.mcp import build_runtime

    root = tmp_path / "project"
    (root / ".plainweave").mkdir(parents=True)
    (root / ".plainweave" / "plainweave.db").touch()
    monkeypatch.chdir(root)
    monkeypatch.setenv("PATH", "")
    monkeypatch.delenv("LEGIS_HMAC_KEY", raising=False)

    runtime = build_runtime("agent-x")

    assert runtime.plainweave is None
    assert "runtime autodiscovery failed" in caplog.text
    assert "governance unaffected" in caplog.text
```

- [ ] **Step 2: Run the tests and verify RED**

Run:

```bash
uv run pytest tests/mcp/test_server.py -k 'build_runtime and plainweave' -vv
```

Expected: the discovery and stale-environment tests fail because `build_runtime` still reads only `PLAINWEAVE_MCP_CMD`.

- [ ] **Step 3: Implement runtime autodiscovery**

Replace the Plainweave block in `build_runtime` with:

```python
    plainweave = None
    from legis.config import project_root
    from legis.plainweave_binding import discover_plainweave
    from legis.plainweave_preflight.client import (
        PlainweaveError,
        PlainweaveMcpClient,
    )
    from legis.plainweave_preflight.client import (
        StdioMcpInvoke as PlainweaveStdioMcpInvoke,
    )

    plainweave_root = project_root()
    discovery = discover_plainweave(plainweave_root)
    if discovery.command is not None:
        import shlex

        try:
            argv = shlex.split(discovery.command)
            if not argv:
                raise PlainweaveError("discovered Plainweave command is empty")
            plainweave = PlainweaveMcpClient(
                invoke=PlainweaveStdioMcpInvoke(command=argv),
                repo=str(plainweave_root),
            )
        except (PlainweaveError, ValueError) as exc:
            logging.getLogger(__name__).warning(
                "Plainweave runtime autodiscovery produced an invalid command (%s); "
                "plainweave advisory context disabled (governance unaffected).",
                exc,
            )
    elif discovery.error is not None:
        logging.getLogger(__name__).warning(
            "Plainweave runtime autodiscovery failed (%s); plainweave advisory "
            "context disabled (governance unaffected).",
            discovery.error,
        )
```

In `StdioMcpInvoke.__call__`, change the empty-command diagnostic to:

```python
raise PlainweaveError("plainweave-mcp command is empty")
```

- [ ] **Step 4: Run focused runtime and advisory-boundary tests**

Run:

```bash
uv run pytest tests/mcp/test_server.py -k 'plainweave' -q
uv run pytest tests/mcp/test_plainweave_advisory_boundary.py -q
```

Expected: both commands pass.

- [ ] **Step 5: Commit the runtime change**

```bash
git add src/legis/mcp.py src/legis/plainweave_preflight/client.py tests/mcp/test_server.py
git commit -m "fix(mcp): discover Plainweave from active project"
```

### Task 2: Make project binding repair remove the legacy key

**Files:**
- Modify: `src/legis/plainweave_binding.py:129-242`
- Modify: `src/legis/plainweave_binding.py:401-428`
- Modify: `tests/test_plainweave_binding.py:898-1075`

- [ ] **Step 1: Add failing remove-only project tests**

Add:

```python
def test_project_autodiscovery_state_requires_legacy_key_absent(tmp_path: Path) -> None:
    config = _write_legis_entry(
        tmp_path,
        env={"KEEP_ME": "operator", PLAINWEAVE_ENV: "plainweave-mcp --root /old"},
    )

    before = plainweave_binding.inspect_project_binding(tmp_path, None)
    assert before == plainweave_binding.BindingState(True, False, None)

    assert plainweave_binding.repair_project_binding(tmp_path, None) is None

    after = plainweave_binding.inspect_project_binding(tmp_path, None)
    env = json.loads(config.read_text())["mcpServers"]["legis"]["env"]
    assert after == plainweave_binding.BindingState(True, True, None)
    assert env == {"KEEP_ME": "operator"}


def test_project_autodiscovery_repair_is_idempotent(tmp_path: Path) -> None:
    config = _write_legis_entry(tmp_path, env={PLAINWEAVE_ENV: "legacy"})
    assert plainweave_binding.repair_project_binding(tmp_path, None) is None
    first = config.read_bytes()

    assert plainweave_binding.repair_project_binding(tmp_path, None) is None

    assert config.read_bytes() == first
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest tests/test_plainweave_binding.py -k 'project_autodiscovery' -vv
```

Expected: failure because `desired=None` currently makes the binding stale and writes JSON `null` instead of removing the key.

- [ ] **Step 3: Generalize project inspection and repair to remove-only mode**

Add this helper near `BindingState`:

```python
def _binding_is_current(env: dict[str, str], desired: str | None) -> bool:
    if desired is None:
        return PLAINWEAVE_ENV not in env
    return env.get(PLAINWEAVE_ENV) == desired
```

Change `_inspect_project_binding`, `inspect_project_binding`, and
`repair_project_binding` to accept `desired: str | None`, use
`_binding_is_current`, and build the updated environment as follows:

```python
updated_env = dict(env)
if desired is None:
    updated_env.pop(PLAINWEAVE_ENV, None)
else:
    updated_env[PLAINWEAVE_ENV] = desired
entry["env"] = updated_env
```

Update their docstrings so `None` explicitly means “project-agnostic runtime autodiscovery; legacy key absent.” Retain the string mode for the existing hardened writer tests, but add an `rg` verification later proving no production caller sets a value.

- [ ] **Step 4: Run the full project-binding safety tests**

Run:

```bash
uv run pytest tests/test_plainweave_binding.py -k 'project' -q
```

Expected: pass, including size, symlink, FIFO, snapshot-race, mode, newline, and secret-preservation cases.

- [ ] **Step 5: Commit the project migration primitive**

```bash
git add src/legis/plainweave_binding.py tests/test_plainweave_binding.py
git commit -m "fix(doctor): remove legacy project Plainweave binding"
```

### Task 3: Make global repair remove the legacy key and expose fixed cwd

**Files:**
- Modify: `src/legis/plainweave_binding.py:40-44`
- Modify: `src/legis/plainweave_binding.py:549-718`
- Modify: `src/legis/plainweave_binding.py:772-863`
- Modify: `tests/test_plainweave_binding.py:72-900`

- [ ] **Step 1: Add failing global autodiscovery tests**

Global inspection and repair are project-independent: every call below passes
no active project root. First make `_codex_config` accept `cwd: str | None =
None` and emit a `cwd` line only when supplied. Then add:

```python
def test_codex_autodiscovery_removes_only_legacy_binding(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=(
            '[mcp_servers.legis.env]\nKEEP_ME = "operator" # KEEP_ME\n'
            f'{PLAINWEAVE_ENV} = "legacy" # retired\n'
        ),
    )
    config.chmod(0o640)
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(None, None)
    assert state.current is False
    assert plainweave_binding.repair_codex_binding(root=None, desired=None) is None

    text = config.read_text()
    parsed = tomllib.loads(text)
    assert PLAINWEAVE_ENV not in parsed["mcp_servers"]["legis"]["env"]
    assert parsed["mcp_servers"]["legis"]["env"]["KEEP_ME"] == "operator"
    assert "# operator top comment" in text
    assert config.stat().st_mode & 0o777 == 0o640
    assert plainweave_binding.inspect_codex_binding(None, None).current is True


def test_codex_autodiscovery_reports_fixed_cwd(tmp_path: Path, monkeypatch) -> None:
    _codex_config(tmp_path, monkeypatch, cwd="/one/project")
    root = tmp_path / "project"
    root.mkdir()

    state = plainweave_binding.inspect_codex_binding(None, None)

    assert state.registered is True
    assert state.current is True
    assert state.project_bound is True


def test_codex_autodiscovery_repair_with_fixed_cwd_removes_only_legacy_key(
    tmp_path: Path, monkeypatch
) -> None:
    config = _codex_config(
        tmp_path,
        monkeypatch,
        env=f'[mcp_servers.legis.env]\n{PLAINWEAVE_ENV} = "legacy"\n',
        cwd="/operator/project",
    )
    root = tmp_path / "project"
    root.mkdir()

    assert plainweave_binding.repair_codex_binding(root=None, desired=None) is None

    entry = tomllib.loads(config.read_text())["mcp_servers"]["legis"]
    assert entry["cwd"] == "/operator/project"
    assert PLAINWEAVE_ENV not in entry["env"]
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest tests/test_plainweave_binding.py -k 'codex_autodiscovery' -vv
```

Expected: failures because remove-only mode and `project_bound` do not exist.

- [ ] **Step 3: Extend binding state and TOML editing**

Extend the state without breaking existing three-argument construction:

```python
@dataclass(frozen=True, slots=True)
class BindingState:
    registered: bool
    current: bool
    error: str | None = None
    project_bound: bool = False
```

Change Codex inspection/repair signatures to `desired: str | None`. Build the
state with:

```python
state=BindingState(
    registered=True,
    current=_binding_is_current(env, desired),
    project_bound="cwd" in entry,
)
```

At the beginning of `_updated_codex_text`, after resolving `env_span`, add the remove-only branch:

```python
if desired is None:
    if PLAINWEAVE_ENV not in env:
        return text, None
    existing_assignment = _supported_target_assignment(text, env_span)
    if existing_assignment is None:
        return (
            None,
            "global Codex Plainweave target assignment has an unsupported shape",
        )
    start, end = existing_assignment.span()
    return text[:start] + text[end:], None
```

Keep the existing insert/replace path under the non-`None` branch. In
`repair_codex_binding`, verify the updated target with:

```python
target_current = isinstance(updated_env, dict) and _binding_is_current(
    updated_env,
    desired,
)
if not target_current:
    return "updated Codex config.toml did not contain the required binding state"
```

- [ ] **Step 4: Run the complete Codex binding tests**

Run:

```bash
uv run pytest tests/test_plainweave_binding.py -k 'codex' -q
```

Expected: pass. Existing set-value tests remain as hardened writer coverage; new production callers use only `None`.

- [ ] **Step 5: Commit the global migration primitive**

```bash
git add src/legis/plainweave_binding.py tests/test_plainweave_binding.py
git commit -m "fix(doctor): remove global Plainweave project binding"
```

### Task 4: Rework doctor semantics and prove multi-project convergence

**Files:**
- Modify: `src/legis/doctor.py:202-309`
- Modify: `tests/test_doctor.py:35-115`
- Modify: `tests/test_doctor.py:430-900`

- [ ] **Step 1: Add the failing convergence and fixed-cwd doctor tests**

Add a helper that creates a second initialized root sharing the first helper's executable and Codex home. Then add:

```python
def test_plainweave_doctor_converges_across_two_projects(tmp_path, monkeypatch):
    alpha, executable, config = _plainweave_project(tmp_path, monkeypatch)
    plainweave = _make_executable(tmp_path / "plainweave-bin" / "plainweave-mcp")
    alpha_data = json.loads((alpha / ".mcp.json").read_text())
    alpha_data["mcpServers"]["plainweave"]["command"] = str(plainweave)
    alpha_data["mcpServers"]["legis"]["env"][PLAINWEAVE_ENV] = "legacy-alpha"
    (alpha / ".mcp.json").write_text(json.dumps(alpha_data, indent=2) + "\n")
    beta = tmp_path / "beta"
    (beta / ".plainweave").mkdir(parents=True)
    (beta / ".plainweave" / "plainweave.db").touch()
    (beta / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "plainweave": {
                        "type": "stdio",
                        "command": str(plainweave),
                        "args": ["--root", str(beta)],
                    },
                    "legis": {
                        "type": "stdio",
                        "command": str(executable),
                        "args": ["mcp", "--agent-id", "operator"],
                        "env": {PLAINWEAVE_ENV: "legacy-beta"},
                    },
                }
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    config.write_text(
        config.read_text()
        + f'{PLAINWEAVE_ENV} = "plainweave-mcp --root {alpha}"\n',
        encoding="utf-8",
    )

    alpha_fixed = {
        check.id: check for check in collect_checks(alpha, repair=True)
    }
    beta_fixed = {
        check.id: check for check in collect_checks(beta, repair=True)
    }
    alpha_read = {
        check.id: check for check in collect_checks(alpha, repair=False)
    }

    for checks in (alpha_fixed, beta_fixed, alpha_read):
        assert checks["install.plainweave_project_binding"].status == "ok"
        assert checks["install.plainweave_codex_binding"].status == "ok"
    assert PLAINWEAVE_ENV not in tomllib.loads(config.read_text())["mcp_servers"]["legis"]["env"]
    assert str(alpha) not in config.read_text()
    assert str(beta) not in config.read_text()


def test_plainweave_codex_fixed_cwd_is_operator_owned(tmp_path, monkeypatch):
    root, _executable, config = _plainweave_project(tmp_path, monkeypatch)
    config.write_text(
        config.read_text().replace(
            "[mcp_servers.legis.env]",
            f'cwd = {json.dumps(str(root))}\n[mcp_servers.legis.env]',
        ),
        encoding="utf-8",
    )
    before = config.read_bytes()

    check = check_plainweave_codex_binding(root, repair=True)

    assert check.status == "error"
    assert check.repairable is False
    assert "fixed cwd" in (check.message or "").lower()
    assert config.read_bytes() == before
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest tests/test_doctor.py -k 'plainweave and (converges or fixed_cwd)' -vv
```

Expected: convergence fails because doctor writes each discovered command globally; fixed cwd is not reported.

- [ ] **Step 3: Implement the new project check**

Keep discovery and the `install.mcp_json` blocker, but replace desired-value inspection/repair with `None`. Use these user-visible messages:

```python
state = _plainweave_binding.inspect_project_binding(root, None)
```

```python
"project Legis MCP registration carries legacy PLAINWEAVE_MCP_CMD; runtime autodiscovery requires a project-agnostic registration"
```

```python
error = _plainweave_binding.repair_project_binding(root, None)
post = _plainweave_binding.inspect_project_binding(root, None)
```

```python
"legacy project Plainweave binding removed; reconnect or restart the MCP client"
```

Preserve registration-repair ownership and all fail-closed branches.

- [ ] **Step 4: Implement the independent global check**

Remove `discover_plainweave(root)` from `check_plainweave_codex_binding`; inspect global state even for an uninitialized current project. Use this order:

1. operator error from malformed/unsafe state;
2. absent registration → healthy not-applicable;
3. legacy key present → auto-fixable, remove with `repair_codex_binding(root=None, desired=None)`, and post-verify; both global inspection and repair receive no active project root;
4. fixed `cwd` after migration → operator error with “global Codex Legis registration has a fixed cwd; remove it so runtime project autodiscovery inherits the active project”; and
5. otherwise healthy.

When repair removes the legacy key but a fixed `cwd` remains, return an error with `fixed=True`, `repairable=False`, and a message that distinguishes the completed legacy cleanup from the remaining operator action.

- [ ] **Step 5: Update superseded doctor tests and run focused suites**

Change assertions that expected the env key to be added so they instead assert it is absent. Change the uninitialized-project test so the project check remains not-applicable while the global check still validates malformed or legacy global config.

Run:

```bash
uv run pytest tests/test_doctor.py -k 'plainweave' -q
uv run pytest tests/test_plainweave_binding.py -q
uv run pytest tests/mcp/test_server.py -k 'doctor_get or plainweave' -q
```

Expected: all pass.

- [ ] **Step 6: Prove no production code writes a Plainweave binding value**

Run:

```bash
rg -n "repair_(project|codex)_binding" src/legis
rg -n "PLAINWEAVE_MCP_CMD" src/legis/mcp.py
```

Expected: the first command shows only the two definitions and doctor calls
passing `None`; the second command has no matches. The constant remains only in
migration code and tests/docs that explain retirement.

- [ ] **Step 7: Commit doctor convergence**

```bash
git add src/legis/doctor.py tests/test_doctor.py
git commit -m "fix(doctor): converge Plainweave bindings across projects"
```

### Task 5: Update operator documentation and supersession markers

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`
- Modify: `docs/guide/configuration.md`
- Modify: `docs/guide/cli-reference.md`
- Modify: `docs/guide/reading-legis-output.md`
- Modify: `docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md`
- Modify: `docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md`
- Modify: `tests/test_plainweave_docs.py`
- Modify: `tests/test_plainweave_plan.py`

- [ ] **Step 1: Write failing documentation contract tests**

Add `import pytest` to `tests/test_plainweave_docs.py`, then extend it with:

```python
@pytest.mark.parametrize(
    "path",
    [
        Path("README.md"),
        Path("docs/guide/configuration.md"),
        Path("docs/guide/cli-reference.md"),
        Path("docs/guide/reading-legis-output.md"),
    ],
)
def test_plainweave_docs_describe_runtime_autodiscovery(path: Path) -> None:
    text = path.read_text(encoding="utf-8")
    assert "runtime autodiscovery" in text.lower()
    assert "PLAINWEAVE_MCP_CMD" in text
    assert "legacy" in text.lower() or "retired" in text.lower()
```

Extend `tests/test_plainweave_plan.py` with:

```python
def test_original_binding_design_is_explicitly_superseded() -> None:
    historical = (
        Path("docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md"),
        Path("docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md"),
    )
    for path in historical:
        text = path.read_text(encoding="utf-8")
        assert "superseded" in text.lower()
        assert "2026-07-12-plainweave-runtime-autodiscovery" in text
```

- [ ] **Step 2: Run and verify RED**

Run:

```bash
uv run pytest tests/test_plainweave_docs.py tests/test_plainweave_plan.py -vv
```

Expected: failures because published guidance still describes environment-bound launch wiring.

- [ ] **Step 3: Update documentation**

Make these statements consistent across all operator guides:

- Legis discovers initialized Plainweave from the active project at MCP startup.
- For an initialized project, a present malformed `.mcp.json` or invalid local Plainweave entry fails closed and disables the trusted `PATH` fallback. The
  database-plus-`PATH` fallback is considered only when local config presents no Plainweave configuration issue.
- Global Codex configuration contains only the Legis tool pointer and no Plainweave project identity.
- `PLAINWEAVE_MCP_CMD` is a retired 1.5.0 key; `doctor --fix` removes it from safe project/global registrations.
- `install.plainweave_project_binding` verifies local discovery plus a project-agnostic Legis entry.
- `install.plainweave_codex_binding` verifies that an existing global Legis entry has neither the legacy key nor a fixed `cwd`.
- A fixed global `cwd` is operator-owned and must be removed manually.
- MCP clients must be restarted after migration.

Add this banner directly below the title in both 2026-07-11 design/plan files:

```markdown
> **Superseded:** The project-rooted environment-binding design in this document
> was replaced by
> `2026-07-12-plainweave-runtime-autodiscovery-design.md`. It remains as the
> historical 1.5.0 implementation record.
```

Add a changelog entry naming `legis-3622e80f2e` and the multi-project oscillation fix.

- [ ] **Step 4: Run documentation tests and scans**

Run:

```bash
uv run pytest tests/test_plainweave_docs.py tests/test_plainweave_plan.py -q
rg -n "PLAINWEAVE_MCP_CMD|plainweave_(project|codex)_binding|runtime autodiscovery" README.md CHANGELOG.md docs/guide docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md
git diff --check
```

Expected: tests pass; every remaining environment-key reference describes migration/retirement, not active configuration.

- [ ] **Step 5: Commit documentation**

```bash
git add README.md CHANGELOG.md docs/guide/configuration.md docs/guide/cli-reference.md docs/guide/reading-legis-output.md docs/superpowers/specs/2026-07-11-plainweave-doctor-binding-design.md docs/superpowers/plans/2026-07-11-plainweave-doctor-binding.md tests/test_plainweave_docs.py tests/test_plainweave_plan.py
git commit -m "docs: explain Plainweave runtime autodiscovery"
```

### Task 6: Run release verification and prepare tracker closeout

**Files:**
- Modify only if a verification failure proves an in-scope defect.

- [ ] **Step 1: Run formatting and static analysis**

```bash
uv run python scripts/check_changed_format.py --base 3ed0c74
uv run ruff check src
uv run mypy src
```

Expected: all exit 0.

- [ ] **Step 2: Run the focused Plainweave and doctor suites**

```bash
uv run pytest tests/test_plainweave_binding.py tests/test_doctor.py tests/mcp/test_server.py tests/mcp/test_plainweave_advisory_boundary.py tests/plainweave_preflight -q
```

Expected: all pass.

- [ ] **Step 3: Run the full suite**

```bash
uv run pytest -q
```

Expected: at least the clean baseline of 1,690 passing tests with only documented skips, plus the new regressions.

- [ ] **Step 4: Run repository gates**

```bash
uv run pytest --cov=legis --cov-report=term-missing --cov-report=json --cov-fail-under=88
uv run python scripts/check_coverage_floors.py
uv run pytest tests/conformance/test_sei_oracle.py
uv run legis policy-boundary-check --root src --repo-root .
git diff release/1.5.0...HEAD --check
git status --short
```

Expected: coverage is at least 88%, every per-package floor holds, the SEI
oracle passes, the policy-boundary result is `PASS`, the diff has no whitespace
errors, and the worktree is clean.

- [ ] **Step 5: Record verification and move the bug through closeout**

Add a Filigree comment containing the root cause, branch, commits, focused/full verification counts, and exact migration behavior. Move `legis-3622e80f2e` from `fixing` to its valid verification state, then close it with a reason only after all gates are green.
