# 03 — Architecture Diagrams (C4 + dependency)

> Mermaid sources. Edges reflect the measured cross-subsystem import matrix (`01-discovery-findings.md` §6); coupling concerns are validated in `temp/validation-catalog.md`.

## C4 L1 — System Context

```mermaid
graph TB
    agent["Coding Agent<br/>(primary customer)"]
    operator["Human Operator<br/>(signs off / posture / keys<br/>— from OUTSIDE the loop)"]
    legis["<b>Legis</b><br/>git/CI + governance layer<br/>(governance-honesty)"]
    forge["Forge<br/>(git / CI / PR / checks)"]
    loom["Loomweave<br/>(SEI authority)"]
    ward["Wardline<br/>(trust/taint analysis)"]
    fil["Filigree<br/>(issue tracking / sign-off)"]
    warp["Warpline<br/>(preflight facts)"]

    agent -->|override / signoff / read attestations / route findings| legis
    operator -->|sign-off, posture floor, key custody| legis
    legis -->|reads branch/commit/PR/check context| forge
    legis -->|resolve_sei / lineage (SEI opaque)| loom
    legis -->|provides rename feed| loom
    ward -->|findings ingested → routed into cells| legis
    legis -->|SEI-keyed sign-off binding / closure gate| fil
    warp -->|advisory preflight facts (never gates)| legis
```

## C4 L2 — Containers (process + persistence)

```mermaid
graph TB
    subgraph transports["Transports (thin adapters)"]
        http["HTTP — api/app.py"]
        mcp["MCP stdio — mcp.py (~23 tools)"]
        cli["CLI — cli.py (legis ...)"]
    end
    svc["<b>service/</b> — single source of governance truth<br/>(ServiceError taxonomy; adapters translate)"]
    subgraph domain["Domain subsystems"]
        enf["enforcement/ (2x2 engine)"]
        pol["policy/ (grammar, cells, boundary scanner)"]
        idn["identity/ (SEI seam — consumer)"]
        pos["posture/ (floor, operator key, elevation)"]
        fed["federation: wardline/ filigree/ governance/ warpline_preflight/"]
        gitci["git/ checks/ pulls/ (git-CI surfaces)"]
    end
    ops["Runtime/Ops: install.py · doctor.py · hooks.py · config.py"]
    stores[("SQLite stores under .weft/legis/<br/>append-only, HMAC-signed, v3 chain binding")]

    http --> svc
    mcp --> svc
    cli --> svc
    http -.imports.-> mcp
    svc --> enf
    svc --> pol
    svc --> idn
    svc --> fed
    enf --> stores
    pos --> stores
    gitci --> stores
    ops -.resolves store paths (LEGIS_*_DB).-> stores
```

## C4 L3 — Component: hub-and-adapters with dependency direction

```mermaid
graph LR
    http["api/"]; mcp["mcp.py"]; cli["cli.py"]
    svc["service/"]
    enf["enforcement/"]; pol["policy/"]; idn["identity/"]
    sto["store/"]; pos["posture/"]; gov["governance/"]
    ward["wardline/"]; fil["filigree/"]; warp["warpline_preflight/"]
    leaf["leaf: canonical · weft_signing · clock · provenance · records · config"]
    inst["install.py"]

    http --> svc; mcp --> svc; cli --> svc
    svc --> enf; svc --> pol; svc --> idn; svc --> gov; svc --> ward; svc --> warp
    enf --> sto; enf --> idn; enf --> leaf
    pol --> svc
    sto --> enf
    gov --> enf; gov --> fil; gov --> idn; gov --> sto
    ward --> enf; ward --> idn
    idn --> leaf
    pos --> sto; pos --> enf; pos --> pol; pos --> inst
    http --> mcp

    classDef concern stroke:#c0392b,stroke-width:3px;
    class pol,sto,pos concern
```

> Red-outlined nodes participate in a validated coupling concern: `store ↔ enforcement` (bidirectional), `policy → service` (inversion; uses a deferred import to dodge a load cycle), `posture → install` (inverted direction). `api → mcp` is the transport-on-transport edge (Q-H2).

## The governance 2×2 (enforcement engine)

```mermaid
quadrantChart
    title Enforcement cells — structure (x) x inline LLM judge (y)
    x-axis "Simple structure" --> "Complex structure"
    y-axis "Judge OFF" --> "Judge ON"
    quadrant-1 "PROTECTED: HMAC verdicts, decay sweep, override-rate gate, operator sign-off"
    quadrant-2 "COACHED: LLM judge gates the override (model-robustness wall, not crypto)"
    quadrant-3 "CHILL: surface + recordable override (no LLM/crypto)"
    quadrant-4 "STRUCTURED: block + escalate; human operator signs off"
```

## Sign-off binding sequence (fail-closed)

```mermaid
sequenceDiagram
    participant A as Agent/Operator
    participant G as governance/signoff_binding
    participant F as Filigree
    participant L as BindingLedger
    A->>G: bind(issue, entity_key, content_hash, signoff_seq)
    G->>G: reject if entity_key NOT identity_stable (locator) — fail closed
    G->>F: attach(... binding_signature)
    F-->>G: ok (pointer held)
    G->>L: record(binding_seq)
    Note over G,L: if record() fails after attach():<br/>split state, NO silent bind —<br/>ledger.verify() surfaces the missing entry (fail closed)
    G-->>A: {binding_seq, binding_signature}
```
