# Legis operator guides

Practical, human-facing documentation for running and reading Legis. These sit
between the conceptual [`README.md`](../../README.md) (*why* the governance 2×2
exists) and the `legis-workflow` skill (the *agent-call* surface).

| Guide | Answers |
|---|---|
| **[configuration.md](configuration.md)** | What do I set, what does enabling each cell cost, and what does it buy? The full env-var / flag reference, the fail-closed default, and the dev-only escape hatches. |
| **[reading-legis-output.md](reading-legis-output.md)** | What am I seeing when an agent does X? The verdict / outcome / status vocabulary and — for each signal — whether a human needs to act. |

**Audience:** the operator who governs from outside the agent's loop. If you are
the *agent* operating under Legis, the `legis-workflow` skill
(`src/legis/data/skills/legis-workflow/SKILL.md`) is your reference instead.

**Start here if you are:**
- *Standing Legis up* → [configuration.md](configuration.md), then `legis doctor`.
- *Reviewing what an agent did* → [reading-legis-output.md](reading-legis-output.md).
- *Wondering whether you need to act on something you saw* → the one-sentence
  summary at the end of [reading-legis-output.md](reading-legis-output.md).
