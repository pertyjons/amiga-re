# Plans

This directory contains only work that may still be reconsidered or
implemented. Completed plans are removed; their commits and repository history
are the durable record of what landed.

## Current plan

| Plan | Current position | Next decision |
| --- | --- | --- |
| `semantic-disassembly-roadmap.md` | Stages 0–3 are complete. Stage 4 groundwork, six bounded Stage 5A increments, and the bounded Stage 5B function-signature and stack-frame analysis have landed. Schema 16 adds indexed, MOVEM, and sized symbolic reads with synthetic branch/join coverage. | Stop unless a measured case justifies a separate Stage 5C proposal. |

The roadmap describes possible semantic-analysis depth, not an automatic work
queue. Its stop decisions take precedence over stage numbering. Any newly
approved stage should be split into reviewable increments and must pass the
complete workspace gate in `AGENTS.md`.
