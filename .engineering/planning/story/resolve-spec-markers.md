---
format: aep.planning-md/3
id: story:resolve-spec-markers
kind: story
status: implemented
title: Every open spec marker has a recorded outcome
relations:
- decomposes: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-27T18:43:44Z", actor: "human:timo", revision: 2, imported: true}
- {from: "proposed", to: "active", at: "2026-09-27T18:43:49Z", actor: "human:timo", revision: 3, imported: true}
- {from: "active", to: "implemented", at: "2026-09-27T20:18:46Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

Every `UNMAPPED:` marker in this repository's ESS sources has one of four recorded outcomes, and
`ess specify validate` exits 0:

1. **Declared** — the semantics are read from code, OpenAPI or docs and are now modelled, citing
   the source line; where the code can run it, a conformance scenario covers it.
2. **Decided** — a design question with no source; the coordinator's default is modelled and the
   spec comment names it as a decision dated 2026-09-27.
3. **Deferred** — out of scope of the shipped system; the marker becomes a `DEFERRED:` note naming
   an existing story or artifact id that owns it (a draft story is filed when none exists).
4. **ESS limit** — the semantics are known but ESS 0.36 cannot express them; the marker becomes an
   `ESS-LIMIT:` note naming the missing construct.

No `UNMAPPED:` marker remains. The repository's full check exits 0.

## Source

Operator approval 2026-09-27 to resolve the open spec markers after wave 2.
