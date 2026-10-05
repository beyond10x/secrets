---
format: aep.planning-md/3
id: story:resource-and-crypto
kind: story
status: implemented
title: Model and encrypt secret versions
summary: Define ownership, disclosure and envelope encryption.
relations:
- derived_from: epic:encrypted-custody
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 2, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "proposed", to: "active", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 3, decided_on: {"recorded":{"test_result":1}}, imported: true}
- {from: "active", to: "implemented", at: "2026-09-01T11:07:38Z", actor: "human:timo", revision: 4, decided_on: {"recorded":{"test_result":1}}, imported: true}
---
## Acceptance

Tampering, wrong associated data and wrong keys are refused while a valid encrypted version round-trips without persisting plaintext or key material.
