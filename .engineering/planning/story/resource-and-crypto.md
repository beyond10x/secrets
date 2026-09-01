---
format: aep.planning-md/1
id: story:resource-and-crypto
kind: story
status: implemented
title: Model and encrypt secret versions
summary: Define ownership, disclosure and envelope encryption.
relations:
- derived_from: epic:encrypted-custody
revision: 4
---
## Acceptance

Tampering, wrong associated data and wrong keys are refused while a valid encrypted version round-trips without persisting plaintext or key material.
