---
format: aep.planning-md/2
id: story:refusal-codes
kind: story
status: active
title: Every refusal carries a distinct machine-readable code
relations:
- decomposes: epic:encrypted-custody
revision: 3
---
## Acceptance

Every refusal the service answers carries a stable machine-readable code beside its reason, so two
refusals with the same status are distinguishable by a client:
`{"error": "<reason>", "code": "<code>"}`.

The four pairs that answer identically today get distinct codes:

- 403 `missing-action` vs `forbidden` (foreign tenant)
- 400 `malformed-body` vs the other 400 refusals
- 400 `malformed-reference` (empty or NUL part) vs `invalid-reference` (over 255 bytes)
- 400 `empty-batch` vs `cross-tenant-batch`

No code or reason echoes request input. The OpenAPI document and `spec/domains/custody.yaml`
declare the codes; the conformance runner distinguishes each pair from the response alone, not
from what it sent. `task check` exits 0.

## Source

Wave 2 unit S report: the runner told these pairs apart only from its own input.
