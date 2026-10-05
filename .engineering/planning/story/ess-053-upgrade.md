---
format: aep.planning-md/3
id: story:ess-053-upgrade
kind: story
status: active
title: Secrets runs on ESS 0.53.0 and declares what it lifts
relations:
- decomposes: epic:encrypted-custody
scope:
- confidence: cited
  path: .github/workflows/check.yml
- confidence: cited
  path: checks/conformance
- confidence: cited
  path: contracts
- confidence: cited
  path: spec
- confidence: cited
  path: website/data/ess
- confidence: cited
  path: website/docs/reference/ess
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T18:52:18Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-05T18:52:18Z", actor: "human:timo", revision: 3}
---
## Outcome

Secrets builds, specifies and runs its conformance suites on ESS 0.53.0, the newest release, and
every specification limit marker that 0.53.0 makes expressible is declared instead of written down.

## Context

ESS 0.53.0 (2026-10-05) adds source format `ess/22`: dotted input paths `input.<path>` in `sets:`,
`payload:` and `else:` and `label.utf8_bytes` (beyond10x/ess#233); row-set guards
`when_related: {entity, where, ...}` and `{related: {entity, where, field}}` (beyond10x/ess#228,
beyond10x/ess#299); `affects` entries that move (beyond10x/ess#229); views in an actor's `may:`
(beyond10x/ess#286). The repository pins 0.52.0 in CI, the runner's `ess-conformance` and
`ess-primitives` git tags and `contracts/ess-inputs.yaml`. Caller-attribute markers belong to
`story:verified-audit-actor` and are out of scope.

## Acceptance

- CI installs ESS 0.53.0 from the release tarball, checked against its SHA256SUMS entry; the
  runner links `ess-conformance` and `ess-primitives` at tag `0.53.0`; `contracts/ess-inputs.yaml`
  requires `ess 0.53.0`.
- `contracts/suite.json`, `contracts/storage-suite.json`, `contracts/cli-suite.json`,
  `contracts/schema/` and the generated documentation pages are regenerated with ESS 0.53.0, and
  `task conformance` and `task docs-check` report no drift.
- Every `ESS-LIMIT` marker in `spec/domains/custody.yaml` and `spec/domains/storage.yaml` that ESS
  0.53.0 can express is declared and deleted; each lift is falsified by a deliberate defect that a
  named scenario catches. Every remaining non-caller marker cites ESS 0.53.0 and the ESS issue
  that tracks it.
- `task check` exits 0: `secrets-service` 111/111, `secrets-library` 110/110 and the `secretsctl`
  CLI suite 89/89 or more, each three times with identical counts, 0 unsupported, 0 skipped.

## Scope

- `.github/workflows/check.yml`, `checks/conformance/Cargo.toml`, `Cargo.lock`
- `contracts/ess-inputs.yaml`, `contracts/*.json`, `contracts/schema/`
- `spec/system.yaml`, `spec/domains/custody.yaml`, `spec/domains/storage.yaml`
- `checks/conformance/src/` where new scenarios need an answer
- `website/docs/reference/ess`, `website/data/ess`, `website/docs/getting-started.md`, `AGENTS.md`,
  `CHANGELOG.md`

## Ambiguities

None.
