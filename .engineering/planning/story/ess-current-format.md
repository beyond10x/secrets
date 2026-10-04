---
format: aep.planning-md/2
id: story:ess-current-format
kind: story
status: active
title: The specification is current ESS and generates the reference pages
relations:
- decomposes: epic:encrypted-custody
revision: 4
---
# Story: ess-current-format

## Outcome

A reader of the Secrets site gets a specification reference that is generated from `spec/` by the
current ESS release, so the reference cannot disagree with the specification the gate validates.

## Context

`spec/` is `format: ess/14`, gated on ESS 0.36.0. The organization's product sites (Loom, Canon,
ELS, Commission) generate their reference pages with `ess generate --kind docs`, which needs the
current release. Depends on nothing; `story:standalone-site` consumes the generated pages.

## Acceptance

- `ess specify validate --path spec` exits 0 under ESS 0.52.0, and CI installs exactly 0.52.0.
- `contracts/schema/` is regenerated from the migrated specification; the conformance suite against
  the shipped service keeps at least 100 answered scenarios, 0 skipped and 0 failed
  (`contracts/baseline.json`).
- Every custody command still names the route and status code the shipped handler answers with
  (`crates/secrets-http/src/lib.rs`).
- `secrets-docs generate --check` exits 0: `website/docs/reference/ess/` and
  `website/data/ess/*.domain-graph.json` match a fresh generation, and `task check` runs it.

## Out of Scope

Audit records stay deferred to `story:verified-audit-actor`. No storage backend is implemented.

## Ambiguities

None.
