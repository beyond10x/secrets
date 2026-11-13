---
format: aep.planning-md/3
id: story:contract-for-other-languages
kind: story
status: draft
title: A workload in another language has a client or a stated contract
revision: 1
---
## Why

The client this repository ships is the Rust crate `crates/secrets-client`. A workload written
in another language (the case reported at `v0.6.0`: a Go service) calls the workload routes by
hand from `docs/openapi.json`: `PUT /v1/workload/secrets`, the `:get`, `:exists`, `:list` and
`:delete` calls, and prepare, commit and abort. The documentation does not say whether the
OpenAPI document is the contract such a caller may rely on, or which of the Rust client's
behaviour (how it presents the projected token, what it retries, how it reads an error body) a
hand-written caller has to repeat.

Reported by a reader of the source and the documentation; nothing here was run.

## Acceptance

- Either a client for one more language is shipped and held to the service by a test, or the
  documentation states that `docs/openapi.json` is the contract for callers in other languages
  and lists what a caller must do that the document cannot say: the token it sends and where it
  reads it, the audience, which calls are safe to repeat, and the form of an error body. The
  story says which and why.
- Where the statement is chosen: a test fails when a workload route changes and
  `docs/openapi.json` does not.

## Notes

- Not decided: a second client or the statement. A second client is one more thing to keep in
  step with the service at each release.
