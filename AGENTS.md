# AGENTS.md — secrets

What Secrets is and how to build it is in [README.md](README.md); this file is what an agent changing
it must know. The cross-repository decision is Atlas ADR 0023 (Secrets is the shared custody service).

## Serves

- O1: Engineers can compose and operate a coherent development platform.
- O4: Services share explicit, replaceable platform contracts without runtime coupling through a mandatory SDK.
- O5: User and workload credentials have auditable, least-privilege custody and lifecycle.

## Boundaries

- Secrets owns encrypted byte custody, versions, ownership, disclosure, local revocation and
  deletion, workload grants, prepared batches and audit records.
- Provider integrations own OAuth exchange, refresh and upstream revocation.
- Identity verifies users but knows no product resource, connector kind or secret semantics.
- The deployment chart belongs to the composing product (the Devcenter chart); this repository has
  no Helm chart.

## Rules

- A value never appears in a URL, log, metric, error, label or planning artifact, and a refusal
  never repeats the request.
- Every route checks its authority, its action and the request's tenant before storage is called.
- Do not weaken tenant, audience or associated-data checks to simplify an integration.
- Anything that runs is Rust; command lines use clap derive.

## Commands

| Command | What it does |
|---|---|
| `task check` | the gate: fmt, tests, clippy, `cargo doc`, plan and spec validation, provenance, conformance, `docs-check` |
| `task conformance` | `secrets-conformance check`: suite and schema drift, then the suite three times against PostgreSQL |
| `task docs-generate` | rewrite `website/docs/reference/` and `website/data/ess/` from `spec/` |
| `task docs-check` | fail on a missing, stale or hand-edited generated page |
| `task website` | `npm ci && npm run build` in `website/` |

`task check` and `task conformance` need `SECRETS_TEST_DATABASE_URL` pointing at a disposable
PostgreSQL database; conformance refuses to run without it. CI provides one. Tool versions:
`ess` 0.52.0 (`contracts/ess-inputs.yaml` `requires`), `aep` 0.68.0, Rust 1.97.

## Specification

ESS drives this repository. `spec/domains/custody.yaml` is retrofitted from the shipped service and
cites a source for every declaration; `spec/domains/storage.yaml` is the named-storage model,
whose port `secrets-core` implements (`secrets_core::storage`), with the local authorizer
(`secrets_core::authorize`), mount routing (`secrets-federation`) and the keychain
(`secrets-keychain`) and remote (`secrets-remote`) backends. Change the specification first, then
the code.

- `contracts/suite.json` (`secrets-service`), `contracts/storage-suite.json` (`secrets-library`),
  `contracts/cli-suite.json` (`secrets-library` with the authored scenarios under
  `contracts/storage/scenarios/cli`) and `contracts/schema/` are generated; `task conformance`
  fails on drift. Regenerate with the
  exact arguments in `checks/conformance/src/gate.rs`.
- The runner (`checks/conformance/`) sends every custody command through the real router and
  store, and every storage command through the composed storage stack in process, and reads the
  branch from the response and from which backends the call reached; it never decides a branch
  from the suite. The stack is composed in `checks/conformance/src/storage.rs`: keychain on a
  mock store, remote against an in-process custody service, recording fakes for read-only and
  faulting mounts. Every mount of kind `onepassword` is the read-only, binding-required recording
  fake; no 1Password backend exists.
- The CLI suite runs through the built `secretsctl` (`checks/conformance/src/cli.rs`): the runner
  builds it with feature `test-hooks` in a target directory of its own (`secretsctl-conformance`),
  gives each scenario its own `XDG_CONFIG_HOME` under `target/conformance/cli` and a file-backed
  keychain (`SECRETSCTL_TEST_KEYCHAIN_FILE`); a `test-hooks` build also mounts the read-only fake
  for `[backends.onepassword.<label>]`. It reads the branch from the exit status, the JSON
  refusal (with the flag a denial names) and the world before the command, and holds a denial to
  leaving the configuration, its lock and the keychain file unchanged. What ESS cannot state (no
  value on stdout or stderr, `read --out` creating only a new mode-0600 file and refusing a
  symlink, a value in argv refused, `put`'s sources, the configuration file's mode, a denial
  decided before the configuration or keychain is opened, an inert test hook and an unmountable
  fake in a default build) is guarded by `crates/secretsctl/tests/` (`cli.rs`,
  `review_invariants.rs`, `review_default_build.rs`).
- `contracts/baseline.json` holds the custody floor: 111 answered, 0 skipped.
  `contracts/storage-baseline.json` holds the library's: 108 answered, 0 unsupported.
  `contracts/cli-baseline.json` holds the CLI's: 89 answered, 0 unsupported.
  Every authored scenario must pass. Raise a floor or lower a ceiling when the suite grows; never
  the reverse to pass.
- Every authored scenario under `contracts/*/scenarios/` is listed in `contracts/ess-inputs.yaml`.

## Plan

The AEP store under `.engineering/planning` (`aep.project/5`, Git-native) is the plan, written only through `aep`. A new noun gets
its ESS declaration before a story is written around it, and each story's acceptance names its
conformance scenarios.

## Documentation

The public site is `website/`, published at `https://beyond10x.github.io/secrets/` by
`pages.yml` (credential-free build, provenance and route inventory) and `b10x-docs-site.yml`
(Website's project-site workflow). Pages under `website/docs/reference/` and files under
`website/data/ess/` are generated; every other page is written by hand. Keep page paths and
heading IDs stable: the organization Website redirects the former `/docs/secrets/` pages to them.

Do not add a unified Website bundle, `b10x.docs.yaml`, a redirect façade or a second Pages
workflow. `docs/openapi.json` and `docs/index.html` stay where they are: the service embeds both.
Publish no internal plans, decisions or work logs.

<!-- b10x-release-operations:start -->
## Release completion

An ordinary release completes after this repository's exact tag, required source checks,
published release and required artifacts are verified. A pushed tag with unfinished checks or
uploads is queued; report it as released only after those requirements succeed.

Atlas reconciliation and public documentation publication run asynchronously. Do not wait for
Atlas or Website, update Website source locks or bootstrap snapshots, promote consumer pins,
release shared docs tooling, or redeploy documentation façades as part of an ordinary source
release. Report documentation as pending unless its publication was actually verified. A background
documentation failure does not invalidate a successful source release.

Keep this repository's provenance, correctness, security, compatibility and artifact verification
requirements. Shared rendering, routing or delivery-control changes still require their relevant
integration gates. A release request does not authorize deployment or downstream releases.
Repositories without a release unit retain their existing publication policy. This completion
boundary supersedes older instructions that attach synchronous documentation ceremony to each
source release.
<!-- b10x-release-operations:end -->
