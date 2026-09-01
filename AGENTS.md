# Repository guidance

## Serves

- O1: Engineers can compose and operate a coherent development platform.
- O4: Services share explicit, replaceable platform contracts without runtime coupling through a mandatory SDK.
- O5: User and workload credentials have auditable, least-privilege custody and lifecycle.

## Boundaries

- Secrets owns encrypted byte custody, local lifecycle, bindings, and audit records.
- Provider integrations own OAuth exchange, refresh, and upstream revocation.
- Identity verifies users but does not know product resources, connector kinds, or secret semantics.
- Values never belong in URLs, logs, metrics, errors, labels, or planning artifacts.
- The deployment chart belongs to the composing product; this repository does not own a Helm chart.

## Gate

Run `task check` before publishing. Do not weaken tenant, audience, or associated-data checks to simplify an integration.

<!-- b10x-docs-operations:start -->
## Public documentation operations

This repository owns the public source and presentation allowlist in `b10x.docs.yaml`; the unified [beyond10x Website](https://beyond10x.github.io/docs/secrets/) passively collects those declared files from the exact commit in `website/sources.lock.json`. Atlas owns discovery grouping/order; Website and Docs System own rendering, shared components, search, and feeds. Do not add a standalone docs deployer or put App credentials in this public repository. If Atlas catalogs a former Pages workflow, that file remains repository-owned validation: preserve its bespoke checks while keeping exact read-only permissions, an unconditional pull-request trigger, and no deployment primitives. Project Pages at `/secrets/` is only the generated redirect façade in `.github/workflows/b10x-docs-pages.yml`.

From a complete organization workspace, run `cargo run --manifest-path atlas/Cargo.toml -- docs reconcile --workspace . --check` to verify the contract. Keep internal plans, stories, ADRs, decisions, worklogs, security material, and research out of the public allowlist unless a repository authority explicitly declares them public.
<!-- b10x-docs-operations:end -->
