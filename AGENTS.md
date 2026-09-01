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

