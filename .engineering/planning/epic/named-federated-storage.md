---
format: aep.planning-md/3
id: epic:named-federated-storage
kind: epic
status: draft
title: Named, scoped secrets behind several storage backends at once
summary: One SecretStorage port, mount routing per namespace, keychain, 1Password and the custody service as backends, a local CLI.
relations:
- derived_from: executable-system-specification:secrets-storage
revision: 1
---
## Outcome

A library, linked in-process by consumers such as `llm`, stores named secrets (`openai`,
`openai-work`) scoped by tenant, namespace and user, behind one `SecretStorage` port with several
backends active at once: the OS keychain, 1Password (read-only) and the existing custody service.
Each namespace routes to exactly one backend; nothing falls back to another. A local CLI manages
names, namespaces, mounts and bindings and never prints secret bytes. Local mode is one tenant and
one user, both `default`, with `default` as the default namespace.

## Acceptance

The `secrets.storage` conformance suite passes against the library with every backend it mounts,
including the tenant-, namespace- and user-isolation scenarios, and the `secrets.custody` suite
passes against the shipped service.

## Evidence

- `spec/domains/storage.yaml` — the model, with the coordinator decisions of 2026-09-27 and the
  remaining `UNMAPPED:` markers.
- `spec/domains/custody.yaml` — the retrofit of the shipped service, every declaration citing its
  source.
- Operator decisions, 2026-09-26/27: mount routing with no fallback; 1Password read-only; library
  in-process with the service as one backend; the CLI never prints a secret; Vault and Connectors
  out of scope this round.

## Out of scope

Vault; Connectors; namespace-shared secrets with no owning user; the external authorizer (an
authority service deciding `check(context, action, resource)`), which is the agent-platform round.
