---
format: aep.planning-md/2
id: review-result:nfs-scope-round-1
kind: review-result
status: active
title: Named federated storage, scope critic, round 1
relations:
- reviews: epic:named-federated-storage
- reviews: story:ess-custody-retrofit
- reviews: story:rewrap-all-versions
- reviews: story:verified-audit-actor
- reviews: story:storage-port
- reviews: story:local-authorizer
- reviews: story:mount-federation
- reviews: story:keychain-backend
- reviews: story:onepassword-backend
- reviews: story:remote-backend
- reviews: story:local-cli
revision: 1
---
approve

**What I read** — parent `epic:named-federated-storage` (full body) before opening any child; all 10 decomposing stories full bodies (`story:ess-custody-retrofit`, `story:keychain-backend`, `story:local-authorizer`, `story:local-cli`, `story:mount-federation`, `story:onepassword-backend`, `story:remote-backend`, `story:rewrap-all-versions`, `story:storage-port`, `story:verified-audit-actor`); `aep plan artifact graph` (confirmed no other artifact claims part of this epic, and none of the 10 double-claims a `decomposes` edge to it); `aep plan artifact kinds` / `relations`; `spec/domains/storage.yaml` (all 708 lines) and `spec/domains/custody.yaml` (grepped for defect/disagreement markers, 703 lines) for the entities, commands and coordinator decisions the epic derives from.

**Promise extraction (part 3):** 9 discrete promises drawn from the epic's Outcome + Acceptance before reading any story: (1) in-process library storing named secrets scoped by tenant/namespace/user, (2) one `SecretStorage` port, (3) three backends active at once — keychain, 1Password (read-only), custody service, (4) mount routing per namespace with no fallback, (5) local CLI manages names/namespaces/mounts/bindings, (6) CLI never prints secret bytes, (7) local mode is one tenant/user `default` with `default` as the default namespace, (8) `secrets.storage` suite passes including isolation scenarios, (9) `secrets.custody` suite passes against the shipped service. **9 of 9 traced** to at least one item: (1)/(2)→`story:storage-port`; (3)→`story:keychain-backend`, `story:onepassword-backend`, `story:remote-backend`; (4)→`story:mount-federation`; (5)/(6)→`story:local-cli`; (7)→`story:local-authorizer` (matching `spec/domains/storage.yaml`'s `LocalUser` actor and per-command `denied` guards); (8)→jointly `story:storage-port` + the three backend stories + `story:mount-federation`; (9)→`story:ess-custody-retrofit`, with its two prerequisite defect-fixes `story:rewrap-all-versions` and `story:verified-audit-actor` (both explicitly "found by the retrofit," required for the suite to pass, not extraneous work).

Also checked the epic's four named exclusions (Vault; Connectors; namespace-shared secrets with no owning user; the external authorizer/agent-platform round) against all 10 items — none is claimed. `story:local-authorizer` is a fixed local-only allow/deny rule matching the spec's `LocalUser` actor, not the excluded "authority service deciding `check(context, action, resource)`," so it does not reach into that exclusion. The epic's "linked in-process by consumers such as `llm`" is scene-setting: neither the epic's Acceptance nor `spec/domains/storage.yaml`'s `secrets-library` component asks for an actual `llm` migration, and `llm-credentials` appears only as an attribution/shape source for `story:keychain-backend` and `story:storage-port` — not a dropped promise.

No duplicate claims, no silent narrowing found among the 10.

**What I could not establish:** none.

```findings
[]
```
