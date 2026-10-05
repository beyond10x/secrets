---
format: aep.planning-md/3
id: review-result:nfs-scope-round-2
kind: review-result
status: active
title: Named federated storage, scope critic, round 2
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

**What I read** — parent `epic:named-federated-storage` full body first (`aep plan artifact show epic:named-federated-storage`), extracting its promises before opening any item; all 10 decomposing stories full bodies at their current revisions (`story:ess-custody-retrofit` rev7, `story:storage-port` rev5, `story:keychain-backend` rev6, `story:onepassword-backend` rev6, `story:remote-backend` rev4, `story:mount-federation` rev6, `story:local-authorizer` rev2, `story:local-cli` rev6, `story:rewrap-all-versions` rev5, `story:verified-audit-actor` rev4); `aep plan artifact graph` (confirms exactly these 10 `decomposes` edges into the epic, none elsewhere); `aep plan artifact history story:<id>` on all 10 to see which were revised since round 1 and when; `aep plan artifact show review-result:nfs-scope-round-1`, `-design-round-1`, `-acceptance-round-1`, `-parallel-safety-round-1` (round-1 context, not binding on my verdict); `aep plan artifact kinds`, `relations`, `validate`.

**Promise extraction (part 3):** 9 discrete promises from the epic's Outcome + Acceptance: (1) in-process library storing named secrets scoped by tenant/namespace/user, (2) one `SecretStorage` port, (3) three backends active at once — keychain, 1Password (read-only), custody service, (4) mount routing per namespace with no fallback, (5) local CLI manages names/namespaces/mounts/bindings, (6) CLI never prints secret bytes, (7) local mode is one tenant/user `default` with `default` as the default namespace, (8) `secrets.storage` suite passes with every backend it mounts including isolation scenarios, (9) `secrets.custody` suite passes against the shipped service. **9 of 9 traced**: (1)/(2) → `story:storage-port`; (3) → `story:keychain-backend` + `story:onepassword-backend` + `story:remote-backend`; (4) → `story:mount-federation`; (5)/(6) → `story:local-cli`; (7) → `story:local-authorizer`; (8) → jointly `story:storage-port` + the three backend stories + `story:mount-federation` (isolation scenario explicit in `story:keychain-backend`'s Scenarios, and `story:remote-backend`'s Acceptance invokes "the shared `secrets.storage` scenarios" directly); (9) → `story:ess-custody-retrofit` with its two retrofit-found prerequisite fixes `story:rewrap-all-versions` and `story:verified-audit-actor`.

The 8 stories revised since round 1 (`ess-custody-retrofit`, `keychain-backend`, `local-cli`, `mount-federation`, `onepassword-backend`, `rewrap-all-versions`, `storage-port`, `verified-audit-actor`) all responded to `acceptance-round-1` (splitting compound Acceptance clauses into separate `## Scenarios` bullets) and, for `keychain-backend`/its wave-3 siblings, `parallel-safety-round-1` (naming `checks/conformance/src/target.rs` as the coordinator-owned dispatch point). I checked each split against its pre-split compound claim from `review-result:nfs-acceptance-round-1`'s findings and confirmed every clause survived the split with no clause dropped, and no new claim introduced that reaches past the epic. `story:local-authorizer` and `story:remote-backend` were not flagged in round 1 and are unrevised (rev2, rev4). The epic's four named exclusions (Vault; Connectors; namespace-shared secrets with no owning user; the external authorizer/agent-platform round) are claimed by none of the 10. No two items claim the same outcome; no promise is narrowed without saying so.

**What I could not establish:** whether `story:onepassword-backend`'s backend-specific scenario directory (rather than "the shared … scenarios" phrasing `story:remote-backend` and `story:keychain-backend` use) means its slice of the isolation-scenario promise (8) rests on binding-level scoping enforced elsewhere rather than its own conformance run — I could not turn this into a citable narrowing under the rubric's bar, since the epic does not require isolation testing inside every individual backend module, only that the overall suite include it. Whether that overall suite composition is sound is closer to `plan-critic-design`'s lane (the design critic already flagged the general coverage question as its own, in `review-result:nfs-design-round-1`) and I leave it there.

```findings
[]
```
