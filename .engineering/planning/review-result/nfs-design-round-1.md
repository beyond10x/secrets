---
format: aep.planning-md/3
id: review-result:nfs-design-round-1
kind: review-result
status: active
title: Named federated storage, design critic, round 1
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
approve — the ten stories form a clean two-root DAG (`story:ess-custody-retrofit` and, downstream of it, `story:storage-port`) that fans out into independently verifiable branches and fans back in only at `story:local-cli`; no cycle, no full serializing queue, and no seam where two bodies describe halves of one abstraction.

What I read: all 10 stories (`aep plan artifact show` on each), the epic (`aep plan artifact show epic:named-federated-storage`), both cited ESS specs' relevant sections (`spec/domains/storage.yaml` lines 1–330, entity/UNMAPPED notes on `Backend` and `Namespace`), `aep plan artifact relations`, `aep plan artifact graph --format json` and its Graphviz form, and `aep plan artifact validate` (reports `valid`, no findings to relay). I walked every edge touching the 10 in-set stories plus the 3 external nodes they point to (the epic and the two `executable-system-specification` artifacts) — 24 edges among the set, plus the epic's own `derived_from` — and separately confirmed via the full graph dump (19 nodes, 33 edges total in the store) that nothing outside the named set feeds back into it. Each of the 9 non-root stories declares exactly the `depends_on` edges consistent with its body's own citations (interface-then-implementation direction: `storage-port` before the five backends/router, `mount-federation`+`keychain-backend`+`local-authorizer` before `local-cli`, `ess-custody-retrofit` before the two custody-defect fixes).

What I could not establish: whether `story:local-cli`'s outcome silently depends on `story:onepassword-backend` and `story:remote-backend` — `spec/domains/storage.yaml`'s `Backend` entity note says backend-instance registration "under a kind and label" is deferred to `story:local-cli`'s config file, and the CLI's own `mount set` command must eventually route to all three `BackendKind` variants — but `story:local-cli`'s Acceptance is written generically enough (no command named, no backend kind named) that its stated outcome does not, on its face, require naming those two stories' internals, so I could not turn this into a citable hidden-dependency finding under the rubric's bar. Whether the union of the 10 stories actually satisfies the epic's acceptance ("passes … with every backend it mounts") is a coverage question for `plan-critic-scope`, not mine; I note it only so it isn't lost between critics, and it did not affect this verdict.

```findings
[]
```
