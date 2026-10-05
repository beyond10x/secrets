---
format: aep.planning-md/3
id: review-result:nfs-design-round-2
kind: review-result
status: active
title: Named federated storage, design critic, round 2
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
Based on my read, the graph of the ten stories is unchanged from round 1 — every `depends_on` edge I traced back through `aep plan artifact history` on all ten stories was created in revision 1, before any of the eight bodies were revised. The revisions moved multi-clause acceptance language into per-story `## Scenarios` sections (answering the round-1 acceptance critic), which is not a shape change.

approve

What I read: all 10 stories in the set (`aep plan artifact show story:<id>` for ess-custody-retrofit, rewrap-all-versions, verified-audit-actor, storage-port, local-authorizer, mount-federation, keychain-backend, onepassword-backend, remote-backend, local-cli), the epic, `aep plan artifact relations`, `aep plan artifact graph --format json` (24 nodes, 82 edges — walked every `decomposes`/`derived_from`/`depends_on` edge among the set plus its two cited ESS specs and the two external `epic:encrypted-custody` stories `story:remote-backend`'s acceptance touches), `aep plan artifact validate` (`valid`, two pre-existing prose-only review-result notices, not mine to relay as findings), `aep plan artifact history` on every one of the 10 stories (to confirm which edges predate this round's body edits), `aep plan artifact findings story:local-cli`, `review-result:nfs-design-round-1` and `review-result:nfs-acceptance-round-1` in full, `aep plan artifact blocked` (nothing blocked), and `spec/domains/storage.yaml` lines 1–360 for the `Backend`/`BackendKind`/`SetMount` entities the "could-not-establish" note below turns on. No cycle (`ess-custody-retrofit` → `storage-port` → {`local-authorizer`,`mount-federation`,`keychain-backend`,`onepassword-backend`,`remote-backend`} → `local-cli` on 3 of the 5, plus two siblings off `ess-custody-retrofit` directly), no serializing chain, no split abstraction, no new hidden dependency.

What I could not establish: whether `story:local-cli` still hides a dependency on `story:onepassword-backend` and `story:remote-backend` — `spec/domains/storage.yaml:180-182` defers backend-instance *configuration* ("registered under a kind and label") entirely to local-cli's config file, and `SetMount`'s `no-backend` outcome (`spec/domains/storage.yaml:337`) presupposes that configuration exists for any of the three `BackendKind` variants — but this is unchanged from round 1 (`local-cli`'s Scope, Context and Acceptance carry the same generic wording review-result:nfs-design-round-1 already read and declined to cite), so I have nothing new to turn it into a citable finding. Separately, `story:remote-backend` is the one wave-3 backend sibling whose body carries no "`checks/conformance/src/target.rs` is coordinator-owned and pre-wired" note that its three siblings (`keychain-backend`, `onepassword-backend`, `mount-federation`) each added this round — that reads as an unlanded fix for the shared-file concern `review-result:nfs-parallel-safety-round-1` raised, but it is a "two items touch one file and do not say so" question, which is `plan-critic-parallel-safety`'s lane, not mine; I flag it only so it isn't lost, and it did not set my verdict. Whether the ten stories jointly cover the epic's acceptance is `plan-critic-scope`'s question, also not mine.

```findings
[]
```
