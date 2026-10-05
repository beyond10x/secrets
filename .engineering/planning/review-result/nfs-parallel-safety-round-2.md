---
format: aep.planning-md/3
id: review-result:nfs-parallel-safety-round-2
kind: review-result
status: active
title: Named federated storage, parallel-safety critic, round 2
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
`needs-revision`

story:remote-backend — body still does not name `checks/conformance/src/target.rs` as the coordinator-owned, pre-wired registration point for its wave-3 backend harness, unlike its three wave-3 siblings (`story:keychain-backend`, `story:mount-federation`, `story:onepassword-backend`), each of which added that exact sentence after `review-result:nfs-parallel-safety-round-1`; `remote-backend`'s body has no `## Scenarios` section at all, so if it in fact touches the shared runner file the same way its siblings could have (before their fix), that collision with the other three concurrent wave-3 stories is still unnamed — cited (scope path `checks/conformance/src/remote.rs` is body-cited; the missing sentence is confirmed absent by `aep plan artifact show story:remote-backend`, compared against `aep plan artifact show story:keychain-backend`)

What I read: all 10 draft stories under `epic:named-federated-storage` via `aep plan artifact show` on each (`ess-custody-retrofit`, `rewrap-all-versions`, `storage-port`, `keychain-backend`, `local-authorizer`, `mount-federation`, `onepassword-backend`, `remote-backend`, `verified-audit-actor`, `local-cli`), the epic body, the computed `aep plan artifact waves --kind story --status draft` output (4 waves, 1 collision, 0 unassessed), the round-1 parallel-safety review-result (`review-result:nfs-parallel-safety-round-1`), and the tree state (`find . -iname "checks*" -o -iname "*conformance*"`, `crates/*`, `Cargo.toml` members) to confirm `checks/conformance` and the four new backend crates (`secrets-keychain`, `secrets-federation`, `secrets-onepassword`, `secrets-remote`) do not yet exist. Surface placement: 10 cited, 0 inferred-only, 0 unplaceable — every story has at least one body-cited path grounding it, several also carry additional inferred entries the CLI marks weaker.

The one collision the CLI reports (`story:rewrap-all-versions` × `story:verified-audit-actor`, both citing `crates/secrets-postgres/src/lib.rs`) is not a finding: `waves` places them in wave 2 and wave 3 respectively (sequenced, not concurrent), which is exactly what the wave computation resolves. Cross-checked the six wave-3 stories (`keychain-backend`, `local-authorizer`, `mount-federation`, `onepassword-backend`, `remote-backend`, `verified-audit-actor`) pairwise by scope path and found no overlap among them; likewise wave 2 (`rewrap-all-versions`, `storage-port`) has none. Per this task's own framing, `Cargo.toml`, `Cargo.lock`, the four `contracts/` files, and `checks/conformance/src/target.rs` are coordinator-owned and pre-wired at each wave's opening, so the four new crates joining the workspace and the four backend stories' hooks into `target.rs` are not treated as collisions here.

What I could not establish: whether `remote-backend`'s actual implementation touches `checks/conformance/src/target.rs` directly (the crate doesn't exist yet, so this rests on the same inference the round-1 finding rested on, not a citation) — flagged as such above rather than asserted as certain. Out of my lane, not affecting my verdict: `remote-backend` and `local-authorizer` are the only two wave-3 stories with no `## Scenarios` section at all, which may be an acceptance- or design-critic concern about coverage/completeness rather than a file-collision one; I leave that to `plan-critic-acceptance`/`plan-critic-design`.

```findings
[{"file": "aep plan artifact show story:remote-backend", "category": "parallel-safety", "severity": "warning", "verdict": "needs-revision", "origin": "pre-existing", "message": "story:remote-backend and its wave-3 siblings story:keychain-backend, story:mount-federation and story:onepassword-backend were all named in review-result:nfs-parallel-safety-round-1 for not naming the file that registers a new backend's harness with the checks/conformance runner; three of the four bodies now state that checks/conformance/src/target.rs is coordinator-owned and pre-wired at each wave's opening, but story:remote-backend's body still has no such statement and no Scenarios section at all, so whether it touches the shared runner file when run concurrently with its wave-3 siblings remains unnamed (inferred: checks/conformance does not yet exist in the tree to confirm the registration mechanism either way)"}]
```
