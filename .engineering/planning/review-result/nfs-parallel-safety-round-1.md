---
format: aep.planning-md/3
id: review-result:nfs-parallel-safety-round-1
kind: review-result
status: active
title: Named federated storage, parallel-safety critic, round 1
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
needs-revision

story:keychain-backend — this story and its wave-3 siblings story:mount-federation, story:onepassword-backend and story:remote-backend each add a new per-backend harness file under the `checks/conformance` runner that story:ess-custody-retrofit builds in wave 1, and none of the four bodies names the file that registers a new backend's harness with that runner, so a same-wave shared entrypoint goes unnamed if one exists — inferred, since `checks/conformance` is not yet in the tree to confirm the registration mechanism either way — `aep plan artifact show story:keychain-backend` (scope line `checks/conformance/src/keychain.rs`, inferred); `find . -iname "checks*" -o -iname "*conformance*"` returns nothing in the worktree

What I read: 10 story artifacts (`aep plan artifact show` on each of the 10 `story:*` ids listed by `aep plan artifact list --kind story --status draft`), the epic (`aep plan artifact show epic:named-federated-storage`), the computed wave/collision output (`aep plan artifact waves --kind story --status draft`), the workspace `Cargo.toml` members list, and spot-checked source lines cited by `story:verified-audit-actor` and `story:ess-custody-retrofit`/`story:rewrap-all-versions` (`crates/secrets-postgres/src/lib.rs:150-160`, `crates/secrets-http/src/lib.rs:90-112,260-285`) against the actual tree to confirm the cited lines are real. Surface placement: 10 cited, 0 inferred-only, 0 unplaceable — every story has at least one body-cited path grounding it.

The one collision the CLI itself reports (`story:rewrap-all-versions` × `story:verified-audit-actor` on `crates/secrets-postgres/src/lib.rs`) is not repeated here: it is already resolved by wave placement (wave 2 vs wave 3), which is exactly what the wave computation is for, per the rubric's "already reports" exclusion. The four new crates each wave-3 backend story creates (`secrets-keychain`, `secrets-federation`, `secrets-onepassword`, `secrets-remote`) and their need to join the workspace `Cargo.toml` is excluded per this task's own framing (coordinator-owned by convention, not scoped to units), so I did not flag it.

What I could not establish: whether `checks/conformance` will in fact need a shared registration file per backend, or use an auto-discovery pattern (e.g. `inventory`-style registration) that avoids the shared-file touch entirely — the crate does not exist yet in this worktree, so this rests on Rust-idiom inference, not a citation, and is flagged as such above rather than asserted as certain. Out of my lane, not affecting my verdict: whether `mount-federation`'s conformance scenarios need a real keychain/onepassword/remote backend instance (a missing `depends_on` edge, if so) is a design/scope question, not a file-collision one — I found no evidence either way and leave it to `plan-critic-design`/`plan-critic-scope`.

```findings
[
 {
  "file": "find . -iname \"checks*\" -o -iname \"*conformance*\"",
  "category": "parallel-safety",
  "severity": "warning",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "story:keychain-backend and its wave-3 siblings story:mount-federation, story:onepassword-backend and story:remote-backend each add a new per-backend harness file under the checks/conformance runner story:ess-custody-retrofit builds in wave 1, and none of the four bodies names the file that registers a new backend's harness with that runner, so a same-wave shared entrypoint goes unnamed if one exists (inferred: checks/conformance is not yet in the tree to confirm the registration mechanism either way)"
 }
]
```
