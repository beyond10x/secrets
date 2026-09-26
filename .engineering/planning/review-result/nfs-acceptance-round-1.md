---
format: aep.planning-md/1
id: review-result:nfs-acceptance-round-1
kind: review-result
status: active
title: Named federated storage, acceptance critic, round 1
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
Wait — findings exist below, so:

needs-revision

story:ess-custody-retrofit — the acceptance joins two independently-failable claims with "and" (the 46+authored scenarios running through the in-memory fake and real HTTP handlers, and `task check` refusing suite drift, schema drift and any failed/error/unsupported/skipped scenario), so one can hold while the other does not — .engineering/planning/story/ess-custody-retrofit.md:35
story:keychain-backend — "The shared … scenarios pass … and backend errors surface only as closed codes" joins the scenario-pass outcome to a separate error-shape claim with "and"; a backend can pass the named scenarios while still leaking raw error text on an untested path — .engineering/planning/story/keychain-backend.md:27
story:local-cli — the acceptance is three claims joined by semicolons (command scenarios passing, put's input restricted to prompt/FIFO/protected file and never argv, no command writing secret bytes to stdout/stderr), each separately failable — .engineering/planning/story/local-cli.md:28
story:mount-federation — the acceptance is four routing rules joined by semicolons (not-found with no mount, unsupported on a read-only write, conflict on SetMount/RemoveNamespace/Bind/Rename, no request reaching a second backend), any one of which can pass while another fails — .engineering/planning/story/mount-federation.md:27
story:onepassword-backend — the acceptance is four claims joined by semicolons (read scenarios passing, write/delete/list unsupported, unbound name not-found with no transport call, no transport error text reaching a caller), independently checkable and independently failable — .engineering/planning/story/onepassword-backend.md:28
story:rewrap-all-versions — "every stored version … decrypts under the new key alone, and a named scenario fails when rewrap skips a non-current version" joins a production-behaviour claim to a separate test-design claim with "and"; the suite could be under-specified while the fix still holds, or vice versa — .engineering/planning/story/rewrap-all-versions.md:29
story:storage-port — the acceptance is four structural claims joined by semicolons (the named types existing, name/value limits enforced by name, secret bytes carrying no Debug/Display/Serialize, every StorageError a closed code with no free text), each separately failable — .engineering/planning/story/storage-port.md:31
story:verified-audit-actor — the acceptance is three claims (every event recording the verified principal, a differing-actor request being refused-or-recorded-beside, a named scenario failing when the caller-supplied actor replaces the verified one) joined by "and" and a semicolon, any one of which can hold while another does not — .engineering/planning/story/verified-audit-actor.md:29

What I read: the epic (`aep plan artifact show epic:named-federated-storage`), the full graph to identify the 10 `decomposes` edges (`aep plan artifact graph`), and the complete body of all 10 stories that decompose it (`aep plan artifact show story:<id>` for ess-custody-retrofit, keychain-backend, local-authorizer, local-cli, mount-federation, onepassword-backend, remote-backend, rewrap-all-versions, storage-port, verified-audit-actor) — 10 of 10. Also checked `aep plan artifact kinds` and `aep plan artifact lifecycle story`, and skimmed `spec/domains/storage.yaml` for scenario grouping.

What I could not establish: whether the ESS-synthesized scenario suites named in each story's Scope (e.g. "the shared `secrets.storage` backend scenarios") already exercise the appended clause as part of the same suite run, which would make the second clause redundant emphasis rather than a genuinely separable outcome — I did not map every scenario id in `spec/domains/storage.yaml`/`custody.yaml` to each clause. I treated `story:local-authorizer`'s allow/deny pairing and `story:remote-backend`'s mapping qualifier as a single total-behaviour statement rather than two independent outcomes; that line call is close enough to be worth another critic's eye. Whether the shared multi-clause phrasing across 8 of 10 stories reflects a single drafting template (a design/consistency question) rather than 8 independent defects is outside my lane — I note it but it does not change my per-artifact verdict.

```findings
[
 {
  "file": ".engineering/planning/story/ess-custody-retrofit.md",
  "line": 35,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance joins two independently-failable claims with \"and\" (the 46+authored scenarios running through the in-memory fake and real HTTP handlers, and `task check` refusing suite drift, schema drift and any failed/error/unsupported/skipped scenario), so one can hold while the other does not"
 },
 {
  "file": ".engineering/planning/story/keychain-backend.md",
  "line": 27,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "\"The shared … scenarios pass … and backend errors surface only as closed codes\" joins the scenario-pass outcome to a separate error-shape claim with \"and\"; a backend can pass the named scenarios while still leaking raw error text on an untested path"
 },
 {
  "file": ".engineering/planning/story/local-cli.md",
  "line": 28,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance is three claims joined by semicolons (command scenarios passing, put's input restricted to prompt/FIFO/protected file and never argv, no command writing secret bytes to stdout/stderr), each separately failable"
 },
 {
  "file": ".engineering/planning/story/mount-federation.md",
  "line": 27,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance is four routing rules joined by semicolons (not-found with no mount, unsupported on a read-only write, conflict on SetMount/RemoveNamespace/Bind/Rename, no request reaching a second backend), any one of which can pass while another fails"
 },
 {
  "file": ".engineering/planning/story/onepassword-backend.md",
  "line": 28,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance is four claims joined by semicolons (read scenarios passing, write/delete/list unsupported, unbound name not-found with no transport call, no transport error text reaching a caller), independently checkable and independently failable"
 },
 {
  "file": ".engineering/planning/story/rewrap-all-versions.md",
  "line": 29,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "\"every stored version … decrypts under the new key alone, and a named scenario fails when rewrap skips a non-current version\" joins a production-behaviour claim to a separate test-design claim with \"and\"; the suite could be under-specified while the fix still holds, or vice versa"
 },
 {
  "file": ".engineering/planning/story/storage-port.md",
  "line": 31,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance is four structural claims joined by semicolons (the named types existing, name/value limits enforced by name, secret bytes carrying no Debug/Display/Serialize, every StorageError a closed code with no free text), each separately failable"
 },
 {
  "file": ".engineering/planning/story/verified-audit-actor.md",
  "line": 29,
  "category": "acceptance",
  "severity": "blocker",
  "verdict": "needs-revision",
  "origin": "introduced",
  "message": "the acceptance is three claims (every event recording the verified principal, a differing-actor request being refused-or-recorded-beside, a named scenario failing when the caller-supplied actor replaces the verified one) joined by \"and\" and a semicolon, any one of which can hold while another does not"
 }
]
```
