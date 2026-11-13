---
format: aep.planning-md/3
id: story:identity-origin-of-a-workload-only-deployment
kind: story
status: draft
title: The documentation says what a workload-only deployment sets as identity origin
revision: 1
---
## Why

`secrets serve` requires `--identity-origin` and `--identity-audience`
(`SECRETS_IDENTITY_ORIGIN`, `SECRETS_IDENTITY_AUDIENCE`): both are arguments without a default
in `crates/secrets-app/src/main.rs` (the `Serve` arguments, lines 45 to 48 at `v0.6.0`). A reader
of the source at that tag reports that only the four `/v1/user/secrets…` routes call the
identity origin, once per request, and that `GET /health/ready` checks PostgreSQL only
(`website/docs/operations.md`: "`204` when `SELECT 1` succeeds").

So a deployment that serves workloads only has to set an origin that no request of its own ever
reaches, and nothing tells its operator whether a made-up value is fine, whether the origin
must resolve, or whether the service will one day read it at its start.
`website/docs/operations.md` lists the two variables in its configuration table and says none
of this.

Read in the source, not run: whether the service starts with an origin that does not resolve
was not tried.

## Acceptance

- `website/docs/operations.md` says what a deployment without user routes sets for the two
  variables and what the service does with them: when the origin is called, and that readiness
  does not depend on it, or the opposite if that is what the code does.
- A test starts the service with an identity origin that answers nothing and shows what the
  page says: the workload routes answer, and a user route answers the error the page names.
- If the intended answer is that a workload-only deployment should not have to name an origin,
  the two arguments become optional and the user routes answer a declared error without them;
  the story says which was chosen.

## Notes

- Not decided: document the present behaviour, or make the two arguments optional.
