---
title: Roadmap
description: Planned, not shipped. Named, scoped secrets behind the OS keychain, read-only 1Password and the custody service, with a local CLI that never prints a secret.
sidebar_position: 10
---

# Roadmap

> **Planned, not shipped.** Nothing described here exists in a release yet. It describes the next
> milestone as it is specified today; names, commands and limits may change before it ships.

## Next milestone: named, scoped secrets across several backends

Today Secrets is a service reached over HTTP. The next milestone adds an in-process Rust library
that stores **named** secrets, such as `openai` or `team/openai`, for applications that link it,
and puts several storage backends behind one interface at once.

### Scope and names

- Every secret belongs to exactly one scope: a **tenant**, a **namespace** and a **user**, and is
  unique by scope plus name.
- Names are `/`-separated segments of `a-z`, `0-9`, `.`, `_` and `-`, each starting with a letter
  or digit; at most 128 bytes in total and 64 per segment. Tenant, namespace and user names are
  single segments.
- Values are at most 1 MiB.

### Backends

Each namespace is **mounted** on exactly one backend. Different namespaces can use different
backends at the same time; nothing falls back from one backend to another.

| Backend | Read | Write | Delete | List |
|---|---|---|---|---|
| OS keychain | yes | yes | yes | yes |
| 1Password | yes | no | no | no |
| The Secrets custody service | yes | yes | yes | yes |

An operation the mounted backend cannot perform is refused as `unsupported`. Because 1Password is
read-only, a name in a 1Password namespace must be **bound** to a locator such as
`op://<vault>/<item>/<field>` before it can be read. A custody-service backend maps a name to the
existing reference `{tenant, namespace, key = name}` with the scope's user as owner.

### Operations

The library accepts: add, remove and re-mount a namespace; bind and unbind a name; write, read,
delete and rename a secret; and list metadata (name, scope and an opaque version, never a value).
An authorizer decides every operation before any backend is called. Errors are closed codes with
no free text: `not-found`, `denied`, `unsupported`, `unavailable`, `invalid-name`, `too-large`
and `conflict`.

### Local mode and CLI

Local mode has one tenant and one user, both `default`, and a `default` namespace mounted on the
OS keychain, which cannot be removed. A local authorizer allows everything for that tenant and
user and denies every other one.

`secretsctl` gains local commands for names, namespaces, mounts and bindings: put, describe, list,
delete, rename, namespace add, list and remove, mount set, bind and unbind. The CLI **never prints a
secret**: no command, under any flag, writes secret bytes to standard output or standard error,
and put accepts a value only from a hidden prompt, a pipe or a protected file, never from a
command-line argument. Its configuration file holds no secret.

### Also in this milestone

The two defects in [Known limitations](limitations.md) are part of this milestone's plan: rewrap will
re-encrypt every stored version, and every audit event will record the verified principal.

### Not in this milestone

HashiCorp Vault as a backend, changes to Connectors, secrets shared by a whole namespace without an owning user, and an
external authorization service.
