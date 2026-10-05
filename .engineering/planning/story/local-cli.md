---
format: aep.planning-md/3
id: story:local-cli
kind: story
status: implemented
title: The local CLI manages names, namespaces, mounts and bindings without printing a secret
relations:
- decomposes: epic:named-federated-storage
- derived_from: executable-system-specification:secrets-storage
- depends_on: story:mount-federation
- depends_on: story:keychain-backend
- depends_on: story:local-authorizer
scope:
- confidence: cited
  path: contracts/storage/scenarios/cli
- confidence: cited
  path: crates/secretsctl
revision: 10
transitions:
- {from: "draft", to: "proposed", at: "2026-10-05T11:50:40Z", actor: "human:timo", revision: 7, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "proposed", to: "active", at: "2026-10-05T11:50:40Z", actor: "human:timo", revision: 8, decided_on: {"recorded":{"review_outcome":1}}}
- {from: "active", to: "implemented", at: "2026-10-05T12:23:45Z", actor: "human:timo", revision: 10, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Context

`secretsctl` gains the local commands: put, describe, list, delete, rename,
namespace add|list|remove, mount set, bind, unbind. Configuration lives in
`$XDG_CONFIG_HOME/b10x-secrets/config.toml` and holds no secret.

## Acceptance

The `contracts/storage/scenarios/cli` scenario set passes against the real `secretsctl`
binary.

## Evidence

`spec/domains/storage.yaml` commands; operator decision that the CLI never prints a secret.

## Verification

Each behaviour named in Acceptance is an authored `ess-scenario/1` under the scenario directory
named in Scope, run by `checks/conformance` against the real library, three runs with identical
counts, zero failed, error, unsupported or skipped. Every guarded behaviour has a falsification
record: a deliberate defect in the source fails a named scenario, and the source is restored
byte for byte. No network, no credential and no paid call in the default gate.

## Scenarios

- one scenario per command: put, describe, list, delete, rename, namespace add|list|remove,
  mount set, bind, unbind
- put refuses a value passed in argv and accepts only a hidden prompt, a stdin FIFO or a
  protected file
- no command, under any flag, writes secret bytes to stdout or stderr

## Guards

The `contracts/storage/scenarios/cli` set (12 `ess-scenario/1` files) is synthesized beside the
library's generated scenarios into `contracts/cli-suite.json` and run by
`checks/conformance/src/cli.rs` against the built `secretsctl` (feature `test-hooks`), three runs
per `task check`. The same 12 files run in process in `contracts/storage-suite.json`.

Behaviours ESS cannot state are guarded by Rust tests in `crates/secretsctl/tests/cli.rs` that
run the binary:

- no secret bytes on stdout or stderr, under any command or flag, including refused command
  lines: `no_command_writes_secret_bytes_to_stdout_or_stderr`;
- a value in argv refused and nothing stored: `put_refuses_a_value_in_argv_and_stores_nothing`;
- a file its group or others can access refused, a mode-0600 file taken:
  `put_refuses_a_file_its_group_or_others_can_access_and_takes_a_protected_one`;
- stdin that is neither a terminal nor a pipe refused:
  `put_refuses_stdin_that_is_neither_a_terminal_nor_a_pipe`;
- the configuration written atomically with mode 0600 and holding no secret:
  `the_configuration_is_written_atomically_with_mode_0600_and_holds_no_secret`;
- a remote token from an environment variable or a protected file, never the configuration:
  `a_remote_token_comes_from_its_variable_or_a_protected_file_and_never_from_the_config`;
- the keychain unavailable without feature `native-keychain`:
  `without_the_native_keychain_feature_the_keychain_is_unavailable_and_says_why` (run by
  `task test` without that feature).

The hidden prompt (no echo) is `rpassword` on the controlling terminal; no headless test
drives a terminal.

Falsification (2026-10-05): each defect below was applied alone, the named test or scenario
failed, and the file was restored byte for byte (sha256 compared).

| Defect | Caught by |
|---|---|
| a refused command line rendered with clap's own message | `no_command_writes_secret_bytes_to_stdout_or_stderr` |
| the argv-value refusal skipped | `put_refuses_a_value_in_argv_and_stores_nothing` |
| the file-mode check masking nothing | `put_refuses_a_file_its_group_or_others_can_access_and_takes_a_protected_one` |
| a non-pipe stdin read anyway | `put_refuses_stdin_that_is_neither_a_terminal_nor_a_pipe` |
| the configuration written 0644 | `the_configuration_is_written_atomically_with_mode_0600_and_holds_no_secret`, `the_file_is_mode_0600_in_a_0700_directory_and_no_staging_file_is_left` |
| a token file read without its mode check | `a_remote_token_comes_from_its_variable_or_a_protected_file_and_never_from_the_config` |
| put printing `created` for a replace | `put-stores-a-secret-in-the-local-scope` |
| delete that removes nothing | `delete-removes-a-secret` |
| describe dropping the version | `describe-shows-the-name-scope-and-version-of-a-secret` |
| list keeping one row | `list-reads-the-secrets-of-a-namespace` |
| rename that copies and keeps the old name | `rename-moves-a-secret-to-a-new-name` |
| namespace add that adds nothing | `namespace-add-creates-a-namespace-once` |
| namespace list without mounts | `namespace-list-holds-every-namespace-with-its-mount` |
| namespace remove that removes nothing | `namespace-remove-refuses-default-and-a-namespace-in-use` |
| mount set ignoring the named mount | `mount-set-moves-a-namespace-to-another-backend` |
| bind that binds nothing | `bind-binds-a-name-once` |
| unbind that unbinds nothing | `unbind-removes-a-binding` |
| a configured remote backend never mounted | `a-namespace-on-the-remote-backend-round-trips` |
