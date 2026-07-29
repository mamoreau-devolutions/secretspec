---
title: Devolutions Provider
description: Devolutions Server, Cloud, and SQLite secret entry integration through the devo CLI
---

The Devolutions provider reads existing secret entry data properties through the
`devo` CLI. Devolutions Server supports updates, and supported local RDM SQLite
workspaces can update an entry's `password`; Devolutions Cloud (Hub) is read-only.

:::note[Version compatibility]
The Devolutions provider is an upcoming SecretSpec 0.20 feature and is not
available in SecretSpec 0.19.
:::

## At a glance

| | |
| --- | --- |
| Provider | `devo` |
| Sources | Devolutions Server, Devolutions Cloud (Hub), and local RDM SQLite |
| Access | Server: read/write; SQLite: `password` read/write; Cloud: read-only |
| Best for | Existing team or local RDM entry secrets |
| Authentication | Saved Server or Cloud context, or the selected local RDM workspace |
| Availability | Upcoming in SecretSpec 0.20 |
| Default storage | None; every secret names an explicit entry ID and data property |

## Quick start: Devolutions Server

Declare a Devolutions Server vault and point each secret at its existing entry:

```toml title="secretspec.toml"
[providers]
production = "devo://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"

[profiles.production]
DATABASE_URL = { description = "Production database", ref = { item = "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124", field = "Password" }, providers = ["production"] }
```

```bash
# Get the existing entry property.
$ secretspec get DATABASE_URL --profile production

# Update that property in place.
$ secretspec set DATABASE_URL --profile production

# Run with the resolved value injected as DATABASE_URL.
$ secretspec run --profile production -- deploy
```

## Setup

### Prerequisites

- A `devo` CLI version that includes the `server secret`, `cloud secret`, and
  `sqlite secret` commands, including `sqlite secret set` for local password
  updates
- A saved Server or Cloud context, or a configured local RDM workspace,
  appropriate to the source in the provider URI

### Source selection

SecretSpec selects the source explicitly in the provider URI. It never guesses
an RDM workspace from the current daemon context.

| Source | URI | CLI command | Access |
| --- | --- | --- | --- |
| Devolutions Server (DVLS) | `devo://[context@][vault-guid]` or `devo+server://[context@][vault-guid]` | `devo server secret` | Read/write |
| Devolutions Cloud (Hub) | `devo+cloud://[context@][vault-guid]` | `devo cloud secret` | Read-only |
| Local RDM SQLite | `devo+sqlite://[vault-guid]?datasource=<datasource-id>` | `devo sqlite secret get` / `set` | `password` only |

`devo+hub` is accepted as a compatibility alias for `devo+cloud`, but new
configuration should use `devo+cloud`.

For Server, `context` is a saved `devo server` context and is passed as the
command's optional positional context. Its API-key, credential, OAuth, or
Windows authentication needs sensitive-field permission to read and entry-edit
permission to write. Server uses its direct Devolutions Server connection and
does not derive its context from RDM workspace or source selection.

For Cloud, `context` is a saved direct `devo cloud` context. Omit it to use the
current Cloud context. Cloud entries support only the CLI's supported fields:
`domain`, `host`, `password`, `port`, `privatekey` (or `private-key`), `url`,
and `username`. `private_key` and `user` are also accepted aliases.

For SQLite, configure an eligible local RDM profile with an existing plaintext
SQLite datasource. SecretSpec runs its child command with
`DEVO_RDM_CLOUD_SOURCE=sqlite`, which satisfies the standalone CLI's source
selection requirement and prevents an inherited `hub` or `server` selector
from redirecting the operation.

## Configuration

### URI formats

```text
devo://[server-context@][vault-guid]
devo+server://[server-context@][vault-guid]
devo+cloud://[cloud-context@][vault-guid]
devo+sqlite://[vault-guid]?datasource=<canonical-datasource-id>
```

All URI forms accept an optional default vault. When it is omitted, every
secret `ref` must supply `vault`.

The SQLite `datasource` query value is required. It is the decoded datasource
component reported by `devo entry references`, not a full `devo://` reference.
For example, a reference beginning
`devo://ds/sqlite%3AConnections.db/vault/...` uses
`?datasource=sqlite:Connections.db`.

### Project configuration

Keep the source, vault, and optional context mapping in checked-in provider
aliases:

```toml title="secretspec.toml"
[providers]
prod_server = "devo+server://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"
cloud = "devo+cloud://deploy@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"
local = "devo+sqlite://e20ad6fb-e991-4f1e-84a0-b12e63832f3a?datasource=sqlite:Connections.db"

[profiles.production]
API_TOKEN = { description = "Deployment token", ref = { item = "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124", field = "ApiKey" }, providers = ["prod_server"] }
```

### SQLite passphrase credential

SQLite password updates require the workspace's Shared passphrase. Prefer an
alias-scoped `passphrase` [provider credential](/concepts/providers/#provider-credentials)
so SecretSpec can retrieve it from a secure store:

```toml title="secretspec.toml"
[providers]
keyring = "keyring://"
local = { uri = "devo+sqlite://e20ad6fb-e991-4f1e-84a0-b12e63832f3a?datasource=sqlite:Connections.db", credentials = { passphrase = "keyring" } }
```

The example reads `passphrase` from keyring at SecretSpec's conventional
credential address. Use an explicit credential `ref` when it is stored
elsewhere. For a direct URI or CI setup, `DEVO_SQLITE_PASSPHRASE` is the
fallback environment variable; an alias credential takes precedence. SecretSpec
copies the resolved passphrase only to the `devo` child environment and removes
the fallback variable from that child.

## Storage model

Every source addresses an entry by ID, not by a unique name. SecretSpec
therefore has no convention path such as
`secretspec/{project}/{profile}/{key}` for this provider. Each secret must use
a [`ref`](/reference/configuration/#secret-references):

- `item`: required entry ID
- `field`: required data-property name on that entry
- `vault`: optional vault ID that overrides the provider URI's default vault,
  and required when the URI omits one

For SQLite, the provider URI supplies the required datasource ID. Do not put a
full `devo://` reference in `item`, `vault`, or `field`; use the individual
decoded components returned by `devo entry references`.

### Server reads and writes

Server reads invoke:

```text
devo server secret get [context] --vault-id <vault-guid> --entry-id <entry-guid> --field <data-property>
```

Server writes invoke:

```text
devo server secret set [context] --vault-id <vault-guid> --entry-id <entry-guid> --field <data-property> --value-env <child-env-var> --yes
```

The CLI writes an exact read value to stdout without adding a newline.
SecretSpec preserves leading, trailing, and multiline whitespace. For writes,
it passes the value through a child-only environment variable, never a
command-line argument or diagnostic.

### Cloud reads

Cloud reads invoke:

```text
devo cloud secret get [context] --vault-id <vault-guid> --entry-id <entry-guid> --field <data-property>
```

Cloud is read-only: `secretspec set` reports
`cloudSecretWriteUnsupported` before prompting for a value.

### SQLite reads and password updates

SQLite reads invoke:

```text
devo sqlite secret get --datasource-id <datasource-id> --vault-id <vault-id> --entry-id <entry-id> --field <field>
```

SQLite reads return exact text on stdout without an added newline. SQLite
updates are limited to a native reference whose field is exactly `password`.
SecretSpec requires a configured passphrase before prompting for a replacement
value, then invokes:

```text
devo sqlite secret set --datasource-id <datasource-id> --vault-id <vault-id> --entry-id <entry-id> --field password --passphrase-env <child-passphrase-env> --value-env <child-value-env> --yes
```

Both secret values are child-only environment variables, never command-line
arguments or diagnostics. On success, the Devo CLI writes only `Secret:
updated`; it does not echo either value. The CLI accepts `--workspace-id` as an
alias for `--datasource-id`, but SecretSpec always passes the canonical
datasource ID from the provider URI.

## Use existing secrets

Every Devolutions provider secret is an existing secret reference:

```toml
[profiles.production]
DATABASE_URL = { description = "Postgres DSN", ref = { item = "ff676a0a-0b5b-4d31-ae2e-4cc34f56a124", field = "ConnectionString" }, providers = ["devo+server://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"] }

# Override the alias's vault for this entry.
SENTRY_DSN = { description = "Sentry DSN", ref = { vault = "3f2bcfbb-a7fe-4cf7-9c21-b329e8c07d70", item = "4cf2e7b1-a0f7-4cfd-94b7-4e34851c0089", field = "Dsn" }, providers = ["devo+cloud://production@e20ad6fb-e991-4f1e-84a0-b12e63832f3a"] }
```

SecretSpec never creates an entry or tries to resolve a name to an entry ID.

## CI/CD

Set up a non-interactive saved context before using a Server or Cloud URI:

```bash
$ secretspec run --profile production --provider "devo+server://ci@e20ad6fb-e991-4f1e-84a0-b12e63832f3a" -- deploy
```

SQLite reads and updates in CI require a configured eligible local SQLite
profile. Configure the `passphrase` credential through an alias where possible;
otherwise provide `DEVO_SQLITE_PASSPHRASE` only to the SecretSpec process.
Grant each source only the vault, entry, and sensitive-field permissions the
deployment needs.

## Troubleshooting and limitations

- Vault and entry IDs are required; the provider never guesses an entry from a
  title.
- Server supports writes, except that the Devolutions Server Public API cannot
  write PAM vault entries. Reads still work with sensitive-field permission.
- Cloud is read-only. `cloudSecretWriteUnsupported` is surfaced before a value
  is read.
- SQLite updates require exactly `ref.field = "password"` and a non-empty
  `passphrase` provider credential or `DEVO_SQLITE_PASSPHRASE`. SecretSpec
  returns `sqliteSecretFieldUnsupported` or `sqlitePassphraseRequired` before
  asking for the replacement value when either requirement is unmet.
- SQLite mutation is deliberately fail-closed: it supports only a plaintext
  SQLite format-3 container at database version 155 or later with an exact
  Shared passphrase v2 payload. Application passwords, unsafe or clear-text
  mirrors, external credentials, non-profile-root child files, reparse-point
  or alternate-data-stream ambiguity, and checkout/check-in lifecycle entries
  are unsupported. The Devo CLI also rejects unavailable runtimes, missing
  exact datasource/vault/entry IDs, conflicts, and persistence failures rather
  than bypassing RDM's lifecycle or policy checks.
- Missing secrets remain eligible for SecretSpec provider fallback chains.
- Generic `devo secret` and MCP DVLS reference resolution are not supported.
- Override the CLI path with `SECRETSPEC_DEVO_CLI_PATH` when `devo` is not on
  `PATH`.
