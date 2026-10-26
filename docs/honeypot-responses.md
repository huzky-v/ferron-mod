# Configurable honeypot responses

Ferron supports two startup sources: a legacy SQLite database plus a template
directory, or a single ZIP bundle. In the legacy configuration, global
`honeypot_mode true` requires the **global** directive
`honeypot_templates_dir "/etc/ferron/honeypot-responses"`. The path must
be a nonempty string and must name a readable directory. `ban_mode` and
`honeypot_mode` are independent; when honeypot mode is false, templates are
not required or loaded. See [`ferron-abuse.conf`](ferron-abuse.conf) for a
tracked legacy configuration example. Other global directives include
`ban_mode`, `honeypot_mode`, `ban_duration`, and `audit_log`; the legacy source
uses `definitions_db` and optionally `definitions_url` (an HTTPS startup
source for definitions).

### ZIP bundle alternative

Set the optional global directive `definitions_bundle` to `"default"`, a
local ZIP path, or an HTTPS URL. `"default"` resolves to
`/var/lib/ferron/abuse-bundle.zip`. For example:

```text
definitions_bundle "default"
# Or: definitions_bundle "/path/to/abuse-bundle.zip"
# Or: definitions_bundle "https://security.example.invalid/abuse-bundle.zip"
```

When configured, the bundle silently takes precedence over legacy
`definitions_db`, `definitions_url`, and `honeypot_templates_dir` settings;
those settings do not provide a fallback. A failed remote bundle fetch fails
startup, even if an older bundle was previously available locally. The fixed
ZIP layout is:

```text
definitions.sqlite
honeypot-responses/<definition-name>.yaml
```

Place the SQLite database at the ZIP root as `definitions.sqlite` and the
matching YAML files under `honeypot-responses/`. The SQLite file must be
self-contained and checkpointed; do not package a database that needs an
external `-wal` file (and do not rely on an external `-shm` file). Whenever
the bundle is loaded, its archive structure, entry safety, entry types, and
size limits are validated. With `honeypot_mode false` and `ban_mode true`,
the database is validated, but YAML catalog/content validation is skipped;
response YAML files are not required. When both modes are false, the bundle
is not fetched or validated. With `honeypot_mode true`, provide one matching
YAML for each enabled `id_leak` definition as described below. See the
[Compose bundle alternative](../examples/docker-compose/README.md) for a
single read-only ZIP mount that does not run the legacy initializer.

## Loading and deployment

SQLite is authoritative for seed and definition information; YAML files supply
responses for the enabled `id_leak` definitions in that database. At startup
Ferron resolves one immutable SQLite definition snapshot, reads the legacy
response directory or bundled responses **once** when honeypot mode is
enabled, verifies that it contains exactly one `.yaml` file per enabled
`id_leak` definition, and constructs the policy with the validated catalog.
File names must be `<definition-name>.yaml`, and the
YAML `name` must equal the same unique definition name. No template is
required for scanner/other types or disabled definitions. Extra files,
unknown/retired names, duplicate/missing names, malformed YAML, unsupported
operators/references, or oversized possible responses fail startup. Request
handling never accesses the source directory or ZIP; runtime rendering errors
return 404 and never reach the protected application.

Neither runtime Docker image bundles YAML templates. For the legacy source,
`abuse-definitions-init <sqlite-path>` creates/validates the schema only; it
never inserts definitions.
Use `abuse-definitions-init --list-definitions <sqlite-path>` to inspect the
current rows read-only. Provision SQLite definition rows at `definitions_db`
separately, and mount an externally managed template directory read-only at
`honeypot_templates_dir`. The Compose example includes commands for creating
one rule and copying only its matching YAML into
`examples/docker-compose/honeypot-responses/`; Compose mounts it at
`/etc/ferron/honeypot-responses`. Add or update SQLite definition rows and
their corresponding YAML files **without rebuilding the binary or image**;
restart Ferron to load the new snapshot and catalog. For the legacy source,
the template directory and its ancestors are operator-trusted: protect
them from untrusted writers and do not put symlinks in the catalog (Unix final
components are opened without following symlinks).

## Version 1 YAML

Only the following top-level keys are accepted: `version: 1`, `name`,
`restype`, optional `variables`, and either `fields` for `restype: json` or
`template` and optional `content_type` for `restype: normal`. Unknown keys,
tags, and duplicate YAML keys are errors. Every `variables` entry is a named
expression, evaluated at most once per response (so repeated references
reuse the same generated value). Use `${name}` in strings, JSON keys, and
expression parameters; `$$` emits one literal `$`. No environment, file,
machine state, request headers, request path, or upstream data is interpolated.
Only references to declared variables are allowed; cycles are rejected.

JSON responses use recursively nested YAML maps, lists, booleans, numbers,
nulls and strings; strings and keys are JSON-escaped structurally, not spliced
as JSON text. Dynamic JSON keys must be the *sole key* in their object to
prevent collisions. The content type is always `application/json`:

```yaml
version: 1
name: id-leak-example-json
restype: json
variables:
  token: {op: chars, alphabet: abcdef0123456789, min: 16}
fields:
  credential: '${token}'
  enabled: true
  metadata: {roles: [reader, deployer], tries: 0}
```

Normal responses use a rendered UTF-8 string with a default content type of
`text/plain; charset=utf-8`; the only other permitted content type is
`application/yaml; charset=utf-8`. Status is always 200:

```yaml
version: 1
name: id-leak-example-normal
restype: normal
content_type: application/yaml; charset=utf-8
variables:
  region: {op: choice, values: [us-east-1, eu-west-1]}
template: |
  region: ${region}
```

### Variable operators

Each expression uses an `op` and **only** its documented keys:

| `op` | Keys | Result |
| --- | --- | --- |
| `format` | `value` | String with `${name}` substitutions. |
| `chars` | `alphabet`, `min`, optional `max` | Random ASCII characters; `min` is positive, default `max = min`, both lengths bounded. Alphabet is nonempty printable ASCII without `$`. |
| `integer` | `min`, `max`, optional `width` | Random inclusive unsigned integer, zero-padded to *at least* `width` digits if specified. |
| `choice` | `values` | One nonempty YAML string list's member; every arm is validated and bounded. |
| `bytes_base64` | `length` | Random bytes encoded as standard Base64. |
| `base64` | `value` | Standard Base64 encoding of a composed string. |
| `replace` | `value`, `from`, `to` | Replace occurrences in a composed string. `from` must be a nonempty **literal without `$`**; `to` may contain references. |
| `url_encode` | `value` | Percent-encode UTF-8 bytes except URL unreserved characters. |
| `pkcs8_rsa_pem` | none | Synthetic, **nonfunctional** PKCS#8 RSA-shaped private-key PEM (not a real credential). |

All choice arms, maximum random lengths, encoding growth, escaping, nested
JSON structure and repeated references are conservatively checked at startup.
There is no random sample validation. Files are capped at 64 KiB each, the
catalog at 1,024 files and 8 MiB total (also bounded by the configured
definition count), JSON nesting at 32, and variable count at 256 per file.
Rendered output is bounded by `Limits::max_honeypot_body_bytes` (16 KiB by
default, never over its 1 MiB hard limit), with a bounded JSON writer as
defense in depth.

To add a secret-discovery rule: create or edit a named `id_leak` definition
in the externally managed SQLite database, add one YAML file with the same
name in the mounted directory, and use the operators above. Adding rows and
templates requires no image rebuild. No new Rust code
is needed to change a match pattern or compose a response using existing
operators. A **new generator/operator** still requires code and a new build.
Do not add templates for retired definitions unless their `id_leak` rules
are active in the loaded database.

Domain-bearing synthetic responses use `${slug}.local` for generated local
hostnames and email domains (for example, `api.${slug}.local` and
`db.${slug}.local`). Use the same `slug` variable throughout one template so
its hostnames agree. Public provider endpoints needed to make a credential
format recognizable retain their actual provider names.

### Definition data

`definitions/docs/database/attack-definitions-snapshot-v1.sql` is the canonical, complete
definition snapshot. It includes the current accumulated honeypot decoys and
ban-only probes. Install it into a new SQLite database rather than applying it
to an existing definitions database. Deploy all matching
`definitions/honeypot-responses/id-leak-*.yaml` files with the database before enabling
honeypot mode. Snapshot integration coverage lives in
`definitions/tests/cases/snapshot-v1.yml`; common application routes,
`/var/run/secrets/kubernetes.io/serviceaccount/ca.crt`, and random PHP filenames
remain unmatched. See [`definitions/docs/database/README.md`](../definitions/docs/database/README.md).
