# Integration contract for the GNS3 server and web UI

The registry is data. Consumers must validate it before activation and must never execute content from it.

## Fetching a release

Pin a tag; never fetch `main` in production.

```text
https://raw.githubusercontent.com/yueguobin/gns3-bpf-registry/gns3-bpf-registry-v<date>/registry/manifest.json
https://raw.githubusercontent.com/yueguobin/gns3-bpf-registry/gns3-bpf-registry-v<date>/schema/registry.schema.json
https://raw.githubusercontent.com/yueguobin/gns3-bpf-registry/gns3-bpf-registry-v<date>/registry/<entry>.json
```

1. Fetch the manifest.
2. Validate it against the schema.
3. For each `files` entry, fetch `registry/<name>`, compute its SHA-256 digest and compare it with the manifest value.
4. Validate every entry against the schema.
5. Validate every `locator` primitive and every `emit` template probe with `tcpdump -d`. The server has no field-selection compiler; compiler consistency is enforced separately by the web UI's golden-vector test suite.
6. Activate the version.

The manifest contains `schemaVersion`, `license`, `registryVersion` and `files` (one SHA-256 per file). The whole bundle — tools, prototype, registry entries, generated fixtures and vectors — is licensed GPL-3.0-only. Compare `registryVersion` to detect changes; do not depend on HTTP ETag behaviour.

## Activation

- Stage the release in a version directory, for example `.../registry/2026.11.0/`.
- Validate every file before switching.
- Switch atomically (rename or symlink swap).
- Keep the previous version for rollback.
- On any validation failure, keep the active version and discard the staged directory.

## Compiler contract

- Canonical clause order: VLAN slot, locator group, then fields in registry order.
- The golden vectors in `vectors/golden.json` are the byte-for-byte contract for the TypeScript compiler.
- `tcpdump -d` is the syntax authority. The server must re-run it on every expression it accepts from a client or from the registry.
- Keep `tcpdump`/libpcap versions aligned between the server and CI where possible; record the version in diagnostics.

## Versioning

- `schemaVersion` changes only for a schema break.
- `registryVersion` is `YYYY.MM.PATCH`; it counts content changes and does not need to match a tag date. Release tags are `gns3-bpf-registry-v<YYYY.MM.DD>` named after the actual day the tag is cut (daily or weekly cadence, at most one tag per day) and are immutable; tags up to `registry-v2026.11.6` use the legacy `registry-v` name.
- Additive entries are compatible. Changes to existing byte boundaries require a new registry version and two approvals; see `CONTRIBUTING.md`.

## Security

Registry files are untrusted input until validated. Do not evaluate expressions from the registry. Treat them as data, validate them with `tcpdump -d`, and enforce the file hashes from the manifest.

## Repository location

The source is currently `https://github.com/yueguobin/gns3-bpf-registry`. If the repository moves to the GNS3 organization, make the base URL configurable; the manifest and tags are the stable interface.
