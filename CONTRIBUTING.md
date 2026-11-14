# Contributing

## The six governance rules

1. New protocol: submit the entry JSON and its fixtures. A green CI run is enough for a single-curator merge. This is the normal path and should stay fast.
2. Changing an existing field's byte boundaries (`offset`, `size`, `mask`, `shift`): open an issue with evidence (RFC text or a capture), get the curator plus a second approval, and bump `registryVersion`. Never edit a field silently.
3. Published tags are immutable. Fix mistakes in a new version; never force-push or re-create a tag.
4. Generated artifacts (`registry/manifest.json`, `fixtures/**`, `vectors/golden.json`) must not be edited by hand. CI regenerates and diffs them.
5. Every field needs a verifiable `ref` (an RFC section, or IEEE 802.3/802.1Q where no RFC applies).
6. Review checks three things: the citation, the positive/negative fixtures and the CI output.

## Adding a protocol

1. Add a probe recipe for the protocol to `tools/auto_draft.py`: a packet builder with every computed field pinned (`chksum=0x1234`), the fixed header length, and max-contrast sentinels per field (`0x0F0F0F` vs `0xF0F0F0`). Run `.venv/bin/python tools/auto_draft.py --draft --entry <id>` and confirm the probed offsets against the RFC header diagram before writing anything by hand. Variable-length and conditional fields come back as `needs_human`; classify them yourself.
2. Add `registry/<id>.json` following `schema/registry.schema.json`. The draft skeleton is a starting point, not a drop-in: complete every `TODO` (label, `ref`, `kind` and its payload, `locator`) — drafts get no governance exemption.
3. Add the protocol's fixture construction to `tools/make_fixtures.py`: a packet builder and canonical positive/negative values for every field. Add sentinel values to `tools/crosscheck.py` as well.
4. Add golden vectors for every new field to `tools/make_vectors.py`.
5. Run:

   ```sh
   .venv/bin/python tools/make_fixtures.py
   .venv/bin/python tools/make_manifest.py
   .venv/bin/python tools/make_vectors.py
   .venv/bin/python tools/crosscheck.py
   .venv/bin/python tools/auto_draft.py --check
   .venv/bin/python tools/verify.py
   ```

6. Commit the entry and the regenerated manifest, fixtures and vectors.

## Changing an existing field

Follow rule 2. In addition, update the field's fixture values, the sentinel in `crosscheck.py`, and the golden vector. Explain in the pull request why the previous offset was wrong.

## Generated artifacts

- `registry/manifest.json` is produced by `tools/make_manifest.py`.
- `fixtures/**/*.pcap` are produced by `tools/make_fixtures.py`.
- `vectors/golden.json` is produced by `tools/make_vectors.py`.
- All three commands accept `--check`, which CI runs on every pull request and push.

## Review checklist

- [ ] Every field has a `ref`.
- [ ] The positive fixture matches and the negative fixture does not.
- [ ] `crosscheck.py`, `auto_draft.py --check`, `verify.py` and all three `--check` commands pass.
- [ ] Byte-boundary changes have an issue, evidence, two approvals and a version bump.
- [ ] No generated file was hand-edited.

## Local setup

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python tools/verify.py
```

`tcpdump` must be installed and on `PATH`. CI uses Ubuntu 24.04's tcpdump; record the version in the pull request if you see a syntax difference.
