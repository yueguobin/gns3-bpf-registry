# Contributing

## The six governance rules

1. New protocol: submit the entry JSON and its fixtures. A green CI run is enough for a single-curator merge. This is the normal path and should stay fast.
2. Changing an existing field's byte boundaries (`offset`, `size`, `mask`, `shift`): open an issue with evidence (RFC text or a capture), get the curator plus a second approval, and bump `registryVersion`. Never edit a field silently.
3. Published tags are immutable. Fix mistakes in a new version; never force-push or re-create a tag.
4. Generated artifacts (`registry/manifest.json`, `fixtures/**`, `vectors/golden.json`) must not be edited by hand. CI regenerates and diffs them.
5. Every field needs a verifiable `ref` (an RFC section, or IEEE 802.3/802.1Q where no RFC applies).
6. Review checks three things: the citation, the positive/negative fixtures and the CI output.

## Adding a protocol

1. Seed drafts from scapy metadata (probe-first; the differential probe corrects whatever `fields_desc` gets wrong):

   ```sh
   .venv/bin/python tools/seed_draft.py --class <Class> --under ip:89 --write
   ```

   Then complete the semantics in `drafts/<id>.json` (labels, refs, enum labels, exclusions with reasons) and polish `recipes/<id>.json`. Writing recipes by hand is still fine: packet stack bottom-up with every computed field pinned (`"chksum": "$PIN"`), the fixed header length, renames in `fieldMap` (qualify as `Layer.name` when two layers share a kwarg), max-contrast probe sentinels, and a `manual` section with a reason for fields the probe cannot derive. Fill in the `crosscheck`, `fixtures` and `vectors` tables — they are the ones every tool consumes. The probed layer must be last in the stack.
2. Run `.venv/bin/python tools/auto_draft.py --draft --entry <id>` and confirm the probed offsets against the RFC header diagram before writing anything by hand. Variable-length and conditional fields come back as `needs_human`; classify them yourself.
3. Add `registry/<id>.json` following `schema/registry.schema.json`. The draft skeleton is a starting point, not a drop-in: complete every `TODO` (label, `ref`, `kind` and its payload, `locator`) — drafts get no governance exemption.
4. Run:

   ```sh
   .venv/bin/python tools/make_fixtures.py
   .venv/bin/python tools/make_manifest.py
   .venv/bin/python tools/make_vectors.py
   .venv/bin/python tools/crosscheck.py
   .venv/bin/python tools/auto_draft.py --check
   .venv/bin/python tools/verify.py
   ```

5. Commit the entry, the recipe and the regenerated manifest, fixtures and vectors.

## Changing an existing field

Follow rule 2. In addition, update the field's `fixtures`, `crosscheck` and `vectors` entries in `recipes/<id>.json`. Explain in the pull request why the previous offset was wrong.

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
