---
name: seed-protocol
description: Add a protocol to the gns3-bpf-registry — generate recipe and entry drafts from scapy metadata with tools/seed_draft.py, verify layouts with the differential probe, complete the semantics by hand, and land the entry through the full verification chain. Use when adding any new protocol or extending an existing entry with new fields.
---

# Seed a protocol into the registry

Goal: register every fixed-offset field of a protocol header with zero
manual byte-counting. scapy metadata proposes; the differential probe
decides; the human (you, acting as curator) only confirms semantics
against the RFC. Never trust `fields_desc` over the probe: the VXLAN
union reports the VNI at the wrong offset, and conditional fields lie
about wire layout.

## Workflow

1. **Seed.** Generate drafts from a scapy class:

   ```sh
   .venv/bin/python tools/seed_draft.py --class <Class> [--module scapy.contrib.xyz] --id <id> --under <encap> [--write]
   ```

   - `--under` picks the encapsulation and derives anchor + locator:
     `ip:89`, `udp:4789`, `tcp:179`, `ipv6:58`, `ether`
   - Without `--write` it only prints the entry draft (useful to preview).
   - If the class is not in `pktspec.LAYERS`, add the import and one
     entry to `tools/pktspec.py`, then rerun.
   - Output per field is either `probe` (layout verified from serialized
     bytes — trust it, including when it disagrees with `fields_desc`)
     or `metadata guess (probe rejected)` (goes to the recipe's `manual`
     section — confirm the guess against the RFC header diagram).

2. **Complete the semantics** in `drafts/<id>.json` (this is the human
   part; nothing here is derivable):
   - `label`, `rfc`, and per-field `ref` (RFC section — governance rule 5)
   - enum labels and bit labels from the RFC (seeded values are scapy's;
     curate them), `min`/`max` for numbers
   - rename fields via `fieldMap` if scapy names are wrong
     (`len` -> `packet_length`); targets colliding with under-layer
     kwargs must be layer-qualified (`OSPF_Hdr.chksum`)
   - confirm `anchor`, `locator`, `headerLength` against the RFC diagram
   - document every exclusion in `notes` (conditional fields, fields
     wider than 4 bytes, encrypted regions). Addresses and ports are
     always excluded — host/port primitives cover them.

3. **Land.** Move the completed draft to `registry/<id>.json`, polish
   `recipes/<id>.json` (realistic `fixtures` values, vector names),
   bump `registry/VERSION` (additive change), then:

   ```sh
   .venv/bin/python tools/make_fixtures.py
   .venv/bin/python tools/make_manifest.py
   .venv/bin/python tools/make_vectors.py
   .venv/bin/python tools/crosscheck.py
   .venv/bin/python tools/auto_draft.py --check
   .venv/bin/python tools/verify.py
   ```

   All six green, then commit `feat(registry): add <id> entry` on a
   feature branch and open a PR. Drafts get no governance exemption.

## Inclusion rules (current standard)

A field goes in iff: fixed offset (position independent of other field
values) AND not an address/port (primitives) AND fits a 1/2/4-byte read
window (bit-packed words become masked views; overlapping windows are
fine). Everything else in the RFC header diagram is included —
checksums, version fields, reserved bits included.

## Hard limits

- Never edit `registry/manifest.json`, `fixtures/**`, `vectors/golden.json`
  by hand; regenerate them.
- Never weaken a check to make an entry pass; fix the entry or the recipe.
- Machine-dependent values in stacks (host-filled addresses) must be
  pinned with `$VARS` literals — CI regenerates fixtures and will catch them.
