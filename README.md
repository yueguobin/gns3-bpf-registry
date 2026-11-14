# gns3-bpf-registry

[![CI](https://github.com/yueguobin/gns3-bpf-registry/actions/workflows/ci.yml/badge.svg)](https://github.com/yueguobin/gns3-bpf-registry/actions/workflows/ci.yml)

Versioned registry of protocol header field definitions for GNS3 BPF packet filters.

GNS3 users build packet filters from protocol fields such as TTL, TCP flags or the VXLAN VNI. This repository is the single, auditable source of truth for where those fields live and how they compile to libpcap/tcpdump expressions. The web UI compiles a field selection with the same rules. The server validates and activates a registry fetched from a pinned release tag.

## What lives here

- `registry/*.json`: one curated entry per protocol.
- `registry/manifest.json`: generated. Contains the schema version, the registry version and a SHA-256 digest for every registry file. Never edit it by hand.
- `schema/registry.schema.json`: JSON Schema v1 for entries and the manifest.
- `fixtures/`: generated positive/negative pcap pairs, one pair per field.
- `vectors/golden.json`: generated input-to-expression vectors. The TypeScript compiler in `gns3-web-ui` must match these strings byte for byte.
- `recipes/*.json`: hand-maintained per-protocol packet stacks and per-tool tables (probe sentinels, crosscheck sentinels, fixture values, golden vector specs). `tools/pktspec.py` builds packets from them.
- `tools/`: the Python reference compiler and the verification toolchain.

## Consumer flow

1. The server fetches `registry/manifest.json` from a release tag:
   `https://raw.githubusercontent.com/yueguobin/gns3-bpf-registry/registry-v2026.11.0/registry/manifest.json`
2. It validates the manifest, verifies every file hash, validates each entry against the schema and re-checks compiled expressions with `tcpdump -d`.
3. It activates the new version in a version directory and switches atomically, keeping the previous version for rollback. See [INTEGRATION.md](INTEGRATION.md).

The web UI uses the same entry files and the golden vectors as the cross-language contract.

## Entry format

A header entry describes fields reachable through a tcpdump anchor:

```json
{
  "id": "vxlan",
  "label": "VXLAN",
  "rfc": ["7348"],
  "notes": "Classic VXLAN only. VXLAN-GPE is out of scope.",
  "anchor": { "header": "udp", "base": 8 },
  "locator": ["udp port 4789", "udp port 8472"],
  "headerLength": 8,
  "fields": [
    {
      "id": "vni",
      "label": "VXLAN Network Identifier",
      "offset": 4,
      "size": 4,
      "mask": "0xffffff00",
      "shift": 8,
      "kind": "number",
      "ref": "RFC 7348 §5",
      "min": 0,
      "max": 16777215
    }
  ]
}
```

A primitive-only entry has no byte layout; its fields emit a tcpdump primitive:

```json
{
  "id": "vlan",
  "label": "VLAN",
  "rfc": [],
  "fields": [
    {
      "id": "vlan_id",
      "label": "VLAN ID",
      "kind": "number",
      "min": 1,
      "max": 4094,
      "ref": "IEEE 802.1Q-2022 §9.6",
      "emit": "vlan {value}"
    }
  ]
}
```

## The eight registry rules

1. `size` is 1, 2 or 4. libpcap's `proto[offset:size]` window supports only those widths. Wider logical fields are read through a mask: the 24-bit VNI uses `offset: 4`, `mask: "0xffffff00"`, `shift: 8`.
2. `anchor.header` is one of `ether`, `ip`, `ip6`, `tcp`, `udp`, `icmp`, `icmp6`, `arp`. `anchor.base` is the protocol header's byte offset relative to the anchor. VXLAN starts after the 8-byte UDP header, so its anchor is `{"header": "udp", "base": 8}`.
3. `locator` is an array of tcpdump primitives. The compiler ORs them inside parentheses and ANDs the group with the field clauses. An empty array emits no prefix. Never hand-write `A or B and C`.
4. IP addresses and ports are not byte fields. The filter builder emits `host` and `port` primitives; the registry only holds header fields that primitives cannot express.
5. A primitive-only field uses the `emit` escape hatch, for example `vlan {value}`. The template must contain `{value}` exactly once, and every compiled value is validated with `tcpdump -d`.
6. Every field carries a `ref` to an RFC or another normative standard (IEEE 802.3 or 802.1Q where no RFC exists). Entries with unverifiable provenance are rejected.
7. VLAN matching belongs to the builder's VLAN slot, placed first. The `vlan` primitive changes decoder offsets for the rest of the expression, so `vlan` never appears in a locator and VLAN tags are never modelled as byte offsets.
8. Additions append. Changing an existing field's `offset`, `size` or `mask` requires a new `registryVersion` and two approvals after an issue with evidence. Published tags are immutable.

## Compiler output contract

Canonical clause order: VLAN slot, locator group, then fields in registry order.

- Masked field: `(<anchor>[<base+offset>:<size>] & 0x<mask>) == 0x<value << shift>`. The parentheses are mandatory.
- Bit set: `(<anchor>[<base+offset>:<size>] & 0x<OR of selected bits>) == 0x<same>`.
- Plain number: decimal literal. Enum: hexadecimal. Masks and masked expected values: lowercase hexadecimal, no padding.
- One locator is emitted as-is. Several become `(a or b)`. An empty locator is omitted.
- A selection must contain at least one field.

`vectors/golden.json` is the authoritative list of examples. The Python reference compiler is `tools/bpf_compile.py`; the TypeScript compiler must produce identical strings.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt
.venv/bin/python tools/crosscheck.py
.venv/bin/python tools/auto_draft.py --check
.venv/bin/python tools/verify.py
.venv/bin/python tools/make_fixtures.py --check
.venv/bin/python tools/make_manifest.py --check
.venv/bin/python tools/make_vectors.py --check
```

Regenerate artifacts after changing a registry entry:

```sh
.venv/bin/python tools/make_fixtures.py
.venv/bin/python tools/make_manifest.py
.venv/bin/python tools/make_vectors.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for governance and [schema/VERSIONING.md](schema/VERSIONING.md) for versioning and compatibility rules.

## Release

1. Merge the change to `main` after CI passes.
2. Update `registry/VERSION` in the same pull request.
3. Run `make_manifest.py` and commit `registry/manifest.json`.
4. Tag the merge commit `registry-v<registryVersion>` and push the tag. Never move or re-create a published tag.

## License

GPL-3.0. See [LICENSE](LICENSE).
