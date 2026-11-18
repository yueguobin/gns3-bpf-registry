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
- `prototype/index.html`: the BPF Expression Visual Calculator, a dependency-free single-file page described below.
- `.github/workflows/pages.yml`: publishes the prototype plus the registry JSON it loads to GitHub Pages on every push to `main` that touches them.

## Consumer flow

1. The server fetches `registry/manifest.json` from a release tag:
   `https://raw.githubusercontent.com/yueguobin/gns3-bpf-registry/gns3-bpf-registry-v2026.11.15/registry/manifest.json`
   (tags up to `registry-v2026.11.6` use the legacy `registry-v` name)
2. It validates the manifest, verifies every file hash, validates each entry against the schema and re-checks compiled expressions with `tcpdump -d`.
3. It activates the new version in a version directory and switches atomically, keeping the previous version for rollback. See [INTEGRATION.md](INTEGRATION.md).

The web UI uses the same entry files and the golden vectors as the cross-language contract.

## Visual calculator

**<https://yueguobin.github.io/gns3-bpf-registry/>** — the BPF Expression Visual Calculator, a live prototype of the layer-stack filter builder specified in [docs/ui-contract.md](docs/ui-contract.md):

- protocol bricks are stacked like Lego from a palette grouped by encapsulation family (link / network / transport / tunnel / application);
- every header renders as the textbook RFC diagram: a 32-bit word grid derived purely from each field's `offset`/`mask` (fields never wrap mid-field; wide fields get their own row);
- double-click a field to type a value, pick an enum, or toggle flag letters (TCP F/S/R/P/A/U/E/C, EIGRP I/C/R/E, …); values that name the next protocol (EtherType, IP proto, UDP/TCP port) grow or replace the following brick;
- the compiled libpcap/tcpdump expression appears live, including locator clauses (`ip proto 89`, `udp port 520`, …), guard pins and the VLAN slot — byte-identical to `tools/bpf_compile.py` and checked with `tcpdump -d`.

The prototype is a single `prototype/index.html` with no build step; it loads `registry/*.json` at runtime, so the bricks always mirror the registry — a new entry appears on the page as soon as it is merged, with no hand-maintained copy to drift. Its compiled output is byte-identical to `tools/bpf_compile.py`, checked against every vector in `vectors/golden.json`. To run locally, serve the repository over HTTP (`python3 -m http.server`, then open `http://localhost:8000/prototype/`) — opening the file directly cannot fetch the registry. English by default, 中文可选.

## Protocols

47 entries, 306 fields.

| Entry | Standard | Fields | Entry | Standard | Fields |
|---|---|---|---|---|---|
| ah | RFC 4302 | 5 | ipv6 | RFC 8200 | 6 |
| arp | RFC 826 | 9 | isis | ISO/IEC 10589; RFC 1195 | 9 |
| bfd | RFC 5880/5881 | 11 | lacp | IEEE 802.1AX | 23 |
| bgp | RFC 4271/2918 | 2 | ldp | RFC 5036 | 4 |
| cdp | Cisco CDP Spec 2.02 | 3 | lldp | IEEE 802.1AB | 2 |
| dhcp | RFC 2131/2132 | 12 | mpls | RFC 3032/5462 | 4 |
| dhcpv6 | RFC 8415 | 2 | ntp | RFC 5905 | 9 |
| dns | RFC 1035/4035/9619 | 15 | ospf | RFC 2328 | 7 |
| eapol | IEEE 802.1X | 3 | ospfv3 | RFC 5340 | 8 |
| eigrp | RFC 7868 | 8 | pim | RFC 7761 | 4 |
| esp | RFC 4303 | 2 | pppoe | RFC 2516 | 5 |
| ethernet | IEEE 802.3 | 1 | rip | RFC 2453 | 3 |
| frag6 | RFC 8200 | 6 | ripng | RFC 2080 | 3 |
| geneve | RFC 8926 | 8 | rsvp | RFC 2205 | 7 |
| gre | RFC 2784/2890 | 5 | sctp | RFC 9260 | 4 |
| gtp | 3GPP TS 29.060 | 9 | srh | RFC 8754 | 7 |
| hsrp | RFC 2281 | 11 | stp | IEEE 802.1D | 14 |
| icmp | RFC 792 | 5 | tacacsplus | RFC 8907 | 6 |
| icmp6 | RFC 4443/4861 | 5 | tcp | RFC 9293 | 8 |
| igmp | RFC 1112/2236/3376 | 4 | udp | RFC 768 | 2 |
| ikev2 | RFC 7296/3948 | 6 | vlan | IEEE 802.1Q | 1 (primitive) |
| ipv4 | RFC 791 | 10 | vrrp | RFC 3768 | 8 |
| nhrp | RFC 2332 | 14 | vxlan | RFC 7348 | 3 |
| radius | RFC 2865/2866/5997 | 3 | | | |

Every fixed-offset field of the header diagram is modelled; addresses and ports are left to `host`/`port` primitives and fields without a fixed layout (conditional, variable-length, encrypted) are excluded with a reason in `notes`. New protocols are seeded from scapy metadata and probe-verified by `tools/seed_draft.py` — see [CONTRIBUTING.md](CONTRIBUTING.md).

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

1. `size` is 1, 2 or 4. libpcap's `proto[offset:size]` window supports only those widths. Wider or sub-byte logical fields are read through a mask: the 24-bit VNI uses `offset: 4`, `mask: "0xffffff00"`, `shift: 8`; bit-packed words can carry several masked views (IPv6 version, traffic class and flow label all read the first word).
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

Seed a new protocol from scapy metadata (drafts land in `drafts/`, gitignored; the differential probe verifies or rejects every proposed layout):

```sh
.venv/bin/python tools/seed_draft.py --class OSPF_Hdr --module scapy.contrib.ospf --id ospf --under ip:89 --write
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
4. Cut a release tag `gns3-bpf-registry-v<YYYY.MM.DD>` named after the actual day the tag is created (for example `gns3-bpf-registry-v2026.11.15`) and push it. Batch merged pull requests into daily or weekly releases; at most one tag per day. Never move or re-create a published tag.

## License

GPL-3.0. See [LICENSE](LICENSE).
