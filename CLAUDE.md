# CLAUDE.md

## Repository purpose

`gns3-bpf-registry` is a versioned, curated data repository: protocol header field definitions that compile to libpcap/tcpdump expressions for GNS3 packet filters. It is consumed by the GNS3 server (ingest, validate, activate) and the GNS3 web UI (TypeScript compiler).

## Invariants

- `registry/*.json` and `recipes/*.json` are hand-maintained. `registry/manifest.json`, `fixtures/**` and `vectors/golden.json` are generated; never edit them by hand.
- The reference compiler is `tools/bpf_compile.py`. Its output format is the cross-language contract recorded in `vectors/golden.json`.
- Every field has a `ref` to an RFC or another normative standard.
- `size` is 1, 2 or 4. Wider logical fields use a mask and shift.
- Field windows may overlap: bit-packed words carry one masked view per field (e.g. IPv6 version, traffic class and flow label all read the first word). Fields stay sorted by offset.
- Encapsulation-layer addresses and ports (outer Ethernet/IP headers, TCP/UDP ports) stay out of the field tables; the filter builder emits host/port primitives for them. Addresses embedded in a protocol's payload (ARP sender/target, DHCP yiaddr, chaddr) are not reachable by primitives and are first-class `ipv4`/`mac` fields; a mac compiles to a 4+2 two-load conjunction, the same shape libpcap emits for `ether host`.
- Byte coverage: every byte of a fixed header is either covered by a registered field view or listed in the entry's `excluded` section with a reason; `verify.py` enforces this. There is no third state.
- VLAN is primitive-only (`emit: "vlan {value}"`) and belongs in the builder's VLAN slot, first in the expression.
- Additive changes only. Changing an existing field's `offset`, `size` or `mask` requires a new `registryVersion` and two approvals.
- Published tags are immutable.

## Commands

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt

.venv/bin/python tools/crosscheck.py
.venv/bin/python tools/auto_draft.py --check
.venv/bin/python tools/verify.py
.venv/bin/python tools/make_fixtures.py --check
.venv/bin/python tools/make_manifest.py --check
.venv/bin/python tools/make_vectors.py --check
python3 tools/check_i18n.py
```

Regenerate after editing a registry entry: `make_fixtures.py`, `make_manifest.py`, `make_vectors.py`.

Compile one expression:

```sh
.venv/bin/python tools/bpf_compile.py --entry vxlan --select vni=100
.venv/bin/python tools/bpf_compile.py --entry tcp --select flags=SYN,ACK
.venv/bin/python tools/bpf_compile.py --entry vxlan --select vni=100 --vlan 100
.venv/bin/python tools/bpf_compile.py --entry vxlan --select vni=100 --vlan 100 --vlan 200
```

Seed a new protocol from scapy metadata (see the seed-protocol skill):

```sh
.venv/bin/python tools/seed_draft.py --class OSPF_Hdr --module scapy.contrib.ospf --id ospf --under ip:89 --write
```

## Verification rules

- `crosscheck.py` builds each field with a sentinel value and asserts the serialized bytes at the documented offset. A recipe sentinel may be a `[build, expected]` pair when the scapy kwarg encoding differs from the wire bits (e.g. scapy's 3-bit TCP `reserved` beside the NS bit). It deliberately does not read scapy `fields_desc`: the VXLAN class is a union and reports the wrong VNI offset.
- `seed_draft.py` seeds recipe + entry drafts from a scapy class (`--class <C> --under ip:89 --write`), probe-first: `fields_desc` only proposes, the differential probe decides; probe-rejected fields land under `manual` with their guess. Drafts go to `drafts/` (gitignored) and get no governance exemption. The workflow is codified in `.claude/skills/seed-protocol`.
- `auto_draft.py` re-derives every registered field's `offset`/`size`/`mask`/`shift` from serialized bytes (differential probes with pinned computed fields) and compares against the registry; `--check` fails on drift or missing recipe coverage. Fields the probe cannot derive (bit-packed or length-changing) are declared under `manual` in the recipe with a reason; crosscheck still verifies them byte for byte. `--draft --entry <id>` emits candidate skeletons into `drafts/` (gitignored); drafts get no governance exemption.
- Per-protocol knowledge lives in `recipes/<id>.json` (packet stack, anchor, probe sentinels, crosscheck sentinels, fixture values, golden vector specs). `pktspec.py` is the shared interpreter: the tools contain no per-protocol code. `$PIN` marks probe-pinned checksums; fixture builds drop them so pcaps keep real checksums. `fieldMap` targets may be layer-qualified (`UDP.chksum`) when two layers share a kwarg name. The probed layer must be last in the stack, so the layer window is `len(packet) - headerLength`.
- `verify.py` validates the schema, structural invariants, `tcpdump -d` syntax, golden vectors and fixture replay. Replay counts packets with scapy: positive fixtures must match exactly one packet and negative fixtures zero. Do not rely on tcpdump's exit code.
- All generators support `--check`; CI fails if a generated artifact is stale.
- The prototype is bilingual: UI chrome lives in `prototype/i18n.js` (STR.en/STR.zh, identical key sets); per-protocol data strings ride inline `{en, zh}` objects in the registry and `prototype/overlay.js`. `check_i18n.py` fails on any CJK codepoint in `prototype/index.html`, on key-set drift, or on a localized object missing a language — new user-visible strings go through `T()`/`L()`, never hardcoded in the page.

## Working conventions

- Comments, documentation, commit messages and pull request descriptions are in English.
- Do not add AI attribution to commits or pull requests.
- Commit subjects use conventional prefixes (`chore:`, `feat(schema):`, `feat(registry):`, `feat(tools):`).
