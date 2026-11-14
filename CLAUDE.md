# CLAUDE.md

## Repository purpose

`gns3-bpf-registry` is a versioned, curated data repository: protocol header field definitions that compile to libpcap/tcpdump expressions for GNS3 packet filters. It is consumed by the GNS3 server (ingest, validate, activate) and the GNS3 web UI (TypeScript compiler).

## Invariants

- `registry/*.json` are hand-maintained. `registry/manifest.json`, `fixtures/**` and `vectors/golden.json` are generated; never edit them by hand.
- The reference compiler is `tools/bpf_compile.py`. Its output format is the cross-language contract recorded in `vectors/golden.json`.
- Every field has a `ref` to an RFC or another normative standard.
- `size` is 1, 2 or 4. Wider logical fields use a mask and shift.
- Addresses and ports stay out of the field tables; the filter builder emits host/port primitives.
- VLAN is primitive-only (`emit: "vlan {value}"`) and belongs in the builder's VLAN slot, first in the expression.
- Additive changes only. Changing an existing field's `offset`, `size` or `mask` requires a new `registryVersion` and two approvals.
- Published tags are immutable.

## Commands

```sh
python3 -m venv .venv
.venv/bin/pip install -r tools/requirements.txt

.venv/bin/python tools/crosscheck.py
.venv/bin/python tools/verify.py
.venv/bin/python tools/make_fixtures.py --check
.venv/bin/python tools/make_manifest.py --check
.venv/bin/python tools/make_vectors.py --check
```

Regenerate after editing a registry entry: `make_fixtures.py`, `make_manifest.py`, `make_vectors.py`.

Compile one expression:

```sh
.venv/bin/python tools/bpf_compile.py --entry vxlan --select vni=100
.venv/bin/python tools/bpf_compile.py --entry tcp --select flags=SYN,ACK
.venv/bin/python tools/bpf_compile.py --entry vxlan --select vni=100 --vlan 100
```

## Verification rules

- `crosscheck.py` builds each field with a sentinel value and asserts the serialized bytes at the documented offset. It deliberately does not read scapy `fields_desc`: the VXLAN class is a union and reports the wrong VNI offset.
- `verify.py` validates the schema, structural invariants, `tcpdump -d` syntax, golden vectors and fixture replay. Replay counts packets with scapy: positive fixtures must match exactly one packet and negative fixtures zero. Do not rely on tcpdump's exit code.
- All generators support `--check`; CI fails if a generated artifact is stale.

## Working conventions

- Comments, documentation, commit messages and pull request descriptions are in English.
- Do not add AI attribution to commits or pull requests.
- Commit subjects use conventional prefixes (`chore:`, `feat(schema):`, `feat(registry):`, `feat(tools):`).
