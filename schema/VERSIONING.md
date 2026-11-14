# Schema and registry versioning

## Versions

- `schemaVersion` (integer, currently `1`): the shape of entry and manifest files. It changes only for a breaking schema change. Consumers must reject unknown schema versions.
- `registryVersion` (`YYYY.MM.PATCH`, for example `2026.11.0`): the content version stored in `registry/VERSION` and in `registry/manifest.json`. Every content change, including a new protocol, bumps it. Release tags are `registry-v<registryVersion>`.
- Published tags are immutable. Corrections go into a new version; never force-push or delete a tag.

## Compatibility rules

- Additive changes (a new entry, or a new field appended to an existing entry) are compatible. New fields must not change the meaning of existing field IDs.
- Changing an existing field's `offset`, `size`, `mask`, `shift`, `kind` or `emit` is a content break. It requires:
  1. an issue with RFC text or capture evidence;
  2. the curator plus a second approval;
  3. a new `registryVersion`.
- Removing a field or an entry requires the same process as a byte-boundary change.
- Consumers must tolerate unknown extra files; the manifest is the authoritative list.

## Entry shapes

- A header entry has `anchor`, `locator`, `headerLength` and fields with `offset` and `size`.
- A primitive entry has no byte layout; every field has an `emit` template containing `{value}`.
- A file is exactly one entry. IDs and filenames match (`vxlan` corresponds to `vxlan.json`).

## The eight schema rules

1. `size` is 1, 2 or 4. libpcap's `proto[offset:size]` window supports only those widths. Wider logical fields use a mask and shift (VNI: `offset: 4`, `mask: "0xffffff00"`, `shift: 8`).
2. `anchor.header` is one of `ether`, `ip`, `ip6`, `tcp`, `udp`, `icmp`, `icmp6`, `arp`; `anchor.base` is the protocol header's byte offset relative to the anchor (VXLAN: the UDP payload starts at 8).
3. `locator` is an array of tcpdump primitives. The compiler ORs them inside parentheses, then ANDs the group with the field clauses. An empty array means no prefix. Do not rely on `A or B and C` precedence.
4. Addresses and ports are not byte fields. Use `host` and `port` primitives; the registry only models header fields that primitives cannot express.
5. Primitive-only fields use `emit` (for example `vlan {value}`). The template must contain `{value}` exactly once. Every emitted value must pass `tcpdump -d`.
6. Every field needs a `ref` to an RFC or normative standard (IEEE 802.3 or 802.1Q where no RFC exists). CI rejects entries with unverifiable provenance.
7. VLAN matching is handled by the builder's VLAN slot, placed first. The `vlan` primitive changes decoder offsets for the rest of the expression; `vlan` must not appear in a locator and VLAN tags must not be modelled as byte offsets.
8. Additions append. Changing an existing field's byte boundaries requires a new `registryVersion` and two approvals (see `CONTRIBUTING.md`). Published tags are immutable.

## Structural rules enforced by `tools/verify.py`

JSON Schema cannot express these; the verifier enforces them:

- `offset + size <= headerLength`; fields are sorted by offset and do not overlap.
- `mask` fits within `size` bytes; `mask >> shift` is a contiguous low-bit mask; `min` and `max` fit inside `mask >> shift`.
- When `mask` is present, `shift` defaults to 0 and must match the mask's trailing-zero count.
- Enum values fit in `size` bytes and are unique. Bit masks are single bits, are unique and fit in `size` bytes.
- A primitive field's `emit` template contains exactly one `{value}` and no other braces; `min <= max`.
- `registry/VERSION` matches the manifest's `registryVersion`; the manifest lists exactly the non-manifest `registry/*.json` files with correct SHA-256 digests.
- Every field appears in at least one golden vector.

## Compiler output contract

- Clause order: VLAN slot, locator group, then fields in registry order.
- Masked: `(<anchor>[<base+offset>:<size>] & 0x<mask>) == 0x<value << shift>`; parentheses are mandatory.
- Bit set: `(<anchor>[<base+offset>:<size>] & 0x<OR of selected bits>) == 0x<same>`.
- Plain number: decimal. Enum: hexadecimal. Masks and masked expected values: lowercase hexadecimal, no padding.
- One locator is emitted as-is; several become `(a or b)`; an empty locator is omitted.
- A selection must contain at least one field.

`vectors/golden.json` records the exact strings. The TypeScript compiler must match them byte for byte.
