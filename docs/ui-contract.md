# UI contract: the visual packet-filter calculator

How the GNS3 web UI consumes this registry to build the layer-stack
filter builder: the user stacks encapsulation layers, the tool renders
each header as colored field blocks (an interactive RFC diagram), and
every field selection compiles to a tcpdump/libpcap expression without
anyone counting bytes.

A live prototype of this contract ships from this repository as the
BPF Expression Visual Calculator:
<https://yueguobin.github.io/gns3-bpf-registry/> (single-file
`prototype/index.html`, deployed by `.github/workflows/pages.yml`).

The rendering model is the textbook encapsulation anatomy: a vertical
layer stack with a cumulative byte ruler on the side ("50 bytes of
overhead"), Underlay/Overlay grouping, and per-layer detail panels in
which each field is a block whose width is proportional to its byte
size with bit-width labels (48 / 16 / 24 ...).

## 1. Layer stack builder

- The user adds layers bottom-up (Ether → IP → UDP → VXLAN → inner
  Ether → ...). Each layer renders one colored block in the stack.
- A byte ruler shows the cumulative offset at every layer boundary —
  the prefix sum of the declared header lengths.
- Clicking a layer expands its **field blocks** from the registry
  entry: `offset`, `size`, `mask`/`shift`, `kind`, `label`. Blocks sit
  at their proportional position inside the layer; `excluded` ranges
  render as gray blocks with the exclusion reason as a tooltip.
- Clicking a field opens the value control selected by `kind`:
  - `number` — numeric input bounded by `min`/`max`
  - `enum` — dropdown of `values`
  - `bitset` — one checkbox per declared bit
  - `ipv4` — dotted-quad input
  - `mac` — MAC-notation input
- Encapsulation addresses and ports (listed in each entry's `excluded`
  with a primitive reason) are offered as **primitives** (`src`, `dst`,
  `port`, `ether src/dst`) — never as byte windows.

## 2. Expression generation: two modes

The tool picks the mode from the stack; the user never chooses.

**Native mode** — the stack does not cross a payload boundary
(Ether → IP → TCP): clauses use the entry's keyword anchor
(`udp[8:1] == 0x1`). libpcap resolves the outer layers (IHL-aware,
VLAN-aware via protocol keywords), so these clauses are robust to
outer-header variation. This is what `vectors/golden.json` locks.

**Drill mode** — the stack crosses a tunnel payload (… → UDP:4789 →
VXLAN → inner Ether → inner IP → TCP): keywords cannot reach past the
outer payload, so clauses compile to absolute `ether[N:M]` reads where
`N` = ruler prefix sum + field offset. Every declared layer
contributes a **guard clause** so a packet whose real encapsulation
differs from the declared stack fails the whole filter (safe miss,
never a wrong match):

- each crossed layer's `locator` becomes a link guard
  (`ether proto 0x0800`, `ip proto 17`, `udp port 4789`, ...);
- a crossed IP layer with a declared header length pins IHL
  (`(ether[N] & 0x0f) == 5` for the 20-byte default, adjustable
  20–60).

Example (tested):

```
stack: Ether → IP(20) → UDP:4789 → VXLAN → Ether → IP(20) → TCP
inner TCP dport 443 →
  udp port 4789 and (ether[64] & 0x0f) == 5 and ether[86:2] == 443
```

## 3. Tested pitfalls the generator must respect

- The `vlan` keyword auto-shifts subsequent **protocol keywords**
  (`ip6`, `udp port`) but does **not** shift `ether[]` reads: with an
  outer VLAN tag, every absolute `ether[N]` carries the extra 4 bytes
  by hand (compile output verified: `ldb [97]` reads raw offset 97).
- IPv6 extension headers are **declared layers**: built-in layouts for
  the standard headers (mind the length units — most are 8-byte
  multiples, AH is 4-byte), `Next Header` filled from the chain. A
  Fragment header in the chain must warn: non-first fragments carry no
  L4 header, so L4 field reads hit payload bytes.
- LLDP-style TLV protocols: only the first TLV sits at a fixed offset;
  the stack renders to that boundary and no further.

## 4. Custom layers (the escape hatch)

Unregistered protocols never block the tool: add a **custom layer**
declaring only its length (even "unknown N bytes" just to advance the
ruler). To filter bytes inside a custom layer, select a range on a
byte grid and enter the value. A useful custom layer can be promoted
into the registry later through the normal seed workflow.

## 5. TypeScript compiler requirements

The TS compiler must produce strings identical to `tools/bpf_compile.py`;
`vectors/golden.json` is the contract and CI-verifies it. Current
requirements:

- numbers compile in decimal (`tcp[14:2] == 100`); enum values, ipv4
  values, masks and mac halves in `0x` hexadecimal;
- `ipv4` values parse as dotted quads or integers
  (`192.0.2.10` → `0xc000020a`);
- `mac` values parse as `aa:bb:cc:dd:ee:ff` (or aabbccddeeff) and
  compile to the 4+2 two-load conjunction — the same shape libpcap
  emits for `ether host`:
  `(arp[18:4] == 0xaabbccdd and arp[22:2] == 0xeeff)`;
- masked enums compile as `(addr & mask) == value << shift`;
- bitset selections take a labels list (`flags: ["SYN"]`) or a numeric
  mask.

## 6. Registry-side notes

- Layer lengths come from `headerLength`; nothing else is needed for
  the stack builder.
- Optional future enhancement: a layer-category marker
  (`fixed` / `variable-length` / `tlv` / `tunnel`) so the UI knows
  which layers can advance the ruler by data alone and which need a
  declared length. Not yet in the schema.
