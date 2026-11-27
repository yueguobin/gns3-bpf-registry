# UI contract: the visual packet-filter calculator

How the GNS3 web UI consumes this registry to build the layer-stack
filter builder: the user stacks encapsulation layers, the tool renders
each header as colored field blocks (an interactive RFC diagram), and
every field selection compiles to a tcpdump/libpcap expression without
anyone counting bytes.

A live prototype of this contract ships from this repository as the
BPF Expression Visual Calculator:
<https://yueguobin.github.io/gns3-bpf-registry/> (three files:
`prototype/index.html` for markup and logic, `prototype/i18n.js` for
UI-chrome strings, `prototype/overlay.js` for per-protocol UI data;
deployed by `.github/workflows/pages.yml`).

The rendering model is the textbook encapsulation anatomy: a vertical
layer stack with a cumulative byte ruler on the side ("50 bytes of
overhead"), Underlay/Overlay grouping, and per-layer detail panels in
which each field is a block whose width is proportional to its byte
size with bit-width labels (48 / 16 / 24 ...).

## 1. Layer stack builder

- The user adds layers bottom-up (Ether → IP → UDP → VXLAN → inner
  Ether → ...). Each layer renders one colored block in the stack.
- The construction area stacks **columns** vertically, each one
  full-width (a "+" bar at the bottom adds one, an "×" per column
  deletes it, and a horizontal operator bar between adjacent columns
  cycles `and` / `or` / `not` on click). Each column is an independent
  stack as described here and one operand of the final boolean
  expression — see section 2. A column may start at any protocol: a
  bare OSPF brick is already anchored by its `locator`
  (`ip proto 89`), no Ethernet/IP preamble required.
- Bricks drag by their label strip — except the padded × delete zone,
  which stays a pure click target and never arms a drag: reorder
  within a column or move across columns (field selections ride
  along, they are keyed by layer id). A tunnel header drags its whole
  inner-packet run with it.
- **VLAN bricks stack** (QinQ): one brick = one tag; repeat the brick
  once per tag, stack order = tag order (outer first). Each pre-tunnel
  brick emits one `vlan <id>` keyword (leading the column expression);
  a tag's EtherType enum offers 0x8100 / 0x88a8 and chains into the
  next VLAN brick. Tag k's byte views (PCP/DEI/EtherType) are absolute
  reads at 14 + 4×(preceding tags); protocol keywords shift on their
  own inside libpcap.
- The brick rail groups protocols by family behind collapsible headers
  that mirror the brick geometry, accordion-style: exactly one family
  is expanded at a time (including the Custom group) — opening a group
  collapses the others, and open state changes only by click, so
  picking a brick never collapses the group it came from. While a
  search term is active, every group holding matches is expanded
  instead; clearing the search restores the accordion state.
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
  - `ipv6` — IPv6-notation input (any `::`-compressed group-hex form)
- Single-bit number fields render as a one-letter toggle. The letter
  comes from the label's `(X)` convention (GRE `Checksum Present (C)`
  → `C`), else from a short field id which reads like the RFC name
  (DNS `qr` → `QR`, GTP `pn_flag` → `PN`), else the label initial
  (`Bottom of Stack` → `B`) — never a bare `?`.
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
stack: Ether → IP(20) → UDP → VXLAN → Ether → IP(20) → TCP
inner TCP dport 443 →
  (udp port 4789 or udp port 8472) and (ether[64] & 0x0f) == 5 and ether[86:2] == 443
```

(The locator clause is the entry's `locator` list joined with `or` —
single locators emit bare; the VXLAN entry carries both the standard
port 4789 and 8472.)

**Boolean combination** — every column compiles independently (its own
locators, VLAN slot, guards and drill state); the per-column
expressions are then joined by the operators sitting between the
columns: `and` / `or`, and `not`, which negates the column to its
right (`X not Y` ≡ `X and not (Y)`). Grouping follows libpcap
precedence `not > and > or` and always emits explicit parentheses:

```
columns [A] or [B] not [C]         → A or (B and (not C))
columns [A] and [B] or [C] not [D] → (A and B) or (C and (not D))
```

Empty columns sit out of the combination; a single live column emits
its clauses bare, exactly like the single-stack model above.

## 3. Tested pitfalls the generator must respect

- The `vlan` keyword auto-shifts subsequent **protocol keywords**
  (`ip6`, `udp port`) but does **not** shift `ether[]` reads: with an
  outer VLAN tag, every absolute `ether[N]` carries the extra 4 bytes
  by hand (compile output verified: `ldb [97]` reads raw offset 97).
- The VLAN slot is **repeatable** for QinQ (802.1ad double tagging):
  repeat the primitive once per tag, **outer tag first** (`vlan 100 and
  vlan 200`). libpcap matches TPIDs 0x8100 / 0x88a8 / 0x9100 at every
  level and shifts its decoder offsets per keyword, so the chain
  reaches the inner tag without a dedicated QinQ entry. With two tags,
  protocol keywords shift by 8 and absolute `ether[]` reads carry 8
  extra bytes by hand. Golden vectors record the slot as a scalar
  (single tag) or a list (stacked, outer first).
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
- `ipv6` values parse in any `::`-compressed group-hex form
  (`ff02::fb`, `2001:db8::1`, `::`) and compile to the 4x4 four-load
  conjunction — the same shape libpcap emits for `ip6 host`:
  `(icmp6[8:4] == 0xff020000 and icmp6[12:4] == 0x0 and icmp6[16:4] == 0x0 and icmp6[20:4] == 0xfb)`;
- masked enums compile as `(addr & mask) == value << shift`;
- bitset selections take a labels list (`flags: ["SYN"]`) or a numeric
  mask;
- the VLAN slot takes one ID or a list (outer tag first) and emits one
  `vlan <id>` primitive per ID, joined with `and`, leading the
  expression (`vlan 100 and vlan 200 and ...`).

## 6. Registry-side notes

- Boot: the UI fetches `registry/manifest.json`, then every listed
  entry file **in parallel** (they are independent — no ordering), and
  shows a spinner + per-file progress (STR keys `loading` /
  `loadingProg`) until the palette can render. Port the same feedback
  instead of a blank screen: with dozens of entries the fetch phase is
  the page's only perceptible wait. `registry/` may sit beside the
  page (flat Pages bundle) or one level up (repo-root serving) — probe
  `registry/…` then `../registry/…`; do not hardcode one layout.
- Layer lengths come from `headerLength`; nothing else is needed for
  the stack builder.
- Optional future enhancement: a layer-category marker
  (`fixed` / `variable-length` / `tlv` / `tunnel`) so the UI knows
  which layers can advance the ruler by data alone and which need a
  declared length. Not yet in the schema.

## 7. Localization (i18n)

The calculator is bilingual (English default, Chinese secondary) and
keeps two string populations apart:

- **UI chrome** lives in `prototype/i18n.js`: one `STR` table with
  `en` and `zh` blocks declaring identical key sets, resolved through
  `T(key)` (English is the fallback) and `L(obj)` for `{en, zh}`
  objects. The language-switch button shows the *other* language's
  name in that language (`中文` on the English UI) — the one
  sanctioned CJK occurrence inside `STR.en`.
- **Data strings** travel with their entry, never in the chrome
  table: registry entries carry `description` / `reason` as inline
  `{en, zh}` objects, and the UI overlay (`prototype/overlay.js`)
  does the same for tail notes, pin warnings and family labels.

`tools/check_i18n.py` (CI-enforced) keeps the split honest: no CJK
codepoint anywhere in `index.html`, no CJK in `STR.en` (except the
language name above), identical `en`/`zh` key sets, no unused keys or
unresolved `T()` references, and both languages present on every
localized object in the overlay and the registry. Without the
index.html rule a hover or badge can silently ship untranslated in
the other language.

The GNS3 web UI should port the chrome table into its own i18n
catalogs (vue-i18n or equivalent) and consume the registry's
`{en, zh}` data objects as-is; the file split mirrors that boundary.
