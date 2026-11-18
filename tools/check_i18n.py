#!/usr/bin/env python3
"""i18n integrity checks for the prototype calculator.

The prototype keeps two string populations apart:

- UI CHROME lives in prototype/i18n.js (STR.en / STR.zh + the T()/L()
  helpers). English is the fallback language, so STR.en must stay CJK-free
  and both languages must declare the same keys.
- DATA strings (registry/*.json and the overlay in prototype/overlay.js)
  travel with their entry as inline {en, zh} objects resolved through L();
  every such object must carry both languages.

prototype/index.html is markup + logic only and must contain no CJK
codepoint at all — that is the rule which keeps a hover or label from
shipping untranslated in the other language.

Checks (all fail loudly):
1. no CJK codepoints in prototype/index.html;
2. no CJK codepoints inside the STR.en block of i18n.js;
3. STR.en and STR.zh declare identical key sets, and every key is
   referenced by at least one T("...") call in index.html;
4. every T("...") key used in index.html exists in STR.en;
5. every {en, zh} object literal in i18n.js / overlay.js has both keys;
6. every localized object in registry/*.json (excluding the generated
   manifest) carries non-empty en and zh strings.

Usage: python3 tools/check_i18n.py
"""

import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
# CJK punctuation, kana, CJK extension A, CJK unified, compatibility
# ideographs, fullwidth forms — the ranges a leaked zh string can hit.
CJK = re.compile("[　-〿぀-ヿ㐀-䶿一-鿿豈-﫿＀-￯]")


# ---------- a string/comment-aware JS object scanner ----------
# Yields (start, end, keys) for every object literal, where keys are the
# identifiers found in key position (right after "{" or ","). Strings
# (including template literals with ${...} holes) and comments are skipped
# so their contents never leak into keys or brace balance.
def js_frames(src):
    n = len(src)
    frames = []
    stack = []  # [start, keys, expect_key]

    def skip_string(j):
        quote = src[j]
        j += 1
        while j < n:
            c = src[j]
            if c == "\\":
                j += 2
                continue
            if quote == "`" and c == "$" and src[j + 1 : j + 2] == "{":
                j += 2
                depth = 1
                while j < n and depth:
                    if src[j] == "}":
                        depth -= 1
                        j += 1
                    elif src[j] in "\"'`":
                        j = skip_string(j)
                    else:
                        j += 1
                continue
            if c == quote:
                return j + 1
            j += 1
        raise ValueError("unterminated string in JS source")

    def skip_comment(j):
        if src[j + 1 : j + 2] == "/":
            end = src.find("\n", j)
            return n if end < 0 else end
        end = src.find("*/", j)
        return n if end < 0 else end + 2

    i = 0
    while i < n:
        c = src[i]
        if c in "\"'`":
            i = skip_string(i)
            continue
        if c == "/" and src[i + 1 : i + 2] in "/*":
            i = skip_comment(i)
            continue
        if c == "{":
            stack.append([i, [], True])
            i += 1
            continue
        if c == "}":
            if stack:
                start, keys, _ = stack.pop()
                frames.append((start, i + 1, keys))
            i += 1
            continue
        if c == "," and stack:
            stack[-1][2] = True
            i += 1
            continue
        if (c.isalpha() or c in "_$") and stack and stack[-1][2]:
            j = i
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            k = j
            while k < n and src[k] in " \t\r\n":
                k += 1
            if k < n and src[k] == ":" and src[k + 1 : k + 2] != ":":
                stack[-1][1].append(src[i:j])
                stack[-1][2] = False
            i = j
            continue
        i += 1
    if stack:
        raise ValueError("unbalanced braces in JS source")
    return frames


def localized_js_errors(src, filename, errs):
    for _start, _end, keys in js_frames(src):
        if "en" in keys or "zh" in keys:
            for lang in ("en", "zh"):
                if lang not in keys:
                    errs.append(f"{filename}: localized object with keys {sorted(keys)} is missing '{lang}'")


def cjk_lines(text, filename, errs, span=None, exempt_keys=()):
    lo, hi = (0, len(text)) if span is None else span
    for lineno, line in enumerate(text[lo:hi].splitlines(), start=1 + text[:lo].count("\n")):
        if CJK.search(line):
            # A language switcher shows the OTHER language's name in that
            # language ("中文" on the English UI) — the one sanctioned CJK
            # occurrence inside STR.en.
            if any(re.search(rf"\b{k}\s*:", line) for k in exempt_keys):
                continue
            errs.append(f"{filename}:{lineno}: CJK codepoint in a file that must stay translate-free")


def str_language_blocks(src, errs):
    """Return (en_keys, zh_keys, en_span) for the STR object in i18n.js."""
    frames = js_frames(src)
    str_frames = [(s, e, k) for s, e, k in frames if "en" in k and "zh" in k]
    if not str_frames:
        errs.append("prototype/i18n.js: no STR object with en/zh blocks found")
        return set(), set(), None
    start, end, _keys = max(str_frames, key=lambda f: f[1] - f[0])
    inner = [(s, e, k) for s, e, k in frames if start < s and e < end]
    # direct children of STR: not contained in any other inner frame
    kids = [f for f in inner if not any(g is not f and g[0] <= f[0] and f[1] <= g[1] for g in inner)]
    kids.sort(key=lambda f: f[0])
    if len(kids) != 2:
        errs.append(f"prototype/i18n.js: expected exactly the en/zh blocks inside STR, found {len(kids)}")
        return set(), set(), None
    return set(kids[0][2]), set(kids[1][2]), (kids[0][0], kids[0][1])


def main():
    errs = []

    # 1. index.html holds no CJK at all
    index_src = (REPO / "prototype" / "index.html").read_text(encoding="utf-8")
    cjk_lines(index_src, "prototype/index.html", errs)

    # 2-3. STR language blocks in i18n.js
    i18n_src = (REPO / "prototype" / "i18n.js").read_text(encoding="utf-8")
    en_keys, zh_keys, en_span = str_language_blocks(i18n_src, errs)
    if en_span:
        cjk_lines(i18n_src, "prototype/i18n.js (STR.en)", errs, span=en_span, exempt_keys=("langOther",))
    for k in sorted(en_keys - zh_keys):
        errs.append(f"prototype/i18n.js: key '{k}' has no zh translation")
    for k in sorted(zh_keys - en_keys):
        errs.append(f"prototype/i18n.js: key '{k}' has no en entry")

    # 4. every T("key") in index.html resolves, and every key is used
    used = set(re.findall(r'\bT\(\s*"([A-Za-z_$][\w$]*)"\s*\)', index_src))
    for k in sorted(used - en_keys):
        errs.append(f'prototype/index.html: T("{k}") has no STR entry')
    for k in sorted(en_keys - used):
        errs.append(f'prototype/i18n.js: STR key "{k}" is never used')

    # 5. {en, zh} object parity in the JS data files
    localized_js_errors(i18n_src, "prototype/i18n.js", errs)
    overlay_src = (REPO / "prototype" / "overlay.js").read_text(encoding="utf-8")
    localized_js_errors(overlay_src, "prototype/overlay.js", errs)

    # 6. registry localized objects carry both languages, non-empty
    for path in sorted((REPO / "registry").glob("*.json")):
        if path.name == "manifest.json":
            continue

        def walk(node, where):
            if isinstance(node, dict):
                if "en" in node or "zh" in node:
                    for lang in ("en", "zh"):
                        if not isinstance(node.get(lang), str) or not node[lang].strip():
                            errs.append(f"registry/{path.name}: {where} localized object missing non-empty '{lang}'")
                for k, v in node.items():
                    walk(v, f"{where}.{k}")
            elif isinstance(node, list):
                for idx, v in enumerate(node):
                    walk(v, f"{where}[{idx}]")

        walk(json.loads(path.read_text(encoding="utf-8")), path.stem)

    if errs:
        print("i18n check FAILED:")
        for e in errs:
            print(f"  - {e}")
        return 1
    print(f"i18n OK: index.html CJK-free, {len(en_keys)} STR keys in both languages, "
          f"{len(used)} T() references resolve, registry localized objects complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
