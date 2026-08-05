#!/usr/bin/env python3
r"""Deobfuscator statis untuk stage-1 (`auto_clean.deb`).

Payload aslinya ~600 KB hasil bashfuscator. Script ini HANYA mem-parsing
teks, tidak pernah mengeksekusi apa pun.

Tiga lapis:

  L0  wrapper       __=$(())&&${!__}<<<${!__}\<\<\<\$\'...\'
                    -> ${!__} = ${!0} = $0 = "bash", jadi: bash <<< bash <<< $'...'

  L1  aritmatika    $((~$(())))                = ~0  = -1
                    $((~$(( -1 * n ))))        = ~-n = n-1
                    Jadi tiap grup berisi n unit bernilai (n-1) -> satu digit oktal.
                    $(())                      = 0
                    Hasilnya string $'\NNN\NNN...' -> decode oktal.

  L2  XOR           _d = hex data, _k = hex key (repeating-key XOR), lalu eval.

Usage:  python3 deob_stage1.py payloads/auto_clean.deb.obfuscated
"""

import argparse
import re
import sys

UNIT = "$((~$(())))"
GROUP = re.compile(r"\$\(\(~\$\(\(((?:\$\(\(~\$\(\(\)\)\)\))+)\)\)\)\)")
OCTAL = re.compile(r"\\{1,2}([0-7]{1,3})")


def strip_wrapper(raw):
    """Buang L0, sisakan isi $'...'."""
    marker = "\\$\\'"
    if marker not in raw:
        raise ValueError("wrapper bashfuscator tidak dikenali")
    body = raw[raw.index(marker) + len(marker):]
    return body[:-2] if body.endswith("\\'") else body


def decode_arithmetic(body):
    """L1: grup aritmatika -> digit, $(()) -> 0, escape oktal -> byte."""
    s = GROUP.sub(lambda m: str(m.group(1).count(UNIT) - 1), body)
    s = s.replace("$(())", "0")
    if "$((" in s:
        raise ValueError("masih ada ekspresi aritmatika yang belum ter-decode")
    return OCTAL.sub(lambda m: chr(int(m.group(1), 8)), s)


def decode_xor(layer):
    """L2: repeating-key XOR dari variabel _d / _k."""
    d = re.search(r"_d=([0-9a-f]+)", layer)
    k = re.search(r"_k=([0-9a-f]+)", layer)
    if not (d and k):
        raise ValueError("variabel _d/_k tidak ditemukan di layer XOR")
    data, key = bytes.fromhex(d.group(1)), bytes.fromhex(k.group(1))
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def deobfuscate(raw):
    return decode_xor(decode_arithmetic(strip_wrapper(raw)))


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("payload", help="file stage-1 terobfuskasi")
    ap.add_argument("-o", "--output", help="tulis hasil ke file")
    args = ap.parse_args()

    raw = open(args.payload, encoding="utf-8", errors="replace").read()
    plain = deobfuscate(raw)
    if args.output:
        open(args.output, "wb").write(plain)
        print(f"[+] {len(raw)} B -> {len(plain)} B  ditulis ke {args.output}", file=sys.stderr)
    else:
        sys.stdout.write(plain.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
