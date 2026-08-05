"""Helper tipis di atas `sysdig` untuk membaca capture .scap.

Capture ini dibuat dengan snaplen 80 byte, artinya tiap buffer I/O yang
tertangkap dipotong di 80 byte pertama. Jadi:

  * write/read <= 80 byte  -> utuh, bisa direkonstruksi byte-exact
  * write/read >  80 byte  -> cuma dapat 80 byte pertama

Seluruh solve bergantung pada fakta itu, jadi helper di sini sengaja
mengekspos `snaplen_report()` untuk memverifikasinya.
"""

import re
import shutil
import subprocess

HEXLINE = re.compile(r"^\s*0x[0-9a-f]{4}:\s+([0-9a-f ]+)$")


class SysdigError(RuntimeError):
    pass


def _sysdig(capture, filt, extra):
    if shutil.which("sysdig") is None:
        raise SysdigError("`sysdig` tidak ditemukan di PATH (apt install sysdig)")
    cmd = ["sysdig", "-r", str(capture)] + extra + [filt]
    proc = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    if proc.returncode != 0 and not proc.stdout:
        raise SysdigError(f"sysdig gagal: {proc.stderr.strip()[:400]}")
    return proc.stdout


def fields(capture, filt, fmt):
    """Jalankan sysdig dengan -p <fmt>, kembalikan list baris."""
    out = _sysdig(capture, filt, ["-p", fmt])
    return [ln for ln in out.splitlines() if ln.strip()]


def payload(capture, filt):
    """Gabungkan semua buffer data= dari event yang match, urut kejadian.

    sysdig -x mencetak hexdump payload di bawah event exit (`< write`/`< read`).
    Event enter tidak punya data, jadi aman untuk digabung apa adanya.
    """
    out = _sysdig(capture, filt, ["-x"])
    chunks = []
    for line in out.splitlines():
        m = HEXLINE.match(line)
        if m:
            chunks.append(m.group(1).replace(" ", ""))
    return bytes.fromhex("".join(chunks))


def snaplen_report(capture, filt):
    """(jumlah_buffer, panjang_maksimum) -- untuk membuktikan batas snaplen."""
    out = _sysdig(capture, filt, ["-x"])
    sizes, cur = [], 0
    for line in out.splitlines():
        m = HEXLINE.match(line)
        if m:
            cur += len(m.group(1).replace(" ", "")) // 2
        elif cur:
            sizes.append(cur)
            cur = 0
    if cur:
        sizes.append(cur)
    return len(sizes), (max(sizes) if sizes else 0)
