import sys

from Crypto.Cipher import AES


def decrypt_malware_file(input_path, output_path, hex_key):
    try:
        # Konversi hex key string ke bytes (16 byte untuk AES-128)
        key = bytes.fromhex(hex_key)

        if len(key) != 16:
            print("Error: Key harus 16 byte (32 karakter hex)!")
            return

        with open(input_path, "rb") as f:
            file_data = f.read()

        if len(file_data) < 34:  # 18 (header+IV) + minimal data + 16 (Tag)
            print("Error: File terlalu kecil, bukan file dari malware ini.")
            return

        # 1. Ekstrak IV (12 byte setelah 6 byte pertama)
        # Offset: [6 sampai 18]
        iv = file_data[6:18]

        # 2. Ekstrak Tag (16 byte terakhir)
        tag = file_data[-16:]

        # 3. Ekstrak Ciphertext (di antara IV dan Tag)
        ciphertext = file_data[18:-16]

        print(f"[*] IV ditemukan: {iv.hex()}")
        print(f"[*] Tag ditemukan: {tag.hex()}")

        # 4. Inisialisasi AES-GCM
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

        # 5. Dekripsi dan Verifikasi
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        with open(output_path, "wb") as f:
            f.write(decrypted_data)

        print(f"[+] Sukses! File didekripsi menjadi: {output_path}")

    except ValueError:
        print("[-] Gagal: Key salah atau data telah dimodifikasi (Tag mismatch).")
    except Exception as e:
        print(f"[-] Terjadi kesalahan: {e}")


# --- PENGGUNAAN ---
# Ganti dengan Key yang kamu dapatkan dari analisis (format hex)
KEY_HEX = "4b38665a703251774c6d334e37725839"
FILE_TARGET = "halo.txt.malrev"
FILE_RESULT = "hasil_dekripsi.txt"

if __name__ == "__main__":
    decrypt_malware_file(FILE_TARGET, FILE_RESULT, KEY_HEX)
