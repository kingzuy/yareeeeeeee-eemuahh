# Disk Image Analysis

## Pengertian
Disk image analysis adalah proses menganalisis salinan (image) dari media penyimpanan seperti hard disk, SSD, atau flash drive tanpa mengubah data asli. Disk image biasanya merupakan hasil cloning secara bit-by-bit dari media asli.

Tujuan utama:
- Menjaga integritas data asli
- Melakukan investigasi forensik
- Menganalisis aktivitas sistem

---

## Jenis Disk Image

### 1. RAW / DD (.img, .dd)
- Format paling sederhana
- Salinan byte-per-byte
- Tidak memiliki metadata tambahan

### 2. E01 (EnCase Image)
- Format forensik terkompresi
- Mendukung metadata
- Memiliki checksum untuk integritas

### 3. AFF (Advanced Forensic Format)
- Open-source
- Lebih fleksibel dibanding E01
- Mendukung kompresi dan metadata

---

## Komponen yang Dianalisis

### 1. File System
Contoh:
- NTFS
- FAT32
- EXT4

### 2. File
- File aktif
- File tersembunyi
- File sistem

### 3. Deleted Files
- File yang sudah dihapus namun masih dapat direcover

### 4. Metadata
- Created time
- Modified time
- Accessed time
- Owner

### 5. Unallocated Space
- Area kosong yang masih menyimpan data lama

### 6. Slack Space
- Sisa ruang dalam cluster file

### 7. Artefak Sistem
- Browser history
- Log sistem
- Registry
- Credential

---

## Tools yang Digunakan

### GUI Tools
- Autopsy
- FTK Imager

### CLI Tools
- The Sleuth Kit
- foremost
- bulk_extractor

---

## Teknik Analisis

### 1. File Browsing
Melihat isi file system seperti file explorer

### 2. File Carving
Mengambil file langsung dari raw data tanpa bergantung pada file system

### 3. Keyword Searching
Mencari string tertentu seperti:
- password
- flag
- username

### 4. Timeline Analysis
Mengurutkan aktivitas berdasarkan waktu

### 5. Hash Analysis
Membandingkan hash file dengan database known file

---

## Workflow Disk Image Analysis

### 1. Verifikasi Image
- Hitung hash (MD5/SHA256)
- Pastikan integritas data

### 2. Identifikasi File System
- Tentukan jenis file system

### 3. Mount Image
- Gunakan mode read-only

### 4. Eksplorasi File System
- Cari file mencurigakan
- Periksa direktori penting

### 5. Recovery Deleted Files
- Gunakan teknik carving

### 6. Analisis Artefak
- Browser
- Log
- Registry

### 7. Timeline Analysis
- Rekonstruksi aktivitas pengguna

---

## Konsep Penting

### Partition Table
Struktur yang mengatur pembagian disk

### MFT (Master File Table)
Database utama pada NTFS yang menyimpan informasi file

### Unallocated Space
Ruang kosong yang dapat berisi data lama

### Slack Space
Ruang sisa dalam cluster file

---

## Contoh Kasus

Input:
- file disk.img

Analisis:
- Menemukan file yang dihapus
- Mengambil file tersembunyi
- Menemukan password dalam artefak
- Mengidentifikasi aktivitas mencurigakan

---

## Kesimpulan

Disk image analysis merupakan teknik penting dalam digital forensik untuk:
- Menganalisis isi media penyimpanan
- Mengambil data yang tersembunyi atau terhapus
- Mere konstruksi aktivitas sistem

Pendekatan yang sistematis dan penggunaan tools yang tepat sangat penting untuk mendapatkan hasil analisis yang akurat.
