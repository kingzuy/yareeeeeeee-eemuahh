Baik, berikut adalah kode lengkap untuk **Soal 1, 2, dan 3** yang menggunakan struktur OOP dengan blok `if __name__ == "__main__":` sebagai entry point (titik masuk) program.

Struktur ini adalah standar yang baik (best practice) dalam pemrograman Python, menjaga agar definisi Class terpisah dari kode eksekusi utama.

### 1. Soal 1: Class Book

```python
class Book:
    def __init__(self, isbn, title, author, publisher, pages, price):
        # [cite_start]Instance attribute [cite: 125-132]
        self.isbn = isbn
        self.title = title
        self.author = author
        self.publisher = publisher
        self.pages = pages
        self.price = price

    def view(self):
        # [cite_start]Method view menampilkan data [cite: 133-134]
        print("=== Detail Buku ===")
        print(f"ISBN      : {self.isbn}")
        print(f"Title     : {self.title}")
        print(f"Author    : {self.author}")
        print(f"Publisher : {self.publisher}")
        print(f"Pages     : {self.pages}")
        print(f"Price     : Rp {self.price:,}")
        print()

# --- Entry Point ---
if __name__ == "__main__":
    # [cite_start]Membuat 4 buah objek [cite: 135]
    buku1 = Book("978-602-03", "Dilan 1990", "Pidi Baiq", "Pastel Books", 330, 79000)
    buku2 = Book("978-979-22", "Laskar Pelangi", "Andrea Hirata", "Bentang", 529, 85000)
    buku3 = Book("978-006-24", "Hidden Figures", "Margot Lee", "HarperCollins", 368, 150000)
    buku4 = Book("978-144-93", "Fluent Python", "Luciano Ramalho", "O'Reilly", 792, 650000)

    # Menjalankan method view
    buku1.view()
    buku2.view()
    buku3.view()
    buku4.view()

```

---

### 2. Soal 2: Class Segitiga Siku-Siku (Encapsulation)

```python
import math

class SegitigaSikuSiku:
    def __init__(self, alas, tinggi):
        # Menggunakan setter untuk inisialisasi agar tervalidasi
        self.alas = alas
        self.tinggi = tinggi

    # [cite_start]Accessor & Mutator untuk Alas [cite: 138, 140-143]
    @property
    def alas(self):
        return self._alas

    @alas.setter
    def alas(self, value):
        if value > 0:
            self._alas = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # [cite_start]Accessor & Mutator untuk Tinggi [cite: 139, 140-143]
    @property
    def tinggi(self):
        return self._tinggi

    @tinggi.setter
    def tinggi(self, value):
        if value > 0:
            self._tinggi = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # [cite_start]Accessor Hipotenusa [cite: 144]
    @property
    def hipotenusa(self):
        return math.sqrt((self.alas ** 2) + (self.tinggi ** 2))

    # [cite_start]Accessor Keliling [cite: 144]
    @property
    def keliling(self):
        return self.alas + self.tinggi + self.hipotenusa

    # [cite_start]Method Luas [cite: 145]
    def luas(self):
        return 0.5 * self.alas * self.tinggi

    def view(self):
        # [cite_start]Menampilkan output sesuai format [cite: 146-151]
        print(f"Alas       : {self.alas}")
        print(f"Tinggi     : {self.tinggi}")
        print(f"Hipotenusa : {self.hipotenusa:.2f}")
        print(f"Keliling   : {self.keliling:.2f}")
        print(f"Luas       : {self.luas():.2f}")
        print("-" * 25)

# --- Entry Point ---
if __name__ == "__main__":
    print("=== Soal 2: Segitiga Siku-Siku ===")
    try:
        # Objek 1: Valid
        segitiga1 = SegitigaSikuSiku(3, 4)
        segitiga1.view()

        # Objek 2: Valid
        segitiga2 = SegitigaSikuSiku(5, 12)
        segitiga2.view()

        # Objek 3: Error Test (Uncomment baris bawah untuk tes error)
        # segitiga_error = SegitigaSikuSiku(-5, 10) 

    except ValueError as e:
        print(f"Terjadi Kesalahan: {e}")

```

---

### 3. Soal 3: Logic Program (Controller)

```python
class RoomController:
    def __init__(self, suhu, intensitas_suara):
        # [cite_start]Constructor menerima input [cite: 159]
        self.suhu = suhu
        self.intensitas_suara = intensitas_suara

    def calculate(self):
        [cite_start]# [cite: 160] Method calculate()
        
        # [cite_start]1. Menentukan Status Suhu [cite: 155]
        if self.suhu < 18:
            status_suhu = "Dingin"
        elif 18 <= self.suhu <= 30:
            status_suhu = "Normal"
        else:
            status_suhu = "Panas"

        # [cite_start]2. Menentukan Status Kebisingan [cite: 155]
        if self.intensitas_suara < 40:
            status_bising = "Tenang"
        elif 40 <= self.intensitas_suara <= 60:
            status_bising = "Normal"
        else:
            status_bising = "Berisik"

        # [cite_start]3. Menentukan Status Ventilasi berdasarkan Logika Tabel [cite: 155-156]
        status_ventilasi = "Off"  # Default

        if status_suhu == "Dingin":
            # Dingin: On jika >= 40 (Normal/Berisik)
            if status_bising in ["Normal", "Berisik"]:
                status_ventilasi = "On"
        
        elif status_suhu == "Normal":
            # Normal: On hanya jika Berisik (>60)
            if status_bising == "Berisik":
                status_ventilasi = "On"
        
        elif status_suhu == "Panas":
            # Panas: Selalu On (>30 derajat)
            status_ventilasi = "On"

        # Output Hasil
        print(f"Input -> Suhu: {self.suhu}, Suara: {self.intensitas_suara}")
        print(f"  Status Suhu      : {status_suhu}")
        print(f"  Status Kebisingan: {status_bising}")
        print(f"  Status Ventilasi : {status_ventilasi}")
        print("-" * 30)

# --- Entry Point ---
if __name__ == "__main__":
    print("=== Soal 3: Room Controller ===")
    
    # Tes Kasus 1: Dingin, Tenang (<18, <40) -> Off
    c1 = RoomController(16, 30)
    c1.calculate()

    # Tes Kasus 2: Dingin, Normal (<18, 50) -> On
    c2 = RoomController(16, 50)
    c2.calculate()

    # Tes Kasus 3: Normal, Normal (25, 50) -> Off
    c3 = RoomController(25, 50)
    c3.calculate()

    # Tes Kasus 4: Panas, Apapun (35, 30) -> On
    c4 = RoomController(35, 30)
    c4.calculate()

```
