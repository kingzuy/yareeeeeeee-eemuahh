Berikut adalah penyelesaian untuk **Soal 1**, **Soal 2**, dan **Soal 3** berdasarkan dokumen *Responsi Praktikum Pemrograman Python TK02.pdf* yang kamu unggah.

---

### **Soal 1: Class Book**

Membuat class `Book` dengan atribut yang ditentukan, method `view`, dan 4 objek contoh .

```python
class Book:
    def __init__(self, isbn, title, author, publisher, pages, price):
        # [cite_start]Instance attributes [cite: 125-132]
        self.isbn = isbn
        self.title = title
        self.author = author
        self.publisher = publisher
        self.pages = pages
        self.price = price

    def view(self):
        # [cite_start]Method untuk menampilkan semua data [cite: 133-134]
        print("=== Book Details ===")
        print(f"ISBN      : {self.isbn}")
        print(f"Title     : {self.title}")
        print(f"Author    : {self.author}")
        print(f"Publisher : {self.publisher}")
        print(f"Pages     : {self.pages}")
        print(f"Price     : Rp {self.price:,}")
        print()

# [cite_start]Membuat 4 buah objek [cite: 135]
buku1 = Book("978-1", "Python Dasar", "Budi Santoso", "Informatika", 200, 50000)
buku2 = Book("978-2", "Algoritma", "Rina Wati", "Andi Offset", 350, 75000)
buku3 = Book("978-3", "AI Modern", "Joko Anwar", "Elex Media", 500, 120000)
buku4 = Book("978-4", "Data Science", "Siti Aminah", "Salemba", 420, 95000)

# Menjalankan method view
buku1.view()
buku2.view()
buku3.view()
buku4.view()

```

---

### **Soal 2: Class SegitigaSikuSiku**

Menggunakan konsep *encapsulation* (private attribute), *decorator* `@property` untuk accessor & mutator, serta validasi error `ValueError` .

```python
import math

class SegitigaSikuSiku:
    def __init__(self, alas, tinggi):
        # Inisialisasi menggunakan setter untuk validasi otomatis
        self.alas = alas
        self.tinggi = tinggi

    # --- Property Alas ---
    @property
    def alas(self):
        [cite_start]return self._alas  # Accessor [cite: 138]

    @alas.setter
    def alas(self, value):
        # [cite_start]Mutator dengan validasi [cite: 142]
        if value > 0:
            self._alas = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # --- Property Tinggi ---
    @property
    def tinggi(self):
        [cite_start]return self._tinggi # Accessor [cite: 139]

    @tinggi.setter
    def tinggi(self, value):
        # [cite_start]Mutator dengan validasi [cite: 142]
        if value > 0:
            self._tinggi = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # --- Accessor Hipotenusa & Keliling ---
    @property
    def hipotenusa(self):
        # [cite_start]Rumus sqrt((alas**2) + (tinggi**2)) [cite: 144]
        return math.sqrt((self.alas ** 2) + (self.tinggi ** 2))

    @property
    def keliling(self):
        # [cite_start]Rumus alas + tinggi + hipotenusa [cite: 144]
        return self.alas + self.tinggi + self.hipotenusa

    # --- Method Luas ---
    def luas(self):
        # [cite_start]Rumus 0.5 * alas * tinggi [cite: 145]
        return 0.5 * self.alas * self.tinggi

    def view(self):
        # [cite_start]Output menampilkan nilai [cite: 146-151]
        print(f"Alas       : {self.alas}")
        print(f"Tinggi     : {self.tinggi}")
        print(f"Hipotenusa : {self.hipotenusa:.2f}")
        print(f"Keliling   : {self.keliling:.2f}")
        print(f"Luas       : {self.luas():.2f}")
        print("-" * 20)

# Contoh Penggunaan
try:
    segitiga1 = SegitigaSikuSiku(3, 4)
    segitiga1.view()

    segitiga2 = SegitigaSikuSiku(5, 12)
    segitiga2.view()
    
    # Contoh Error (akan mentrigger ValueError)
    # segitiga_error = SegitigaSikuSiku(-5, 10) 
except ValueError as e:
    print(f"Error: {e}")

```

---

### **Soal 3: Logic Program (Smart Controller)**

Menerjemahkan tabel logika Suhu dan Kebisingan menjadi program OOP .

```python
class RoomController:
    def __init__(self, suhu, intensitas_suara):
        # [cite_start]Nilai dimasukkan melalui constructor [cite: 159]
        self.suhu = suhu
        self.intensitas_suara = intensitas_suara

    def calculate(self):
        # [cite_start]Menentukan Status Suhu [cite: 155]
        if self.suhu < 18:
            status_suhu = "Dingin"
        elif 18 <= self.suhu <= 30:
            status_suhu = "Normal"
        else: # > 30
            status_suhu = "Panas"

        # [cite_start]Menentukan Status Kebisingan [cite: 155]
        if self.intensitas_suara < 40:
            status_bising = "Tenang"
        elif 40 <= self.intensitas_suara <= 60:
            status_bising = "Normal"
        else: # > 60
            status_bising = "Berisik"

        # [cite_start]Menentukan Status Ventilasi berdasarkan Tabel [cite: 155-156]
        # Logic Ventilasi "On":
        # 1. (Dingin) AND (Normal atau Berisik)
        # 2. (Normal) AND (Berisik)
        # 3. (Panas) -> Selalu On
        
        status_ventilasi = "Off" # Default Off

        if status_suhu == "Dingin":
            if status_bising in ["Normal", "Berisik"]:
                status_ventilasi = "On"
        elif status_suhu == "Normal":
            if status_bising == "Berisik":
                status_ventilasi = "On"
        elif status_suhu == "Panas":
             status_ventilasi = "On"

        # Menampilkan Output
        print(f"Input: Suhu={self.suhu}, Suara={self.intensitas_suara}")
        print(f"-> Status Suhu      : {status_suhu}")
        print(f"-> Status Kebisingan: {status_bising}")
        print(f"-> Status Ventilasi : {status_ventilasi}")
        print("-" * 30)

# [cite_start]Test Cases sesuai tabel [cite: 155-156]
print("=== Soal 3 Output ===")
kasus1 = RoomController(10, 30) # Dingin, Tenang -> Off
kasus1.calculate()

kasus2 = RoomController(10, 50) # Dingin, Normal -> On
kasus2.calculate()

kasus3 = RoomController(25, 30) # Normal, Tenang -> Off
kasus3.calculate()

kasus4 = RoomController(35, 70) # Panas, Berisik -> On
kasus4.calculate()

```
