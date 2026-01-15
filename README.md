### **Soal 1: Class Book (Versi Simpel)**

```python
class Book:
    def __init__(self, isbn, title, author, publisher, pages, price):
        self.isbn = isbn
        self.title = title
        self.author = author
        self.publisher = publisher
        self.pages = pages
        self.price = price

    def view(self):
        print("=== Book Details ===")
        print(f"ISBN      : {self.isbn}")
        print(f"Title     : {self.title}")
        print(f"Author    : {self.author}")
        print(f"Publisher : {self.publisher}")
        print(f"Pages     : {self.pages}")
        print(f"Price     : Rp {self.price:,}")
        print()

# --- Langsung eksekusi di sini ---
buku1 = Book("978-1", "Python Dasar", "Budi Santoso", "Informatika", 200, 50000)
buku2 = Book("978-2", "Algoritma", "Rina Wati", "Andi Offset", 350, 75000)
buku3 = Book("978-3", "AI Modern", "Joko Anwar", "Elex Media", 500, 120000)
buku4 = Book("978-4", "Data Science", "Siti Aminah", "Salemba", 420, 95000)

buku1.view()
buku2.view()
buku3.view()
buku4.view()

```

---

### **Soal 2: Class SegitigaSikuSiku (Versi Simpel)**

```python
import math

class SegitigaSikuSiku:
    def __init__(self, alas, tinggi):
        self.alas = alas
        self.tinggi = tinggi

    # Accessor & Mutator untuk Alas
    @property
    def alas(self):
        return self._alas

    @alas.setter
    def alas(self, value):
        if value > 0:
            self._alas = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # Accessor & Mutator untuk Tinggi
    @property
    def tinggi(self):
        return self._tinggi

    @tinggi.setter
    def tinggi(self, value):
        if value > 0:
            self._tinggi = value
        else:
            raise ValueError("Nilai alas dan tinggi harus positif")

    # Property Hipotenusa & Keliling
    @property
    def hipotenusa(self):
        return math.sqrt((self.alas ** 2) + (self.tinggi ** 2))

    @property
    def keliling(self):
        return self.alas + self.tinggi + self.hipotenusa

    def luas(self):
        return 0.5 * self.alas * self.tinggi

    def view(self):
        print(f"Alas       : {self.alas}")
        print(f"Tinggi     : {self.tinggi}")
        print(f"Hipotenusa : {self.hipotenusa:.2f}")
        print(f"Keliling   : {self.keliling:.2f}")
        print(f"Luas       : {self.luas():.2f}")
        print("-" * 20)

# --- Langsung eksekusi di sini ---
print("=== Soal 2: Segitiga ===")
try:
    segitiga1 = SegitigaSikuSiku(3, 4)
    segitiga1.view()

    segitiga2 = SegitigaSikuSiku(5, 12)
    segitiga2.view()
except ValueError as e:
    print(f"Error: {e}")

```

---

### **Soal 3: Logic Program (Versi Simpel)**

```python
class RoomController:
    def __init__(self, suhu, intensitas_suara):
        self.suhu = suhu
        self.intensitas_suara = intensitas_suara

    def calculate(self):
        # Logika Suhu
        if self.suhu < 18:
            status_suhu = "Dingin"
        elif 18 <= self.suhu <= 30:
            status_suhu = "Normal"
        else:
            status_suhu = "Panas"

        # Logika Kebisingan
        if self.intensitas_suara < 40:
            status_bising = "Tenang"
        elif 40 <= self.intensitas_suara <= 60:
            status_bising = "Normal"
        else:
            status_bising = "Berisik"

        # Logika Ventilasi (Sesuai Tabel)
        status_ventilasi = "Off" 

        if status_suhu == "Dingin" and status_bising in ["Normal", "Berisik"]:
            status_ventilasi = "On"
        elif status_suhu == "Normal" and status_bising == "Berisik":
            status_ventilasi = "On"
        elif status_suhu == "Panas":
             status_ventilasi = "On"

        print(f"Input: Suhu={self.suhu}, Suara={self.intensitas_suara}")
        print(f"-> Status Suhu      : {status_suhu}")
        print(f"-> Status Kebisingan: {status_bising}")
        print(f"-> Status Ventilasi : {status_ventilasi}")
        print("-" * 30)

# --- Langsung eksekusi di sini ---
print("=== Soal 3: Controller ===")
kasus1 = RoomController(10, 30)
kasus1.calculate()

kasus2 = RoomController(10, 50)
kasus2.calculate()

kasus3 = RoomController(25, 30)
kasus3.calculate()

kasus4 = RoomController(35, 70)
kasus4.calculate()

```
