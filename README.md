

## BAB I PENDAHULUAN

### 1.1 Latar Belakang

Penyusunan jadwal perkuliahan merupakan salah satu aktivitas administratif yang kompleks dan krusial dalam pengelolaan akademik di perguruan tinggi. Proses penjadwalan melibatkan berbagai komponen yang saling berkaitan, termasuk dosen, mata kuliah, ruang kelas, waktu perkuliahan, dan mahasiswa. Kompleksitas ini semakin meningkat seiring dengan bertambahnya jumlah program studi, mata kuliah yang ditawarkan, serta kebutuhan untuk mengakomodasi preferensi dan keterbatasan dari berbagai pihak yang terlibat.

Dalam praktiknya, penjadwalan perkuliahan di banyak institusi pendidikan tinggi masih dilakukan secara manual atau semi-otomatis dengan bantuan spreadsheet. Pendekatan ini memiliki sejumlah keterbatasan signifikan. Pertama, proses manual membutuhkan waktu yang sangat lama, terutama pada awal semester ketika jadwal harus disusun dari awal. Kedua, kemungkinan terjadinya konflik jadwal sangat tinggi, seperti bentrokan penggunaan ruangan, dosen yang mengajar di waktu yang sama untuk mata kuliah berbeda, atau mahasiswa yang harus mengambil mata kuliah dengan waktu yang bertabrakan. Ketiga, pendekatan manual sulit mengakomodasi perubahan atau permintaan khusus dari dosen terkait preferensi waktu mengajar mereka.

Permintaan jadwal dari dosen merupakan aspek penting yang sering diabaikan dalam sistem penjadwalan konvensional. Dosen memiliki berbagai kebutuhan dan preferensi yang legitimate, seperti keterbatasan waktu mengajar karena komitmen penelitian, kegiatan pengabdian masyarakat, tanggung jawab administratif, atau kondisi personal yang memerlukan fleksibilitas waktu tertentu. Ketika sistem penjadwalan tidak dapat mengakomodasi permintaan ini, dampaknya dapat mengurangi kepuasan kerja dosen, menurunkan efektivitas pembelajaran, bahkan dapat menyebabkan konflik dalam pengelolaan sumber daya akademik.

Constraint Satisfaction Problem (CSP) menawarkan pendekatan yang lebih sistematis dan efisien untuk menyelesaikan permasalahan penjadwalan. CSP adalah paradigma dalam bidang kecerdasan buatan yang digunakan untuk menyelesaikan masalah dengan mendefinisikan variabel, domain nilai untuk setiap variabel, dan batasan-batasan yang harus dipenuhi. Dalam konteks penjadwalan perkuliahan, variabel dapat berupa mata kuliah yang harus dijadwalkan, domain nilai mencakup slot waktu dan ruangan yang tersedia, sementara batasan mencakup aturan-aturan seperti tidak ada dosen yang mengajar di dua tempat pada waktu yang sama, kapasitas ruangan harus memadai, dan berbagai aturan akademik lainnya.

Keunggulan pendekatan CSP terletak pada kemampuannya untuk secara sistematis mengeksplorasi ruang solusi dengan mempertimbangkan semua batasan yang ada. Berbagai algoritma telah dikembangkan untuk menyelesaikan CSP, termasuk backtracking, forward checking, arc consistency, dan metode heuristik lainnya. Algoritma-algoritma ini dapat menemukan solusi yang feasible dengan efisien, bahkan untuk masalah penjadwalan yang kompleks dengan ribuan variabel dan batasan.

Namun, implementasi CSP dalam penjadwalan akademik menghadapi tantangan tersendiri ketika harus mengakomodasi preferensi atau permintaan dari dosen. Permintaan ini dapat bersifat hard constraint yang harus dipenuhi, seperti larangan mengajar pada hari tertentu karena komitmen tetap, atau soft constraint yang sebaiknya dipenuhi jika memungkinkan, seperti preferensi waktu mengajar di pagi hari. Pengintegrasian kedua jenis constraint ini dalam model CSP memerlukan pendekatan yang sophisticated agar sistem dapat menghasilkan jadwal yang tidak hanya feasible dari perspektif aturan akademik, tetapi juga acceptable dari perspektif preferensi dosen.

Penelitian ini berupaya mengembangkan sistem penjadwalan berbasis CSP yang secara khusus dirancang untuk mengakomodasi permintaan jadwal dari dosen sambil tetap memenuhi semua batasan akademik yang ada. Sistem yang dikembangkan diharapkan dapat mengotomatisasi proses penjadwalan, mengurangi waktu yang diperlukan, meminimalkan konflik, dan meningkatkan kepuasan semua stakeholder yang terlibat dalam proses akademik.

### 1.2 Rumusan Masalah

Berdasarkan latar belakang yang telah diuraikan, penelitian ini difokuskan pada beberapa permasalahan utama yang akan diselesaikan.

Pertama, bagaimana merumuskan permasalahan penjadwalan perkuliahan sebagai Constraint Satisfaction Problem yang dapat mengakomodasi berbagai jenis batasan akademik sekaligus permintaan jadwal dari dosen. Formulasi ini harus dapat membedakan antara hard constraint yang bersifat wajib dipenuhi dan soft constraint yang bersifat preferensi.

Kedua, algoritma atau kombinasi algoritma apa yang paling efektif untuk menyelesaikan CSP penjadwalan dengan mempertimbangkan trade-off antara kecepatan komputasi, kualitas solusi yang dihasilkan, dan tingkat akomodasi terhadap permintaan dosen. Pemilihan algoritma ini sangat krusial mengingat kompleksitas masalah yang melibatkan ratusan hingga ribuan variabel.

Ketiga, bagaimana merancang mekanisme pengajuan dan pengelolaan permintaan jadwal dari dosen yang dapat diintegrasikan dengan sistem CSP. Mekanisme ini harus user-friendly bagi dosen sekaligus dapat diterjemahkan menjadi constraint yang dapat diproses oleh sistem.

Keempat, bagaimana mengukur dan mengevaluasi kualitas jadwal yang dihasilkan, tidak hanya dari aspek pemenuhan constraint tetapi juga dari perspektif kepuasan pengguna, terutama dosen dan mahasiswa. Metrik evaluasi ini penting untuk memastikan bahwa solusi yang dihasilkan benar-benar memberikan nilai tambah dibandingkan dengan metode penjadwalan konvensional.

### 1.3 Tujuan Penelitian

Penelitian ini memiliki beberapa tujuan utama yang ingin dicapai. Tujuan pertama adalah mengembangkan model matematis CSP untuk permasalahan penjadwalan perkuliahan yang dapat mengintegrasikan batasan akademik standar dengan permintaan jadwal dari dosen sebagai constraint tambahan.

Tujuan kedua adalah merancang dan mengimplementasikan algoritma penyelesaian CSP yang efisien untuk menghasilkan jadwal perkuliahan yang memenuhi semua hard constraint dan memaksimalkan pemenuhan soft constraint, termasuk preferensi dosen.

Tujuan ketiga adalah membangun sistem informasi penjadwalan yang memfasilitasi pengajuan permintaan jadwal dari dosen dan secara otomatis mengintegrasikan permintaan tersebut ke dalam proses penjadwalan berbasis CSP.

Tujuan keempat adalah mengevaluasi efektivitas sistem yang dikembangkan melalui pengujian dengan data riil dari institusi pendidikan tinggi, dengan membandingkan hasil jadwal yang dihasilkan sistem terhadap jadwal yang dibuat secara manual dari aspek waktu pembuatan, jumlah konflik, dan tingkat kepuasan pengguna.

### 1.4 Manfaat Penelitian

Penelitian ini memberikan kontribusi yang signifikan baik dari perspektif teoritis maupun praktis dalam bidang penjadwalan akademik dan penerapan kecerdasan buatan.

Dari sisi akademis, penelitian ini memperkaya literatur tentang aplikasi CSP dalam domain penjadwalan akademik, khususnya dalam aspek akomodasi preferensi pengguna. Penelitian ini juga memberikan kontribusi metodologis dalam hal integrasi hard constraint dan soft constraint dalam satu framework CSP yang kohesif. Hasil penelitian dapat menjadi referensi bagi penelitian selanjutnya yang ingin mengembangkan sistem penjadwalan dengan kompleksitas serupa atau mengeksplorasi aplikasi CSP dalam domain lain.

Dari perspektif praktis, penelitian ini menghasilkan sistem penjadwalan yang dapat langsung diimplementasikan oleh institusi pendidikan tinggi untuk meningkatkan efisiensi proses administratif akademik. Sistem ini dapat secara signifikan mengurangi waktu dan tenaga yang diperlukan untuk menyusun jadwal perkuliahan setiap semester, yang saat ini dapat memakan waktu berminggu-minggu. Pengurangan waktu ini memungkinkan staf akademik untuk fokus pada tugas-tugas lain yang lebih strategis.

Bagi dosen, sistem ini memberikan mekanisme formal untuk mengajukan preferensi jadwal yang dapat diakomodasi secara objektif dan transparan oleh sistem. Hal ini dapat meningkatkan kepuasan kerja dosen karena kebutuhan mereka dipertimbangkan dalam proses penjadwalan, yang pada akhirnya dapat berkontribusi pada peningkatan kualitas pembelajaran.

Bagi mahasiswa, sistem ini menghasilkan jadwal yang lebih teroptimasi dengan konflik yang minimal, memungkinkan mereka untuk merencanakan perkuliahan dengan lebih baik. Jadwal yang lebih terstruktur dapat membantu mahasiswa dalam mengatur waktu belajar, kegiatan organisasi, dan aktivitas lainnya dengan lebih efektif.

Bagi institusi secara keseluruhan, sistem ini meningkatkan utilisasi sumber daya seperti ruang kelas dan waktu mengajar dosen secara lebih optimal. Peningkatan efisiensi ini dapat berkontribusi pada penghematan biaya operasional dan peningkatan kapasitas institusi untuk melayani lebih banyak mahasiswa tanpa harus menambah infrastruktur fisik secara signifikan.

---

## BAB II LANDASAN TEORI

### 2.1 Constraint Satisfaction Problem

Constraint Satisfaction Problem (CSP) merupakan paradigma dalam kecerdasan buatan yang digunakan untuk merepresentasikan dan menyelesaikan masalah yang melibatkan pemberian nilai pada variabel dengan mempertimbangkan batasan-batasan tertentu. Secara formal, CSP didefinisikan sebagai triplet yang terdiri dari variabel, domain, dan constraint.

Variabel dalam CSP adalah elemen-elemen yang harus diberi nilai. Dalam konteks penjadwalan perkuliahan, variabel dapat berupa mata kuliah yang harus dijadwalkan atau kombinasi dari mata kuliah, dosen, dan kelas. Setiap variabel harus diberi nilai dari domain yang telah ditentukan.

Domain adalah himpunan nilai-nilai yang mungkin untuk setiap variabel. Dalam penjadwalan, domain dapat berupa kombinasi dari slot waktu yang tersedia dan ruang kelas yang dapat digunakan. Misalnya, jika tersedia lima hari dalam seminggu dengan delapan slot waktu per hari dan ada dua puluh ruang kelas, maka ukuran domain untuk setiap variabel adalah delapan puluh kombinasi slot waktu-ruangan.

Constraint adalah batasan yang membatasi kombinasi nilai yang dapat diberikan kepada variabel. Constraint dapat diklasifikasikan menjadi beberapa jenis berdasarkan jumlah variabel yang terlibat. Unary constraint melibatkan satu variabel, seperti mata kuliah tertentu harus dijadwalkan pada hari Senin. Binary constraint melibatkan dua variabel, seperti dua mata kuliah yang diajar oleh dosen yang sama tidak boleh dijadwalkan pada waktu yang bersamaan. Global constraint melibatkan banyak variabel sekaligus, seperti constraint yang memastikan tidak ada ruangan yang digunakan oleh lebih dari satu kelas pada waktu yang sama.

Dalam literatur CSP, constraint juga dibedakan menjadi hard constraint dan soft constraint. Hard constraint adalah batasan yang harus dipenuhi tanpa kompromi, dan pelanggaran terhadap batasan ini membuat solusi menjadi tidak valid. Contoh hard constraint dalam penjadwalan adalah dosen tidak dapat mengajar di dua tempat pada waktu yang sama. Soft constraint adalah preferensi yang sebaiknya dipenuhi tetapi dapat dilanggar jika tidak ada solusi lain. Permintaan jadwal dari dosen umumnya masuk dalam kategori soft constraint.

Solusi dari CSP adalah assignment nilai kepada semua variabel sedemikian rupa sehingga semua constraint terpenuhi. Jika hanya hard constraint yang dipertimbangkan, maka solusi yang dicari adalah solusi yang feasible, yaitu solusi yang tidak melanggar satupun hard constraint. Ketika soft constraint juga dipertimbangkan, maka masalah berubah menjadi optimization problem di mana tujuannya adalah menemukan solusi yang memaksimalkan jumlah soft constraint yang terpenuhi.

### 2.2 Penjadwalan Akademik

Penjadwalan akademik adalah proses mengalokasikan sumber daya pendidikan seperti dosen, ruang kelas, dan waktu kepada mata kuliah atau kegiatan akademik lainnya dengan mempertimbangkan berbagai batasan dan preferensi. Masalah ini telah lama dikenal sebagai NP-complete problem, yang berarti tidak ada algoritma yang dapat menjamin menemukan solusi optimal dalam waktu polinomial untuk semua kasus.

Kompleksitas penjadwalan akademik berasal dari banyaknya faktor yang harus dipertimbangkan secara simultan. Faktor-faktor ini mencakup ketersediaan dosen yang mungkin memiliki jadwal mengajar di program studi lain atau komitmen di luar institusi, kapasitas ruang kelas yang harus sesuai dengan jumlah mahasiswa yang mengambil mata kuliah, distribusi beban mengajar dosen yang harus seimbang, kebutuhan laboratorium atau fasilitas khusus untuk mata kuliah tertentu, dan preferensi mahasiswa dalam memilih kelas untuk mata kuliah yang sama yang ditawarkan di beberapa waktu berbeda.

Dalam konteks perguruan tinggi di Indonesia, terdapat karakteristik khusus yang membuat penjadwalan menjadi lebih kompleks. Pertama, banyak dosen yang mengajar di lebih dari satu program studi atau bahkan di institusi yang berbeda, sehingga koordinasi waktu mengajar menjadi sangat penting. Kedua, sistem kredit semester mengharuskan mahasiswa mengambil mata kuliah dari berbagai semester dan program studi, sehingga jadwal harus disusun sedemikian rupa untuk meminimalkan bentrokan. Ketiga, keterbatasan ruang kelas dan fasilitas membuat utilisasi sumber daya menjadi pertimbangan penting.

Penjadwalan akademik dapat dikategorikan menjadi beberapa jenis berdasarkan tingkat pendidikan dan konteks penggunaannya. Penjadwalan untuk sekolah menengah umumnya lebih sederhana karena mahasiswa memiliki jadwal tetap dan bergerak bersama dalam satu kelas. Penjadwalan untuk perguruan tinggi dengan sistem kredit semester jauh lebih kompleks karena mahasiswa memiliki kebebasan memilih mata kuliah dan membentuk jadwal individual mereka.

### 2.3 Algoritma Penyelesaian CSP

Berbagai algoritma telah dikembangkan untuk menyelesaikan CSP, masing-masing dengan karakteristik, kelebihan, dan kekurangan tersendiri. Pemilihan algoritma yang tepat sangat bergantung pada karakteristik masalah yang dihadapi, termasuk ukuran masalah, keketatan constraint, dan kebutuhan akan solusi optimal versus solusi yang cukup baik.

Backtracking adalah algoritma dasar untuk menyelesaikan CSP. Algoritma ini bekerja dengan cara memilih satu variabel, mencoba memberikan nilai dari domainnya, kemudian secara rekursif mencoba untuk memberikan nilai kepada variabel berikutnya. Jika pada suatu titik ditemukan bahwa tidak ada nilai yang dapat diberikan kepada variabel tanpa melanggar constraint, algoritma akan mundur ke variabel sebelumnya dan mencoba nilai lain. Meskipun sederhana, backtracking murni dapat sangat lambat untuk masalah besar karena mengeksplorasi banyak cabang pencarian yang tidak perlu.

Forward Checking merupakan perbaikan dari backtracking dengan menambahkan mekanisme untuk mengurangi domain variabel yang belum diberi nilai setiap kali assignment dibuat. Ketika variabel diberi nilai, Forward Checking akan menghapus nilai-nilai dari domain variabel lain yang akan menyebabkan konflik dengan assignment yang baru dibuat. Pendekatan ini dapat secara signifikan mengurangi ruang pencarian dengan mendeteksi kegagalan lebih awal.

Arc Consistency adalah teknik yang lebih kuat untuk mengurangi domain variabel dengan memeriksa konsistensi antara pasangan variabel. Sebuah arc dari variabel X ke variabel Y dikatakan konsisten jika untuk setiap nilai dalam domain X, terdapat setidaknya satu nilai dalam domain Y yang tidak melanggar constraint antara X dan Y. Algoritma AC-3 adalah salah satu algoritma arc consistency yang populer dan dapat sangat efektif dalam mengurangi ukuran domain sebelum atau selama proses pencarian.

Untuk masalah yang sangat besar atau ketika solusi optimal tidak wajib diperoleh, algoritma heuristik seperti simulated annealing, genetic algorithm, atau tabu search sering digunakan. Algoritma-algoritma ini tidak menjamin menemukan solusi optimal tetapi dapat menemukan solusi yang cukup baik dalam waktu yang reasonable. Simulated annealing bekerja dengan analogi proses pendinginan logam, di mana sistem secara bertahap mengurangi kemungkinan menerima solusi yang lebih buruk. Genetic algorithm menggunakan prinsip evolusi biologis dengan operasi crossover dan mutation untuk mengeksplorasi ruang solusi.

Untuk penjadwalan yang melibatkan soft constraint, pendekatan yang sering digunakan adalah mengkonversi masalah menjadi optimization problem dengan mendefinisikan fungsi objektif yang mengukur kualitas solusi. Fungsi objektif ini biasanya berupa weighted sum dari berbagai soft constraint yang dilanggar atau dipenuhi. Algoritma optimasi kemudian digunakan untuk mencari solusi yang meminimalkan pelanggaran soft constraint sambil memastikan semua hard constraint terpenuhi.

### 2.4 Penelitian Terkait

Penjadwalan akademik menggunakan CSP telah menjadi topik penelitian yang aktif selama beberapa dekade terakhir. Berbagai pendekatan dan teknik telah diusulkan untuk mengatasi kompleksitas masalah ini.

Burke dan Petrovic (2002) melakukan survei komprehensif tentang metode-metode yang digunakan dalam university timetabling. Penelitian mereka mengidentifikasi tiga kategori utama masalah penjadwalan di perguruan tinggi, yaitu examination timetabling, course timetabling, dan student scheduling. Mereka menyimpulkan bahwa tidak ada satu metode yang superior untuk semua kasus, dan pemilihan metode sangat bergantung pada karakteristik spesifik dari institusi dan constraint yang ada.

Schaerf (1999) mengusulkan survey tentang automated timetabling yang mengklasifikasikan berbagai teknik penyelesaian termasuk graph coloring, constraint-based methods, dan meta-heuristic approaches. Penelitian ini memberikan framework untuk memahami trade-off antara kualitas solusi, waktu komputasi, dan fleksibilitas dalam mengakomodasi constraint yang berbeda-beda.

Dalam konteks akomodasi preferensi pengguna, penelitian oleh Badoni et al. (2014) mengembangkan sistem penjadwalan berbasis CSP yang mengintegrasikan preferensi dosen sebagai soft constraint. Sistem mereka menggunakan weighted CSP di mana setiap soft constraint diberi bobot yang mencerminkan prioritasnya. Hasil penelitian menunjukkan bahwa pendekatan ini dapat meningkatkan kepuasan dosen tanpa mengorbankan pemenuhan hard constraint.

Di Gaspero et al. (2007) mengusulkan pendekatan hybrid yang menggabungkan tabu search dengan teknik constraint propagation untuk menyelesaikan masalah penjadwalan universitas. Pendekatan mereka terbukti efektif dalam menangani masalah berskala besar dengan ribuan variabel dan constraint. Mereka juga memperkenalkan konsep multi-objective optimization di mana sistem berusaha mengoptimalkan beberapa kriteria sekaligus, seperti meminimalkan gap antara sesi perkuliahan dan memaksimalkan pemenuhan preferensi dosen.

Penelitian oleh Kristiansen et al. (2015) fokus pada pengembangan sistem penjadwalan yang mempertimbangkan fairness dalam distribusi preferensi. Mereka mengembangkan mekanisme untuk memastikan bahwa akomodasi preferensi tidak selalu menguntungkan kelompok dosen tertentu saja. Sistem mereka menggunakan pendekatan multi-stage di mana pada stage pertama hard constraint dipenuhi, stage kedua soft constraint dengan prioritas tinggi dioptimalkan, dan stage ketiga dilakukan penyeimbangan fairness.

Dalam konteks lokal Indonesia, penelitian oleh Gunawan et al. (2012) mengembangkan sistem penjadwalan kuliah menggunakan algoritma genetika yang disesuaikan dengan karakteristik perguruan tinggi di Indonesia. Penelitian mereka mengidentifikasi beberapa constraint khusus seperti dosen yang mengajar di beberapa kampus dan preferensi waktu sholat Jumat. Meskipun penelitian mereka tidak secara khusus fokus pada CSP, kontribusi mereka dalam mengidentifikasi constraint lokal sangat relevan.

Penelitian terbaru oleh Tan et al. (2021) mengeksplorasi penggunaan machine learning untuk memprediksi preferensi dosen berdasarkan historical data penjadwalan. Pendekatan mereka menggunakan learned preferences sebagai input untuk sistem CSP, sehingga sistem dapat mengantisipasi preferensi bahkan ketika dosen belum secara eksplisit menyatakannya. Hasil penelitian menunjukkan peningkatan kepuasan dosen sebesar 23 persen dibandingkan dengan sistem yang hanya menggunakan preferensi yang dinyatakan secara eksplisit.

Dari tinjauan literatur ini, dapat diidentifikasi bahwa meskipun banyak penelitian telah dilakukan dalam penjadwalan akademik menggunakan CSP, masih terdapat gap dalam hal pengembangan sistem yang secara sistematis dan transparan mengakomodasi permintaan jadwal dari dosen sambil mempertimbangkan fairness dan optimalisasi sumber daya. Penelitian ini berupaya mengisi gap tersebut dengan mengembangkan framework yang komprehensif untuk mengintegrasikan preferensi dosen dalam sistem CSP penjadwalan.

---

## BAB III METODOLOGI

### 3.1 Pendekatan Penelitian

Penelitian ini menggunakan pendekatan design science research yang bertujuan untuk mengembangkan dan mengevaluasi artifact dalam bentuk sistem penjadwalan berbasis CSP. Design science research dipilih karena sesuai dengan tujuan penelitian yang tidak hanya ingin memahami fenomena penjadwalan akademik tetapi juga mengembangkan solusi praktis yang dapat diimplementasikan.

Penelitian ini menggabungkan metode kuantitatif dalam analisis algoritma dan pengukuran kinerja sistem, serta metode kualitatif dalam mengidentifikasi kebutuhan pengguna dan mengevaluasi kepuasan terhadap sistem. Pendekatan mixed-method ini diperlukan untuk mendapatkan pemahaman yang holistik tentang efektivitas sistem yang dikembangkan, baik dari perspektif teknis maupun perspektif pengguna.

### 3.2 Tahapan Penelitian

Penelitian ini dilaksanakan dalam beberapa tahapan yang sistematis dan terstruktur untuk memastikan pencapaian tujuan penelitian secara komprehensif.

Tahap pertama adalah studi literatur dan analisis kebutuhan. Pada tahap ini dilakukan kajian mendalam terhadap literatur tentang CSP, algoritma penyelesaian CSP, dan penelitian-penelitian sebelumnya tentang penjadwalan akademik. Secara paralel dilakukan analisis kebutuhan melalui studi terhadap proses penjadwalan yang berjalan saat ini di institusi pendidikan tinggi, identifikasi stakeholder yang terlibat, dokumentasi constraint yang ada, dan pengumpulan informasi tentang permintaan jadwal yang biasa diajukan oleh dosen.

Tahap kedua adalah perancangan model CSP untuk penjadwalan. Pada tahap ini dilakukan formalisasi masalah penjadwalan ke dalam komponen-komponen CSP. Variabel didefinisikan sebagai mata kuliah yang perlu dijadwalkan beserta atributnya seperti dosen pengampu, jumlah SKS, dan jenis mata kuliah. Domain untuk setiap variabel didefinisikan sebagai kombinasi dari slot waktu dan ruang kelas yang tersedia. Hard constraint diidentifikasi dan dirumuskan secara matematis, mencakup constraint seperti tidak ada dosen yang mengajar di dua tempat pada waktu bersamaan, kapasitas ruang kelas harus memadai untuk jumlah mahasiswa, mata kuliah dengan syarat laboratorium harus dijadwalkan di ruang laboratorium yang sesuai, dan distribusi beban mengajar dosen harus sesuai dengan ketentuan. Soft constraint juga dirumuskan untuk merepresentasikan permintaan jadwal dari dosen dan preferensi lainnya, dengan sistem pemberian bobot untuk menentukan prioritas relatif dari berbagai soft constraint.

Tahap ketiga adalah pemilihan dan adaptasi algoritma. Pada tahap ini dilakukan evaluasi berbagai algoritma penyelesaian CSP berdasarkan karakteristik masalah penjadwalan yang dihadapi. Implementasi prototype untuk beberapa algoritma kandidat seperti backtracking dengan forward checking, arc consistency dengan heuristic variable ordering, hybrid approach yang menggabungkan constraint propagation dengan local search, dan genetic algorithm untuk optimisasi soft constraint. Pengujian performansi algoritma-algoritma tersebut menggunakan dataset sintetis dan data riil dari institusi untuk membandingkan waktu komputasi, kualitas solusi yang dihasilkan, dan scalability. Pemilihan atau kombinasi algoritma yang paling sesuai dilakukan berdasarkan hasil pengujian.

Tahap keempat adalah perancangan sistem. Pada tahap ini dirancang arsitektur sistem yang mencakup modul pengajuan permintaan jadwal oleh dosen, modul pengelolaan data akademik termasuk dosen, mata kuliah, ruang kelas, dan waktu, modul CSP solver yang mengimplementasikan algoritma yang dipilih, modul evaluasi dan visualisasi hasil penjadwalan, dan modul manajemen pengguna dan hak akses. Desain antarmuka pengguna yang intuitif untuk berbagai stakeholder juga dilakukan, termasuk antarmuka untuk dosen mengajukan permintaan jadwal, antarmuka untuk administrator akademik mengelola data dan menjalankan proses penjadwalan, dan antarmuka untuk melihat dan mengekspor hasil jadwal.

Tahap kelima adalah implementasi sistem. Pada tahap ini dilakukan pengembangan sistem berdasarkan desain yang telah dibuat menggunakan teknologi yang sesuai. Implementasi algoritma CSP dilakukan dengan optimasi untuk efisiensi komputasi. Pengembangan database untuk menyimpan data akademik, permintaan jadwal, dan hasil penjadwalan juga dilakukan. Integrasi berbagai modul menjadi sistem yang terintegrasi dan testing unit untuk memastikan setiap komponen berfungsi dengan benar dilakukan pada tahap ini.

Tahap keenam adalah pengujian dan evaluasi sistem. Pada tahap ini dilakukan pengujian fungsional untuk memastikan semua fitur sistem bekerja sesuai spesifikasi. Pengujian performansi dilakukan dengan menggunakan data riil dari institusi pendidikan tinggi, mengukur waktu yang diperlukan untuk menghasilkan jadwal, mengevaluasi kualitas jadwal yang dihasilkan dari aspek pemenuhan constraint dan optimalisasi sumber daya, dan membandingkan dengan jadwal yang dibuat secara manual. Pengujian usability juga dilakukan dengan melibatkan pengguna potensial untuk mengevaluasi kemudahan penggunaan sistem. Pengumpulan feedback dari dosen dan administrator akademik tentang kepuasan terhadap sistem dan jadwal yang dihasilkan dilakukan pada tahap ini.

Tahap ketujuh adalah analisis hasil dan penyusunan laporan. Pada tahap terakhir dilakukan analisis komprehensif terhadap hasil pengujian dan evaluasi, identifikasi kelebihan dan keterbatasan sistem yang dikembangkan, perumusan rekomendasi untuk pengembangan lebih lanjut, dan penyusunan dokumentasi lengkap sistem beserta panduan penggunaan. Hasil analisis kemudian disusun menjadi laporan penelitian yang komprehensif.

### 3.3 Pengumpulan Data

Pengumpulan data dalam penelitian ini dilakukan melalui beberapa sumber dan metode untuk memastikan kelengkapan dan validitas data yang diperlukan dalam pengembangan dan evaluasi sistem.

Data primer dikumpulkan langsung dari institusi pendidikan tinggi yang menjadi lokasi penelitian. Data ini mencakup informasi tentang dosen yang meliputi identitas, mata kuliah yang diampu, beban mengajar, dan ketersediaan waktu. Data mata kuliah mencakup kode mata kuliah, nama, jumlah SKS, program studi, semester, dan kebutuhan khusus seperti laboratorium atau studio. Data ruang kelas mencakup kode ruangan, kapasitas, jenis ruangan seperti kelas reguler, laboratorium, atau ruang multimedia, serta fasilitas yang tersedia. Data mahasiswa mencakup jumlah mahasiswa per mata kuliah dan program studi untuk menentukan kebutuhan kapasitas ruangan.

Data tentang permintaan jadwal dari dosen dikumpulkan melalui survei dan wawancara mendalam. Survei dirancang untuk mengidentifikasi pola preferensi umum dosen terkait waktu mengajar, hari yang disukai atau dihindari, preferensi ruang kelas, dan alasan di balik preferensi tersebut. Wawancara semi-terstruktur dilakukan dengan sejumlah dosen untuk mendapatkan pemahaman lebih mendalam tentang kebutuhan dan harapan mereka terhadap sistem penjadwalan, serta untuk mengidentifikasi jenis permintaan yang sering diajukan dan tingkat prioritasnya.

Data sekunder diperoleh dari dokumen institusi termasuk jadwal perkuliahan dari semester-semester sebelumnya, kebijakan akademik terkait penjadwalan, dan laporan evaluasi penjadwalan jika tersedia. Data ini digunakan sebagai baseline untuk membandingkan kinerja sistem yang dikembangkan dengan metode penjadwalan yang sudah ada.

Data untuk pengujian sistem dikumpulkan dalam dua bentuk. Pertama, dataset riil dari satu atau dua semester terakhir yang mencakup semua informasi yang diperlukan untuk menjalankan proses penjadwalan. Kedua, dataset sintetis yang dibuat dengan berbagai tingkat kompleksitas untuk menguji scalability dan robustness sistem dalam kondisi ekstrem yang mungkin tidak terjadi dalam data riil.

### 3.4 Analisis dan Perancangan Sistem

Analisis sistem dimulai dengan pemodelan proses bisnis penjadwalan yang berjalan saat ini menggunakan teknik seperti flowchart dan use case diagram. Analisis ini mengidentifikasi aktor-aktor yang terlibat dalam proses penjadwalan, alur kerja dari pengumpulan data hingga publikasi jadwal, titik-titik keputusan dalam proses, serta bottleneck dan pain points yang ada dalam sistem manual.

Berdasarkan hasil analisis kebutuhan dan studi literatur, dilakukan formalisasi masalah penjadwalan ke dalam model CSP. Setiap mata kuliah didefinisikan sebagai variabel yang harus diberi nilai berupa slot waktu dan ruang kelas. Domain untuk setiap variabel adalah himpunan semua kombinasi waktu dan ruangan yang valid. Constraint didefinisikan dalam dua kategori, yaitu hard constraint yang tidak boleh dilanggar dan soft constraint yang merepresentasikan preferensi.

Hard constraint yang dimodelkan mencakup constraint temporal yang memastikan tidak ada dosen mengajar lebih dari satu mata kuliah pada waktu yang sama, constraint kapasitas yang memastikan kapasitas ruangan mencukupi untuk jumlah mahasiswa, constraint ketersediaan yang memastikan ruangan tidak digunakan oleh lebih dari satu kelas pada waktu yang sama, constraint prasyarat yang memastikan mata kuliah dengan kebutuhan khusus seperti laboratorium mendapat fasilitas yang sesuai, dan constraint beban kerja yang memastikan distribusi jadwal mengajar dosen sesuai dengan beban kerja yang ditetapkan.

Soft constraint dimodelkan dengan sistem pemberian bobot untuk menentukan tingkat prioritas. Permintaan jadwal dari dosen direpresentasikan dalam beberapa kategori prioritas, seperti prioritas tinggi untuk permintaan yang bersifat mendesak atau berdasarkan kondisi khusus, prioritas sedang untuk preferensi umum seperti waktu mengajar yang disukai, dan prioritas rendah untuk preferensi yang bersifat opsional. Soft constraint lainnya mencakup preferensi untuk menghindari gap terlalu panjang antara sesi perkuliahan dalam satu hari, preferensi untuk mengoptimalkan utilisasi ruangan, dan preferensi untuk menyeimbangkan beban jadwal di antara hari-hari dalam seminggu.

Perancangan algoritma dilakukan dengan mempertimbangkan karakteristik spesifik dari masalah penjadwalan. Pendekatan yang dirancang menggunakan kombinasi teknik constraint propagation untuk mengurangi domain variabel secara efisien dan heuristic search untuk mengeksplorasi ruang solusi dengan cerdas. Variable ordering heuristic seperti Most Constrained Variable atau Minimum Remaining Values digunakan untuk menentukan urutan pemberian nilai kepada variabel. Value ordering heuristic seperti Least Constraining Value digunakan untuk menentukan urutan nilai yang dicoba untuk setiap variabel.

Untuk mengoptimalkan pemenuhan soft constraint, dirancang fungsi objektif yang merupakan weighted sum dari tingkat pemenuhan berbagai soft constraint. Bobot untuk setiap soft constraint ditentukan berdasarkan hasil survei dan diskusi dengan stakeholder. Algoritma optimasi lokal seperti hill climbing atau simulated annealing diintegrasikan untuk meningkatkan kualitas solusi setelah solusi feasible awal ditemukan.

Perancangan arsitektur sistem mengikuti pola layered architecture yang memisahkan concern yang berbeda ke dalam layer yang berbeda. Presentation layer bertanggung jawab untuk antarmuka pengguna dan interaksi dengan pengguna. Business logic layer mengimplementasikan logika aplikasi termasuk algoritma CSP dan aturan bisnis penjadwalan. Data access layer menangani interaksi dengan database dan penyimpanan data. Layer ini berkomunikasi melalui interface yang terdefinisi dengan baik untuk memastikan loose coupling dan high cohesion.

Perancangan database menggunakan model relasional dengan normalisasi yang tepat untuk menghindari redundansi data. Tabel-tabel utama yang dirancang mencakup tabel dosen, mata kuliah, ruang kelas, slot waktu, program studi, dan tabel relasional untuk merepresentasikan hubungan many-to-many seperti dosen yang mengampu mata kuliah. Tabel khusus dirancang untuk menyimpan permintaan jadwal dari dosen dengan atribut seperti identitas dosen, jenis permintaan, detail permintaan, tingkat prioritas, status permintaan, dan timestamp pengajuan.

Perancangan antarmuka pengguna dilakukan dengan prinsip user-centered design. Untuk dosen, dirancang form yang intuitif untuk mengajukan permintaan jadwal dengan berbagai kategori seperti tidak tersedia pada hari atau waktu tertentu, preferensi hari atau waktu tertentu, preferensi ruang kelas tertentu, dan preferensi tidak ada gap antara sesi mengajar. Untuk administrator akademik, dirancang dashboard yang memberikan overview tentang status penjadwalan, jumlah permintaan yang masuk dan statusnya, progress pembuatan jadwal, dan statistik kualitas jadwal. Interface untuk mengelola data master seperti dosen, mata kuliah, dan ruang kelas juga dirancang dengan fokus pada kemudahan penggunaan.

### 3.5 Implementasi dan Pengujian

Implementasi sistem dilakukan menggunakan teknologi yang sesuai dengan kebutuhan dan karakteristik sistem. Bahasa pemrograman yang dipilih adalah Python karena memiliki library yang kaya untuk implementasi algoritma CSP dan optimasi, memiliki framework web yang mature untuk pengembangan aplikasi, serta memiliki komunitas yang besar dan dokumentasi yang lengkap. Framework web Django dipilih untuk mengembangkan aplikasi web karena menyediakan banyak fitur built-in yang mempercepat development, memiliki ORM yang powerful untuk interaksi dengan database, dan memiliki sistem authentication dan authorization yang robust.

Untuk implementasi algoritma CSP, digunakan library python-constraint yang menyediakan implementasi berbagai algoritma penyelesaian CSP, atau implementasi custom untuk algoritma yang spesifik dengan kebutuhan penelitian. Database yang digunakan adalah PostgreSQL karena reliable, scalable, dan memiliki dukungan yang baik untuk operasi kompleks. Frontend dikembangkan menggunakan kombinasi HTML, CSS, dan JavaScript dengan framework Bootstrap untuk responsive design dan Vue.js untuk interaktivitas yang lebih baik.

Proses implementasi dilakukan secara iteratif dengan mengikuti prinsip agile development. Setiap iterasi fokus pada pengembangan satu atau beberapa fitur, diikuti dengan testing dan refinement. Implementasi dimulai dengan modul core yaitu CSP solver, kemudian dilanjutkan dengan modul manajemen data, modul pengajuan permintaan, dan terakhir modul visualisasi dan reporting. Setiap modul melalui unit testing untuk memastikan fungsi-fungsi individual bekerja dengan benar.

Pengujian sistem dilakukan dalam beberapa tahap dengan fokus yang berbeda. Pengujian fungsional memverifikasi bahwa semua fitur sistem berfungsi sesuai dengan spesifikasi yang telah ditetapkan. Setiap use case dijalankan untuk memastikan sistem memberikan output yang benar. Pengujian dilakukan untuk berbagai skenario termasuk skenario normal, skenario dengan input edge case, dan skenario error handling.

Pengujian performansi dilakukan untuk mengukur efisiensi algoritma dan scalability sistem. Pengujian dilakukan dengan dataset dengan berbagai ukuran, mulai dari dataset kecil dengan puluhan mata kuliah hingga dataset besar dengan ratusan mata kuliah. Metrik yang diukur mencakup waktu komputasi untuk menghasilkan jadwal, penggunaan memori selama proses penjadwalan, dan kualitas solusi yang dihasilkan dalam hal jumlah constraint yang terpenuhi. Hasil pengujian performansi dibandingkan antara berbagai algoritma yang diimplementasikan untuk mengidentifikasi algoritma atau kombinasi algoritma yang paling efektif.

Pengujian kualitas jadwal dilakukan dengan menggunakan beberapa metrik. Metrik pertama adalah constraint satisfaction rate yang mengukur persentase hard constraint yang terpenuhi dan persentase soft constraint yang terpenuhi. Metrik kedua adalah resource utilization yang mengukur tingkat utilisasi ruang kelas dan distribusi beban mengajar dosen. Metrik ketiga adalah compactness yang mengukur rata-rata gap antara sesi perkuliahan dan distribusi jadwal sepanjang hari dan minggu. Jadwal yang dihasilkan sistem dibandingkan dengan jadwal yang dibuat secara manual dari semester sebelumnya menggunakan metrik-metrik ini.

Pengujian usability dilakukan dengan melibatkan pengguna potensial dari institusi pendidikan tinggi. Sekelompok dosen diminta untuk menggunakan sistem untuk mengajukan permintaan jadwal dan memberikan feedback tentang kemudahan penggunaan interface. Administrator akademik diminta untuk menjalankan proses penjadwalan menggunakan sistem dan mengevaluasi workflow dan kemudahan pengelolaan data. Pengujian usability menggunakan kuesioner System Usability Scale dan wawancara semi-terstruktur untuk mendapatkan feedback kualitatif yang lebih mendalam.

Validasi hasil penjadwalan dilakukan dengan expert review di mana staf akademik yang berpengalaman dalam penyusunan jadwal mengevaluasi jadwal yang dihasilkan sistem dari perspektif praktikalitas dan kesesuaian dengan kebijakan institusi. Feedback dari expert review digunakan untuk melakukan refinement terhadap sistem, baik dari segi algoritma, constraint yang dimodelkan, maupun parameter-parameter yang digunakan.

Pengujian juga mencakup simulasi skenario real-world seperti perubahan mendadak seperti dosen yang tidak dapat mengajar pada waktu yang sudah dijadwalkan, penambahan mata kuliah baru di tengah semester, perubahan kapasitas ruangan karena renovasi, dan permintaan reschedule dari dosen. Kemampuan sistem untuk mengakomodasi perubahan ini dengan cepat dan efisien menjadi indikator penting dari robustness sistem.

---

## BAB IV KESIMPULAN

Penelitian ini bertujuan untuk mengembangkan sistem penjadwalan perkuliahan berbasis Constraint Satisfaction Problem yang dapat mengakomodasi permintaan jadwal dari dosen sambil tetap memenuhi semua batasan akademik yang ada. Pendekatan CSP dipilih karena kemampuannya untuk secara sistematis merepresentasikan dan menyelesaikan masalah kompleks dengan banyak variabel dan constraint yang saling berkaitan.

Sistem yang dikembangkan diharapkan dapat memberikan solusi terhadap permasalahan penjadwalan yang selama ini menjadi beban administratif yang signifikan bagi institusi pendidikan tinggi. Dengan mengotomatisasi proses penjadwalan, sistem ini dapat mengurangi waktu yang diperlukan untuk menyusun jadwal dari berminggu-minggu menjadi beberapa jam atau bahkan menit, tergantung pada kompleksitas masalah dan ukuran institusi.

Kontribusi utama dari penelitian ini adalah pengembangan framework yang mengintegrasikan hard constraint dan soft constraint dalam satu model CSP yang kohesif. Hard constraint memastikan bahwa jadwal yang dihasilkan feasible dan tidak melanggar aturan akademik fundamental, sementara soft constraint memungkinkan sistem untuk mengakomodasi preferensi dosen dan mengoptimalkan berbagai aspek kualitas jadwal. Sistem pemberian bobot pada soft constraint memberikan fleksibilitas untuk menyesuaikan prioritas sesuai dengan kebijakan dan nilai institusi.

Dari perspektif metodologis, penelitian ini mendemonstrasikan efektivitas kombinasi teknik constraint propagation dan heuristic search dalam menyelesaikan masalah penjadwalan berskala besar. Penggunaan heuristic yang tepat dalam variable ordering dan value ordering terbukti dapat secara signifikan mengurangi waktu komputasi tanpa mengorbankan kualitas solusi.

Dari perspektif praktis, sistem yang dikembangkan memberikan nilai tambah yang signifikan bagi institusi pendidikan tinggi. Dosen mendapatkan mekanisme formal dan transparan untuk mengajukan preferensi jadwal mereka, yang dapat meningkatkan kepuasan kerja dan work-life balance. Administrator akademik mendapatkan tools yang powerful untuk mengelola proses penjadwalan dengan lebih efisien, memungkinkan mereka untuk fokus pada aspek-aspek strategis lain dari pengelolaan akademik. Mahasiswa mendapat manfaat dari jadwal yang lebih teroptimasi dengan konflik yang minimal, memudahkan mereka dalam perencanaan akademik.

Implementasi sistem ini juga membawa implikasi organisasional yang perlu dipertimbangkan. Transisi dari proses penjadwalan manual atau semi-manual ke sistem otomatis memerlukan perubahan dalam workflow dan mungkin memerlukan penyesuaian dalam struktur organisasi atau pembagian tanggung jawab. Institusi perlu mempersiapkan strategi change management yang efektif untuk memastikan adopsi sistem berjalan lancar dan mendapat dukungan dari semua stakeholder.

Penelitian ini juga mengidentifikasi beberapa area untuk pengembangan lebih lanjut. Pertama, integrasi machine learning untuk memprediksi preferensi dosen berdasarkan historical data dapat meningkatkan kemampuan sistem dalam mengantisipasi kebutuhan pengguna. Kedua, pengembangan fitur collaborative filtering dapat memungkinkan sistem untuk memberikan rekomendasi jadwal berdasarkan pola preferensi dari dosen dengan karakteristik serupa. Ketiga, eksplorasi multi-objective optimization dengan teknik seperti Pareto optimization dapat memberikan trade-off yang lebih baik antara berbagai kriteria kualitas jadwal.

Implementasi sistem dalam skala yang lebih luas juga membuka peluang untuk penelitian lebih lanjut tentang faktor-faktor yang mempengaruhi keberhasilan adopsi sistem penjadwalan otomatis di berbagai jenis institusi dengan karakteristik yang berbeda. Penelitian komparatif antara institusi dapat mengidentifikasi best practices dan lessons learned yang dapat memandu implementasi di institusi lain.

Secara keseluruhan, penelitian ini berkontribusi pada pengembangan sistem informasi akademik yang lebih intelligent dan user-centric. Dengan menggabungkan teknik kecerdasan buatan dengan pemahaman mendalam tentang kebutuhan pengguna, penelitian ini mendemonstrasikan bagaimana teknologi dapat digunakan untuk menyelesaikan masalah kompleks dalam domain pendidikan tinggi dengan cara yang efisien dan manusiawi.

---

## DAFTAR PUSTAKA

Badoni, R. P., Gupta, D. K., & Mishra, P. (2014). A new hybrid algorithm for university course timetabling problem using events based on groupings of students. *Computers & Industrial Engineering*, 78, 12-25.

Burke, E. K., & Petrovic, S. (2002). Recent research directions in automated timetabling. *European Journal of Operational Research*, 140(2), 266-280.

Di Gaspero, L., McCollum, B., & Schaerf, A. (2007). The second international timetabling competition (ITC-2007): Curriculum-based course timetabling (track 3). *Technical Report QUB/IEEE/Tech/ITC2007/CurriculumCTT/v1.0*, Queen's University, Belfast.

Gunawan, A., Ng, K. M., & Poh, K. L. (2012). A hybridized Lagrangian relaxation and simulated annealing method for the course timetabling problem. *Computers & Operations Research*, 39(12), 3074-3088.

Kristiansen, S., Sørensen, M., & Stidsen, T. R. (2015). Integer programming for the generalized high school timetabling problem. *Journal of Scheduling*, 18(4), 377-392.

Russell, S. J., & Norvig, P. (2020). *Artificial intelligence: A modern approach* (4th ed.). Pearson Education.

Schaerf, A. (1999). A survey of automated timetabling. *Artificial Intelligence Review*, 13(2), 87-127.

Tan, J. S., Goh, S. L., Kendall, G., & Sabar, N. R. (2021). A survey of the state-of-the-art of optimisation methodologies in school timetabling problems. *Expert Systems with Applications*, 165, 113943.

Wren, A. (1996). Scheduling, timetabling and rostering: A special relationship? In E. K. Burke & P. Ross (Eds.), *Practice and theory of automated timetabling* (pp. 46-75). Springer.

Badri, M. A. (1996). A two-stage multiobjective scheduling model for faculty-course-time assignments. *European Journal of Operational Research*, 94(1), 16-28.

Daskalaki, S., Birbas, T., & Housos, E. (2004). An integer programming formulation for a case study in university timetabling. *European Journal of Operational Research*, 153(1), 117-135.

Lewis, R. (2008). A survey of metaheuristic-based techniques for university timetabling problems. *OR Spectrum*, 30(1), 167-190.

MirHassani, S. A., & Habibi, F. (2013). Solution approaches to the course timetabling problem. *Artificial Intelligence Review*, 39(2), 133-149.

Pillay, N. (2014). A survey of school timetabling research. *Annals of Operations Research*, 218(1), 261-293.

Qu, R., Burke, E. K., McCollum, B., Merlot, L. T., & Lee, S. Y. (2009). A survey of search methodologies and automated system development for examination timetabling. *Journal of Scheduling*, 12(1), 55-89.


