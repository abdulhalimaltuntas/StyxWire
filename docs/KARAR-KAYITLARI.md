# Karar kayıtları

Kısa ADR biçimi: bağlam → karar → gerekçe → sonuç/etkiler → geri alma koşulu.
Numaralar kalıcıdır; yeni kararlar sona eklenir, eskiler değiştirilmez
("yerini aldı" notu düşülür).

## KK-1 — Derleme sistemi: mevcut `configure` + GNU make korunur (Aşama 1/2)

**Bağlam.** İki dış bağımlılık (libpcap, isteğe bağlı Tcl), tek hedef
(`hping3`) ve bir statik arşiv (`libars.a`). Aşama 1'de `configure` POSIX sh
ile yeniden yazıldı; pkg-config/tclConfig.sh keşfi, derleme testleri,
`DESTDIR`, `SANITIZE`/`WERROR` anahtarları ve `make check` eklendi.

**Karar.** Meson/CMake'e geçilmez; mevcut betik + `Makefile.in` ana akış
olarak sürdürülür. İki bağımsız build tanımı bakıma alınmaz.

**Gerekçe.** Geçiş maliyeti (yeni araç bağımlılığı, dağıtım paketlerinin
alışkanlıkları, CI matrisi) elde edilecek yararı (bağımlılık keşfi zaten
çözüldü; matris küçük) aşıyor. Çapraz derleme ihtiyacı `__BYTE_ORDER__`
ile karşılandı.

**Geri alma koşulu.** Üçüncü bir platform ailesinin (Windows/npcap, macOS
framework) veya paylaşımlı kütüphane hedefinin (`libars.so`, pkg-config
dosyası) eklenmesi; o zaman Meson tercih edilir (tek dosya, çapraz derleme
profilleri).

## KK-2 — Zaman: tek monotonik saat, duvar saati yalnızca protokol/raporlama (Aşama 2)

**Bağlam.** RTT `time(NULL)` + `gettimeofday().tv_usec` ile iki ayrı
okumadan hesaplanıyor, `milliseconds()` gün sonunda sıfırlanıyordu
(`hping recv` zaman aşımı, tarama süreleri).

**Karar.** `clock.c`: `hping_monotonic_us()` (`CLOCK_MONOTONIC`, yoksa
`gettimeofday`), `hping_wall_us()`; delaytable girişleri tek okumayla
`sent_us` tutar; `mstime()` monotonik ms'ye çevrildi (yalnızca farkları
kullanılıyor: HZ kestirimi, saat sapması örnekleri); `milliseconds()`
(ICMP timestamp, RFC 792 "gece yarısından beri ms") duvar saatinde kaldı.
Saat ve rastgelelik kaynağı `ctx.clock`/`ctx.random` üzerinden
değiştirilebilir (`hping_clock_set`, `hping_random_set`).

**Sonuç.** `clock_skew()` çıktısındaki "local/remote clock delta" mutlak
değeri artık monotonik tabana göredir (yalnızca farklar anlamlıydı);
sapma (skew) hesabı değişmez.

## KK-3 — Olay döngüsü: sinyal işleyicileri yalnızca bayrak yazar (Aşama 2)

**Bağlam.** `SIGALRM` işleyicisi `send_packet()` içinde `malloc/printf/
sendto/exit` çağırıyordu; `SIGINT/SIGTERM` işleyicisi istatistik basıp
`exit()` yapıyordu. Async-signal-safe olmayan bu tasarım nadir kilitlenme
ve çöküşlerin kaynağıydı ve test edilemiyordu.

**Karar.** `lifecycle.c`: `init/run/stop/destroy`; `poll(2)` ile pcap
seçilebilir fd + kendi-kendine boru (self-pipe) üzerinde bekleme; gönderim
monotonik deadline ile; `SIGINT/SIGTERM/SIGTSTP` işleyicileri sadece
`sig_atomic_t` bayrak + boruya 1 bayt. I/O primitifleri `ctx.io` üzerinden
değiştirilebilir → sahte saat/betiklenmiş karelerle deterministik testler.

**Taşınabilirlik.** Yalnızca POSIX.1-2001 (`poll`, `pipe`, `sigaction`,
`clock_gettime`). `pcap_get_selectable_fd()` −1 dönerse
`pcap_get_required_select_timeout()` (libpcap ≥ 1.9) ya da 10 ms ile
periyodik yoklama. Linux'a özgü mekanizma (epoll, timerfd, signalfd)
kullanılmadı; ihtiyaç doğarsa `ctx.io` arkasında isteğe bağlı backend.

**Sonuç/etkiler.** `-i 0` (saniye) eskiden `alarm(0)` ile ilk paketten sonra
göndermeyi durduruyordu; artık `-i u0` gibi davranır. `--flood -c N` tam N
paket gönderip durur (eskiden alarm gecikmesi kadar fazladan gönderirdi).
`--count` "cevaplandı" kararı benzersiz cevapla verilir (DUP saymaz).

## KK-4 — `--scan`: fork + SysV shm yerine tek süreçli durum makinesi (Aşama 2)

**Bağlam.** Tarayıcı iki süreçti: çocuk gönderir, ebeveyn okur; port
tablosu `shmget(IPC_PRIVATE)` ile paylaşılıyor, kilit yok, `volatile` yok,
segment hiç `IPC_RMID` edilmiyordu (her taramada sızıntı). Yazarın kendi
notu: "x86'da güvenli olmalı".

**Seçenekler.** (a) iki süreç + C11 atomik/`mmap(MAP_SHARED)`; (b) tek süreç,
olay döngüsü üzerinde durum makinesi.

**Karar.** (b). Aynı algoritma (`opt_scan_probes` deneme, turlar, 3. turdan
sonra ortalama RTT kadar bekleme, yavaşlama kuralı, "Not responding ports"
raporu) `scan_step()`/`scan_round_done()` ile korunur; port tablosunun tek
sahibi vardır; durdurma/temizlik ortak sözleşmeye uyar; çevrimdışı test
edilebilir (`tests/test_scan.c`, sahte saat).

**Etkiler.** Port 65535 artık taranır (eski döngü `< MAXPORT` ile atlıyordu).
Tam hızda ilk turların cevaplar okunmadan önce çıkması davranışı aynı
(iki süreçli tasarımda da öyleydi). Çıkış kodu 0 korunur; gönderim hatası
1.

## KK-5 — Ortak çekirdek (CLI gönderim yolu ↔ ARS) ertelendi (Aşama 2 → 3)

**Bağlam.** `sendtcp.c/sendudp.c/sendicmp.c/sendip.c` ile ARS
(`ars_compiler_*`) aynı protokol işini iki kez yapıyor.

**Karar.** Bu aşamada CLI gönderim yolu ARS'ye taşınmadı; yalnızca hata
sözleşmesi (`int` dönüş, `exit()` yok) ve test çifti (`send_ip_handler`)
düzenlendi. Geçiş, `tests/test_core` vektörleri (bayt-eşit çıktı) hazır
olduğu için Aşama 3'te `sendtcp.c` ile başlayarak küçük adımlarla yapılır;
`--badcksum`, `-O/--tcpoff`, `--rand-source/dest` gibi kasıtlı hatalı
paket yetenekleri ARS `ARS_TAKE_*` bayraklarıyla korunmalıdır.

**Gerekçe.** Aşama 2'nin riski (olay döngüsü) ile protokol üretim
yolunun değişimi aynı pakette olmamalı (prompt ilke 3).

## KK-6 — Durum nesneleri: `cfg`/`ctx`/`stats` yapıları, hâlâ global örnekler (Aşama 2)

**Bağlam.** ~100 global değişken tüm dosyalarda doğrudan kullanılıyordu;
testler sıfırlayamıyordu.

**Karar.** `struct hping_config cfg` (parse_options'ın yazdığı her şey;
çalışma zamanında değişenler "runtime-adjusted" olarak işaretli),
`struct hping_context ctx` (soketler, pcap, adresler, sıra numaraları,
delaytable, saat, I/O, durdurma nedeni), `struct hping_stats stats`;
`*_init()` fonksiyonları. Fonksiyon imzalarına bağlam parametresi
eklenmedi (Tcl bağlayıcısı ve 25 dosya etkilenirdi); bu, sorumlulukları
ayıran ve testleri bağımsızlaştıran ara adımdır.

**Geri alma/ilerleme koşulu.** Birden çok eşzamanlı oturum (örn. Tcl'den
iki hedef) gerektiğinde `ctx` parametre olarak geçirilir; `cfg`'deki
"runtime-adjusted" alanlar `ctx`'e taşınır.
