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

## KK-7 — Ürün adı StyxWire; hping3 uyumluluğu symlink ile korunur (Aşama 3)

**Bağlam.** Proje StyxWire olarak yeniden adlandırıldı. Binary adı, tanı
mesajları, man sayfası ve Tcl komut adı bundan etkilenir; ancak mevcut
betikler ve otomasyon `hping3`/`hping`/`hping2` adlarını ve çıktı biçimini
bekliyor.

**Karar.** Binary `styxwire`; kurulumda `hping3`, `hping2`, `hping` göreli
symlink olarak kurulur; man sayfası `styxwire.8`, `hping3.8` ona symlink.
Tcl'de hem `styxwire` hem `hping` komutu kayıtlı; `styxwire_version`
değişkeni eklendi, `hping_version` (hping3 taban sürümü) korundu. Başlangıç
dosyası `~/.styxwirerc`, yoksa `~/.hpingrc`. Çıktı satır biçimleri
(istatistik başlığı hariç ürün adı büyük harf `STYXWIRE`) korundu.
Kaynaktaki `hping2.h`/`hping_*` API adları ve `hping3.8` içindeki tarihî
gönderim değişmedi (iç adlar; kullanıcıya görünmez).

**Gerekçe.** Ad değişikliği kullanıcıya görünen bir karardır; geriye
uyumluluğu kırmadan yapılması için symlink + çift komut adı en düşük
maliyetli yoldur. Sürüm ayrımı (`STYXWIRE_VERSION` vs `RELEASE_VERSION`)
"sürüm numarasını sırf görünüm için değiştirme" ilkesine uyar: taban hping3
sürümü `--version`'da açıkça belirtilir.

**Geri alma.** Yok; symlink'ler ileride kaldırılırsa geçiş notu gerekir.

## KK-8 — Tcl sürüm desteği: 8.6 ve 9, tek kaynak (Aşama 3)

**Bağlam.** Tcl 9, `Tcl_Obj *CONST` makrosunu kaldırdı ve uzunluk/indeks
türlerini `Tcl_Size`'a çevirdi (resmî geçiş rehberi).

**Karar.** Kaynak `Tcl_Obj *const objv[]` kullanır (her iki sürümde
geçerli); `Tcl_Size` Aşama 1'de 8.x için typedef edilmişti. Tek kaynak iki
sürümde de `-Werror` ile derlenir ve tüm test paketi geçer. Sürüm keşfi
`configure`'da (`TCL_CONFIG`/pkg-config `tcl9.0`/`tcl8.6`).

**Gerekçe.** Sürüm keşfini düzeltmek ile C API portu birbirine
karıştırılmadı (prompt §6); tek fark `const` idi. Destek iddiası gerçek
derleme + çalışma testine dayanır (Tcl 9.0.1 kaynağından derlenip
doğrulandı).

## KK-9 — Yapılandırılmış çıktı: NDJSON, insan çıktısına dokunmadan (Aşama 4)

**Bağlam.** Otomasyon için makine-okur çıktı gerekiyordu; ama mevcut insan
çıktısı (yanıt satırları, tarama tablosu, istatistik) betiklerce ayrıştırılıyor
ve karakterizasyon testleriyle (`cli.sh`) sabitlenmiş.

**Karar.** `--json` ile stdout'a satır başına bir JSON nesnesi (NDJSON);
tanılar ve banner stderr'e. İnsan çıktı yolu **değiştirilmedi**: her yanıt
noktasında `if (output_json_enabled()) { JSON olay } else { mevcut printf }`.
Böylece iki çıktı bağımsız olarak doğru ve insan biçimi bayt-bayt korunur.
Bilinmeyen değer `null` (yanıltıcı 0 değil): eşleşmeyen yanıtın `rtt_ms`'i,
örneklem yokken istatistik RTT'leri. Şema tamsayısı (`schema:1`) yalnızca
uyumsuz değişiklikte artar; tüketici bilinmeyen anahtarı yok saymalı.
Belge: `docs/JSON.txt`.

**Gerekçe.** Ayrı JSON yolu, insan biçimini koruma (uyumluluk) ile
yapılandırılmış çıktıyı aynı anda sağlamanın en güvenli yolu; alan listeleri
mütevazı. Hex dump (-j/-J) JSON'a taşınmadı (kapsam); veri için `--dry-run`
"packet" olayı veya `--read`.

## KK-10 — `--read`: çevrimdışı pcap çözümleyici, gönderim yok (Aşama 4)

**Bağlam.** `ctx.io` savefile yolu (Aşama 2) hazırdı; kullanıcıya çevrimdışı
paket incelemesi sunmak isteniyordu.

**Karar.** `--read file.pcap` alım-yalnızca moddur: raw socket açılmaz,
hiç paket gönderilmez, dosya EOF'a kadar okunup her kare `wait_packet` ile
çözümlenir; hedef/port filtresi normal alım yolundakiyle aynıdır. Probe
gönderilmediği için `rtt_ms` `null` (delaytable boş) — bu dürüsttür,
"ölçüm değil, çözümleme". Link-layer türü dosyanın DLT'sinden gelir.
Kısa harf `-r` `--rel` tarafından alındığından `--read` yalnız uzun
seçenektir.

**Gerekçe.** Root'suz, ağsız bir çözümleme yeteneği; `--json` ile birleşince
tam bir çevrimdışı boru hattı (`--read ... --json`). Gönderim tarafını
kapatmak, "çevrimdışı okuma kendiliğinden yeniden gönderime dönüşmesin"
(prompt §6) ilkesine uyar.

## KK-11 — IPv6: önce çevrimdışı dilim, gönderim bilinçli olarak reddedilir (Aşama 5)

**Bağlam.** Prompt §8 IPv6 istiyor. Gerçek gönderim `AF_INET6` raw socket,
farklı kaynak adres seçimi, farklı yakalama filtresi ve farklı yanıt
eşleştirme demek; hiçbiri yok. Buna karşılık ARS motoru bayt düzeyinde
çalıştığı için başlık modeli, checksum ve çözümleme tamamen çevrimdışı
doğrulanabilir.

**Karar.** IPv6 iki parçaya ayrıldı. (1) **Yapılır:** `ip6` ve `icmp6` APD
katmanları, RFC 8200 §8.1 pseudo-header ile TCP/UDP checksum'u, RFC 4443
§2.3 gereği pseudo-header'ı **içeren** ICMPv6 checksum'u, sürüm nibble'ına
göre IPv4/IPv6 ayrımı yapan çözümleyici, `build`/`describe`/`validate`.
(2) **Yapılmaz:** `ars_send()` bir IPv6 paketini açık bir tanıyla reddeder;
komut satırı IPv6 hedef verildiğinde "bu araç IPv4 gönderir, IPv6'yı
çevrimdışı kurabilirsin" diyen, örnek içeren bir tanı basar ve 1 ile çıkar.
Uzantı başlıkları ayrıştırılmaz, DATA katmanı olarak korunur. Belge:
`docs/IPV6.txt`.

**Gerekçe.** Yarım bir gönderim yolu, kullanıcının göremeyeceği biçimde
yanlış datagram üretirdi; "sessizce yanlış" en kötü sonuç. Reddetme,
yeteneğin sınırını kullanıcıya taşır. Çevrimdışı dilim ise root'suz ve
ağsız tam doğrulanabilir: `test_core` içindeki vektörler checksum'ları
bağımsız hesapla karşılaştırır ve `build → describe → build` turunun
bayt-eşit olduğunu gösterir.

**Geri alma koşulu.** `AF_INET6` gönderim/alım yolu yazılıp canlı ağda
doğrulandığında reddetme kaldırılır; o ana kadar `docs/IPV6.txt`'teki
matris tek doğru kaynaktır.

## KK-12 — Link-layer: boyutu bilinmeyen tür tahmin edilmez, reddedilir (Aşama 5)

**Bağlam.** `dltype_to_lhs()` bazı türler için yanlış ya da ölü değerler
taşıyordu: `#ifdef DLT_IEE802_11` (bir E eksik) 802.11 dalını hiç
derletmiyordu; token ring 14 döndürüyordu (LLC/SNAP hesaba katılmadan);
`DLT_LINUX_SLL2` (modern Linux'ta `-i any` bunu verir) tabloda yoktu;
desteklenmeyen türde `ctx.linkhdr_size`'a `(unsigned) -1` yazılıyordu.

**Karar.** Tablo sabit uzunluklu türlerle sınırlandırıldı. Başlık uzunluğu
kareye göre değişen türler (802.11, radiotap, 802.5 token ring'in 0-18 bayt
routing information field'ı) `-1` döndürür ve `get_linkhdr_size()` türü
adıyla anan bir tanı basıp başarısız olur — `ctx.linkhdr_size`'a dokunmadan.
`DLT_LINUX_SLL2` (20) eklendi, `DLT_LANE8023` tarihsel 16 değerinde bırakıldı.
Desteklenen her tür pcap fixture'ı ile sınanır (`tests/linklayer.sh`,
`tests/test_waitpacket.c`); sınanmayanlar destek matrisinde ayrı
işaretlenir (`docs/PLATFORMS.txt`).

**Gerekçe.** Yanlış bir başlık boyutu her paketi sessizce yanlış ofsetten
okutur; bu, "desteklenmiyor" demekten çok daha kötüdür. `#ifdef` bulunması
destek değildir: matris "derleniyor / birim-test edildi / canlı test edildi"
sütunlarını ayırır.

**Etkisi.** Token ring yakalamaları artık çözümlenmek yerine reddedilir
(eskiden yanlış ofsetten çözümleniyordu). 802.11 dalı zaten ölü koddu.

## KK-13 — Performans: ölçüm altyapısı evet, hedef sayı hayır (Aşama 5)

**Bağlam.** Prompt §8 "yeniden üretilebilir performans temeli" istiyor ve
uydurma hedef koymayı yasaklıyor.

**Karar.** `make bench` (`tests/bench.c`): yalnız bellek içi iş yükleri
(APD→bayt, bayt→katman, describe, checksum; IPv4 ve IPv6), tekrar başına
min/medyan/maks ns/op, `--wrap` ile tahsis sayımı, `getrusage` ile tepe
bellek. Her koşu makineyi, CPU'yu, derleyiciyi, bayrakları ve CPU
affinite'sini başlığa basar. Hedef eşik **tanımlanmadı**; `docs/BENCHMARK.txt`
yalnızca "referans koşu" kaydeder. `make check`, `tests/bench --selftest` ile
iş yüklerinin doğru şeyi hesapladığını doğrular (süre ölçmez).

**Gerekçe.** Sayının anlamı ölçüm koşullarıyla birliktedir: aynı ikili
sabitlenmeden koşturulduğunda `build4` art arda 1229 ns/op ve 2988 ns/op
ölçüldü (P/E çekirdek farkı, 2.4 kat). Bu yüzden `make bench` mümkünse
`taskset -c 0` ile koşar ve affiniteyi rapor eder. Hedef sayı koymak,
ölçüm gürültüsünü gereksinime dönüştürmek olurdu.

**Geri alma koşulu.** Profil çıkarılıp bir darboğaz kanıtlanırsa optimizasyon
yapılır; öncesi/sonrası aynı makinede bu araçla gösterilir.

## KK-14 — Canlı gönderim/alım doğrulaması: kullanıcı ad alanı, gerçek root değil (Aşama 5 sonrası)

**Bağlam.** Beş aşama boyunca en büyük boşluk şuydu: hiçbir test gerçek bir
soketten paket gönderip yanıtı yakalamıyordu. `make check` sözleşmesi bunu
yasaklar (root yok, ağ trafiği yok), o yüzden bu doğrulama her platformda
açık kalmıştı (`docs/PLATFORMS.txt` "live-tested: no").

**Karar.** Ayrı, isteğe bağlı bir hedef eklendi: `make check-live`
(`tests/netns.sh`). Linux'ta ayrıcalıksız kullanıcı ad alanı (user
namespace) içeride uid 0 verir; onun içinde tümüyle sahip olunan boş bir ağ
ad alanı açılır, bir veth çifti kurulur, bir ucu ikinci bir ağ ad alanına
taşınır ve gerçek raw soket üzerinden gönderim/alım yapılır. Gerçek `sudo`,
setuid ya da fiziksel arayüz gerekmez; hiçbir paket ana makineden çıkmaz.
Test ICMP echo, açık/kapalı porta TCP SYN, `--scan` ve sahte kaynak (`-a`)
senaryolarını sürer; her biri yakalanan yanıtı, hesaplanan RTT'yi ve çıkış
kodu sözleşmesini (statistics.c:hping_exit_code — yanıt geldiyse 0, hiç
gelmediyse 1) doğrular.

**Neden `make check`'e konmadı.** `tests/netns.sh` sanal da olsa bir
arayüze gerçek paket koyar ve raw soket açar. Varsayılan suite'in "root yok,
trafik yok" sözleşmesini korumak için ayrı tutuldu. Ayrıcalıksız kullanıcı
ad alanı kapalıysa, Linux dışıysa veya `ip`/`nsenter`/`python3` yoksa test
başarısız olmak yerine 77 ile atlanır — koşmadığı hâlde koştuğunu iddia
etmez.

**Kapsam (dürüstlük notu).** veth bir Ethernet bağıdır (DLT_EN10MB) ve yol
IPv4'tür. Yani EN10MB gönderim/alım/scan yolu artık canlı doğrulanmıştır;
fiziksel NIC, diğer link-layer türleri ve IPv6 gönderim yolu (kararla
reddedilir, KK-11) hâlâ canlı test edilmemiştir. `docs/PLATFORMS.txt` Linux
satırı bu yüzden düz "yes" değil "yes (veth)" der.

**Geri alma koşulu.** Yok; bu yalnızca doğrulama altyapısı ekler, çalışma
zamanı davranışını değiştirmez.

## KK-15 — CLI TCP gönderim yolu ARS'ye taşındı (B4, TCP ilk adım)

**Bağlam.** KK-5, `sendtcp.c/sendudp.c/sendicmp.c/sendip.c` ile ARS
motorunun aynı protokol işini iki kez yaptığını saptamış ve birleştirmeyi
"küçük adımlarla, `sendtcp.c` ile başlayarak, bayt-eşit vektörlerle"
ertelemişti. Bu iş paketi (B4) o ilk adımı atar.

**Karar.** `send_tcp()` artık TCP segmentini elle bayt dizerek değil, ARS
ile kurar (`ars_add_iphdr`/`ars_add_tcphdr`/`ars_add_tcpopt`/`ars_add_data`
→ `ars_compile` → `ars_build_packet`); IP başlığı yine sonra `send_ip()`
tarafından eklenir, ARS'nin IP katmanı yalnızca pseudo-header checksum'u
için adresleri sağlar ve atılır. Böylece TCP başlığı ve checksum'ının tek
bir uygulaması kalır.

**Kasıtlı hatalı paket yetenekleri korundu (prompt ilke 3).** ARS
varsayılanları bunları tek başına üretmez, elle yeniden uygulanır:
- `--badcksum`: ARS doğru checksum'ı hesaplar; `cksum.c` onu
  `~(s ^ 0x5555) == (~s) ^ 0x5555` ile bozar, bu yüzden sonuç 0x5555 ile
  XOR'lanır. (`ars_cksum` `opt_badcksum`'ı bilmez — yalnızca `cksum.c` bilir.)
- `-O/--tcpoff`: data offset elle sahte değere yazılır ve `ARS_TAKE_TCP_HDRLEN`
  ile ARS'nin yeniden hesaplaması engellenir.
- Solaris checksum bug (`STUPID_SOLARIS_CHECKSUM_BUG`): checksum alanına
  segment uzunluğu yazılır.
- TCP timestamp seçeneği: tarihsel bayt sırası (NOP, NOP, kind 8/len 10,
  rastgele tsval, sıfır tsecr) `ars_add_tcpopt(NOP)` ×2 + `TIMESTAMP` ile
  aynen üretilir (ARS dolgu NOP'larını sona koyar; burada 12 bayt zaten
  4'e hizalı olduğundan ek dolgu olmaz).

**Kabul kanıtı.** Önce mevcut `send_tcp()` çıktısı bayt bayt sabitlendi
(`tests/test_core.c:test_send_tcp_vectors`, 7 senaryo/56 kontrol: açık ve
rastgele seq/ack, timestamp, --badcksum, -O, veri, keepstill/force-incdport
yan etkileri; checksum bağımsız pseudo-header ile doğrulanır). Bu ağ testi
eski kodda geçti; ARS'ye geçişten sonra **değişmeden** geçti (474/474).
Ayırt edicilik: badcksum XOR'u kaldırılınca iki kontrol düştü. Canlı yol
(`make check-live`, gerçek TCP veth üzerinden) 17/17; ASan/UBSan/LSan temiz
(paket başına malloc/free sızdırmıyor).

**Kalan iş.** UDP (`sendudp.c`) ve ICMP (`sendicmp.c`) hâlâ elle kuruyor;
aynı desenle (karakterizasyon vektörü → ARS → bayt-eşitlik) taşınacak.
IPv6 gönderimi kararla reddedilir (KK-11), bu birleştirmenin konusu değil.

**Geri alma koşulu.** Yok; davranış bayt düzeyinde korundu. Bir regresyon
çıkarsa karakterizasyon vektörü yakalar.

## KK-16 — B4 tamamlandı: UDP ve ICMP de ARS'ye taşındı; `send_icmp_other` bilinçli olarak dışarıda

**Bağlam.** KK-15 TCP'yi ARS'ye taşımıştı. Geriye `sendudp.c` ve
`sendicmp.c` kalmıştı.

**Karar.** `send_udp()` ve `send_icmp_echo()/send_icmp_timestamp()/
send_icmp_address()` ARS ile kurulur. UDP'de IP katmanı yalnız pseudo-header
adresleri içindir ve atılır; uzunluk (`uh_ulen`) ve checksum'ı ARS hesaplar.
ICMPv4'te pseudo-header yoktur, `ars_compiler_icmp` yalnız mesajı toplar —
tarihsel `cksum()` ile aynı sonuç.

**`send_icmp_other()` taşınmadı — teknik gerekçe.** ICMP hata mesajının
*alıntılanan* datagramı, bu paketin katman düzenine değil **orijinal**
paketin çerçevelemesine uyar: eski kodda alıntılanan UDP checksum'ı yalnız
8 baytlık UDP başlığını kapsar ve pseudo-header uzunluğu alıntılanan IP'nin
`tot_len`'idir (28); ARS ise UDP katmanından sonraki her şeyi (ICMP'nin
16 baytlık veri dolgusunu da) toplardı. Yani ARS'ye zorlamak checksum'ı
bastırıp (`ARS_TAKE_UDP_CKSUM`) elle hesaplamak demekti — tekrar zaten
kalkmazdı. Elle kurulmuş hâlde bırakıldı; davranışı
`tests/test_core.c:test_send_icmp_other()` sabitler.

**`sendip.c` / `sendhcmp.c` kapsam dışı.** `sendip.c` dış IP başlığını kuran,
raw sokete yazan ve `--dry-run` çıktısını üreten **tek ve ortak** yoldur
(`ip->check = 0`, çekirdek doldurur; BSD/Linux bayt sırası farkları,
`--safe` id artışı). ARS ile çoğaltma değil; taşımak fayda getirmeden risk
eklerdi. `sendhcmp.c` listen-mode HCMP'ye özgüdür.

**Kabul kanıtı.** Önce mevcut çıktılar bayt bayt sabitlendi
(`test_send_udp_vectors` 20, `test_send_icmp_vectors` 26 kontrol; ICMP'de
paketin tamamı checksum'landığında sıfıra inmelidir, diğer tüm baytlar
sabitlenir). Vektörler eski kodda geçti, ARS'ye geçişten sonra
**değişmeden** geçti (520/520). Ayırt edicilik: UDP badcksum XOR'u
kaldırılınca 2, ICMP zorlanmış checksum'ı kaldırılınca 1 kontrol düştü.
Canlı yol `make check-live` ile 20/20 (UDP kontrolü eklendi: kapalı porta
UDP → ICMP port unreachable).

**Bu sırada bulunan iki gerçek kusur (düzeltildi).**
1. `make install`, `lib/*.tcl` hiçbir dosyayla eşleşmediğinde globu düz
   metin olarak `install`'a verip **başarısız oluyordu** (lib'de yalnız
   `.htcl` var). `[ -f "$f" ] || continue` eklendi.
2. Bunu `tests/install.sh` yakalayamıyordu: `check "[ \$? -eq 0 ]"`
   dizgesi `check()` içinde değerlendiriliyor, orada `$?` artık make'in
   değil `n=$((n+1))`'in durumu (hep 0). Üç kontrol de **hiçbir zaman
   doğrulamıyordu**. Durum artık çağrı yerinde `rc=$?` ile yakalanıyor;
   kusur geri konulduğunda test düşüyor (doğrulandı).

**Geri alma koşulu.** Yok; davranış bayt düzeyinde korundu.

## KK-17 — Kabuk tamamlama ve statik ikili

**Karar.** `completion/styxwire.bash` ve `completion/styxwire.zsh` eklendi,
`make install` bunları `datadir/bash-completion/completions/` ve
`datadir/zsh/site-functions/` altına kurar (hping3 için de bağ).

**Sürüklenmeye karşı.** Tamamlama dosyalarındaki uzun seçenek listesi
`tests/completion.sh` ile ikilinin kendi tablosuna
(`parseoptions.c:hping_optlist`) karşı **iki yönlü** karşılaştırılır: yeni
bir `--seçenek` tamamlamaya eklenmeden, kaldırılan bir seçenek tamamlamadan
silinmeden `make check` geçmez. Test `LC_ALL=C` kullanır — `[a-z0-9-]`
aralıkları ve `sort` sıralaması yerele bağlıdır (tr_TR'de `grep -o`
belirteçleri bozuyordu; bu bizzat yaşandı).

**Statik ikili.** `make styxwire-static` hedefi **zaten vardı**
(`$(PROG)-static`), yalnız belgesizdi; açıklama eklendi. Bu makinede
bağlanamıyor: `libpcap.a` kurulu değil (`ld: -lpcap bulunamadı … have you
installed the static version of the pcap library ?`). Hedef doğru, ortam
eksik — doğrulanmamış olarak işaretlenir.

## KK-18 — Kaynak ağacı `src/` altına toplandı, profesyonel README.md

**Bağlam.** Depo kökü düzdü: 60 `.c` + 16 `.h` kaynak, meta dosyalar ve
üretilen artefaktlar aynı yerdeydi. Daha derli, GitHub'da profesyonel görünen
bir düzen istendi.

**Karar.**
- Tüm izlenen `.c`/`.h` kaynak `src/` altına taşındı (`git mv`, geçmiş
  korunur). Üretilen `byteorder.h`/`systype.h` ve nesneler kökte kalır.
- Makefile: `VPATH = src` (yerleşik `.c.o` kuralı kaynağı src'de bulur,
  nesneler yine kökte üretilir); `ALL_CPPFLAGS`'a `-I. -Isrc` (testler/fuzz
  src başlıklarına, kaynak da köke üretilen başlıklara erişir); `.depend`
  artık `src/*.c` üzerinden. `configure` de aynı: `src/byteorder.c` ve
  `src/*.c` ile `.depend`.
- Eski hping meta stub'ları (`BUGS`, `KNOWN-BUGS`, `NEWS`, `TODO`) `docs/`
  altına alındı; standart meta (`COPYING`, `AUTHORS`, `CHANGES`, `INSTALL`)
  kökte kaldı.
- Düz metin `README` kaldırıldı; yerine kapsamlı `README.md` (amaç, özellikler,
  gereksinimler, kurulum/test, depo düzeni, kullanım örnekleri, scripting/APD,
  test felsefesi, belge dizini, lisans). Abartılı iddia, sahte rozet/CVE yok;
  yalnız Linux'ta doğrulanmış durum yansıtılır.
- `tests/completion.sh` yolu `src/parseoptions.c`'ye güncellendi.
- `src/gentables.sh` kendi dizinine `cd` eder ve doğru `sbignum-tables.{c,h}`
  adlarına yazar (eski hâli kökten `tables.c` üretiyordu — hem yer hem ad
  yanlıştı).

**Doğrulama.** Temiz ağaçtan `make check` 14/14 (GCC ve clang, WERROR),
`make check-live` 20/20, `make bench`/`make fuzz` derlenir. Kökte izlenen
hiçbir `.c`/`.h` kalmadı.

**Not.** Tarihsel raporlar (ASAMA1-5) ve eski KK kayıtları kaynak dosyalara
çıplak adla atıfta bulunur (`getlhs.c` gibi); bunlar zamana-bağlı kayıt
olduğu için olduğu gibi bırakıldı — README ve güncel yönergeler `src/`
düzenini yansıtır.

**Geri alma koşulu.** Yok; yalnız dosya düzeni ve belge, çalışma zamanı
davranışı değişmedi.

## KK-19 — Derinlemesine statik/dinamik analiz denetimi ve düzeltmeler

**Bağlam.** Depo baştan aşağı denetlenip bulunan gerçek kusurların
düzeltilmesi istendi.

**Yöntem.** clang static analyzer (`scan-build`, core/unix/security/deadcode/
nullability), GCC 16 yüksek-uyarı derlemesi (`-Wextra -Wshadow
-Wimplicit-fallthrough=3 -Wnull-dereference -Wduplicated-cond -Wlogical-op`),
clang-tidy (`bugprone-*`, `clang-analyzer-*`), ve düzenlenen dosyalarda kısa
fuzz koşusu. 344 scan-build bulgusunun ~320'si düşük-sinyalli `insecureAPI`
tavsiyesiydi (her memcpy/fprintf'i işaretler); geri kalan ~11 ve derleyici
uyarıları tek tek triyaj edildi.

**Düzeltilen gerçek kusurlar.**
1. `getifname.c` — `get_if_name()`'te debug çıktısı ilklendirilmemiş `sa`
   değişkenini basıyordu; doğrusu, `get_output_if()`'in az önce doldurduğu
   `output_if_addr`. (Yığında ilklendirilmemiş bellek okuması, yalnız
   `--debug`.)
2. `getifname.c` — `get_output_if()` içinde `socket()` dönüşü kontrol
   edilmiyordu; başarısızlıkta `setsockopt`/`connect` fd -1 ile çağrılırdı.
   Kontrol eklendi.
3. `ars.c` — `ars_send()`'te `ars_bsd_fix()` başarısız olursa `packet`
   sızıyordu (hata yolunda `free` yok). Eklendi.

**Düzeltilen küçük kusurlar / uyarılar.**
4. `ars.h` — `ars_valid_layer()` prototipi iki kez bildirilmişti; biri
   kaldırıldı.
5. `parseoptions.c` — `parse_route()`'ta `case ':'`'ten `default:`'a kasıtlı
   ama işaretsiz fall-through; niyet yorumu + `__attribute__((fallthrough))`
   ile açıklandı (davranış değişmedi).
6. `hex.c` — `char hcharset[16] = "...16 hane..."` NUL'u düşürüyordu (GCC 16
   `-Wunterminated-string-initialization`); yalnız indekslenen bu tablo
   `static const char hcharset[]` yapıldı.

**Değerlendirilip bilerek dokunulmayanlar (yanlış pozitif / zararsız).**
scan-build'in `waitpacket.c:708` (negatif indeks) ve `apd.c:877` (p_layer[-1])
bulguları ulaşılamaz: `cs_window_shift` varsayılanı 5 ve >=1 doğrulanır;
`ARS_DEF_LAYER`, `ars_valid_layer()` ile -1'i reddeder. Alım yolundaki tüm
`-Wsign-compare` uyarıları güvenli: `ip_size`/`enc_size` sınır kontrolleriyle
(`waitpacket.c:111,149`) negatif olamaz, RTT'ler negatif değildir. sbignum.c
(satıcı bignum kütüphanesi) uyarıları sözleşme gereği/yanlış pozitif olduğu
için değiştirilmedi. clang-tidy'nin başlık-koruma tanımlayıcıları ve eksik
`default` gibi bulguları biçimseldir, kusur değil.

**Kabul kanıtı.** Yeni `tests/test_parse.c:test_route()` (önceden test
edilmeyen `parse_route`'u kapsar; §6'daki fall-through reddini de sınar).
`make check` 14/14 (GCC ve clang, `WERROR`), `make check-live` 20/20,
ASan/UBSan/LSan temiz, `fuzz_opts`/`fuzz_apd` 3'er milyon koşu crash'siz,
man sayfası uyarısız.

**Geri alma koşulu.** Yok; düzeltmeler davranışı korur veya yalnız hatalı
yol / debug çıktısını onarır.
