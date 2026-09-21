# StyxWire — Aşama 5 raporu: IPv6, taşınabilirlik ve performans

Aşama 4 (`docs/ASAMA4-RAPORU.md`) üzerine, promptun 8. bölümü uygulandı.
Kararların gerekçeleri `docs/KARAR-KAYITLARI.md` (KK-11, KK-12, KK-13).
Referans: Aşama 4 sonrası ağaç (`4666309`).

---

## 1. Kısa değerlendirme

**Başlangıç.** Araç IPv6'yı hiç bilmiyordu: `ip6` diye bir APD katmanı yoktu,
`::1` gibi bir hedef "Unable to resolve" ile reddediliyordu (yanlış tanı:
adres çözülüyordu, desteklenmiyordu). Link-layer tarafında Ethernet varsayımına
yakın bir tablo vardı: `#ifdef DLT_IEE802_11` yazım hatası (bir E eksik) 802.11
dalını **hiç derletmiyordu**, `DLT_LINUX_SLL2` (modern Linux'ta `-i any` bunu
verir) tabloda yoktu, token ring 14 döndürüyordu (LLC/SNAP hesaba katılmadan) ve
desteklenmeyen bir tür `ctx.linkhdr_size`'a `(unsigned) -1` yazıyordu — bir
sonraki alımda yığında 4 GiB'lık bir VLA. Performans hakkında hiçbir ölçüm
altyapısı yoktu.

**Yapılan.** IPv6'nın **çevrimdışı yarısı** tamamlandı: `ip6`/`icmp6` APD
katmanları, RFC 8200 §8.1 pseudo-header ile TCP/UDP checksum'u, RFC 4443 §2.3
gereği pseudo-header'ı içeren ICMPv6 checksum'u, sürüm nibble'ına göre IPv4/IPv6
ayıran çözümleyici. **Gönderim yarısı bilinçli olarak reddedildi**: `ars_send()`
IPv6 paketini açık bir tanıyla geri çevirir, komut satırı IPv6 hedefte ne
yapılabileceğini örnekle söyleyip 1 ile çıkar. Link-layer tablosu gerçek DLT'yi
esas alacak biçimde yeniden yazıldı; başlık uzunluğu sabit olmayan türler
tahmin edilmek yerine adıyla reddediliyor. `make bench` ile yeniden üretilebilir,
ağsız ve root'suz bir performans temeli eklendi.

**Kullanıcıya etkisi.** `styxwire build/describe/validate` artık IPv6 paketleri
kurar ve çözer; `--read` içinde IPv6 taşıyan bir pcap'i doğru çözümler. `-i any`
ile alınmış bir yakalama (SLL2) artık çalışır — eskiden "physical layer header
size unknown" ile duruyordu. 802.11/radiotap yakalamaları yanlış ofsetten
çözümlenmek yerine adıyla reddediliyor. Test paketi 13 gruba, 1085 kontrole
çıktı (Aşama 4: 11 grup, 777 kontrol).

---

## 2. Kanıtlı analiz

### 2.1 IPv6 çevrimdışı dilimi (WP1, KK-11)

| # | İş | Ayrıntı | Kanıt |
|---|---|---|---|
| 1 | IPv6 başlık modeli | `ars.h:219` `struct ars_ip6hdr`, `ars.h:242` `ARS_IP6_SET` (ver/tclass/flow tek 32-bit alanda), `ars_ip6_pseudohdr` | T: `test_core.c:791` `test_ipv6_vectors` — her alanın tel üzerindeki yeri |
| 2 | `ip6`/`icmp6` katmanları | `ars.c:327` `ars_add_ip6hdr` (ver=6, hlim=64), `ars.c:343` `ars_add_icmp6hdr`, katman tablosu `ars.c:555-556` | T: aynı |
| 3 | APD dili | `apd.c:139-140` anahtar kelimeler, `apd.c:696` `ars_d_set_ip6` (saddr/daddr/ver/tclass/flow/plen/nh/hlim), `apd.c:742` `ars_d_set_icmp6` | T: bilinmeyen alan hataları; D: `docs/IPV6.txt` |
| 4 | Pseudo-header checksum | `ars.c:794` `ars_ip6_pseudo_cksum`; `ars_udptcp_cksum` alt katmanın IP mi IP6 mı olduğuna bakar; ICMPv6 `ars.c:878` `ars_compiler_icmp6` pseudo-header **dahil** hesaplar (ICMPv4'ten farkı) | T: ICMPv6 `0xe066` ve TCP/IPv6 `0x4194` bağımsız Python hesabıyla bayt-bayt aynı |
| 5 | Uzunluk/nexthdr otomatiği | `ars.c:834` `ars_compiler_ip6`: `plen` ve `nh` verilmediyse hesaplanır, verildiyse **aynen korunur** (kasıtlı bozuk paket üretimi bozulmaz) | T: açık `plen`/`nh`/`cksum` korunur vektörleri |
| 6 | Çözümleme | `split.c:162` sürüm nibble'ına göre IPv4/IPv6 seçimi, `split.c:246` `ars_split_ip6`, `split.c:230` uzantı başlığı DATA olarak korunur | T: 1..39 bayt FTRUNC, 40 bayt tam başlık, 41..47 FTRUNC; `plen` ile kırpma; uzantı başlığı |
| 7 | Serileştirme | `rapd.c:98` `ars_rapd_ip6`, `rapd.c:125` `ars_rapd_icmp6` (`inet_ntop`) | T: `build → describe → build` bayt-eşit tur |
| 8 | Gönderim reddi | `ars.c:1125` `ars_send` IPv6'yı tanıyla reddeder | T: `test_core` gönderim reddi kontrolü |

### 2.2 IPv6 komut satırı tanısı (WP2)

`resolve.c` yeniden yazıldı: `resolve_addr()` `inet_pton(AF_INET)` + IPv4
`getaddrinfo`; ayrıca `resolve.c:62` `resolve_is_ipv6_only()`. `lifecycle.c:232`
`resolve_or_fail()` bu ayrımı kullanır:

```
% styxwire -c 1 ::1
'::1' is an IPv6 address: styxwire's command line sends IPv4 only.
IPv6 packets can be built and dissected offline, for example:
  styxwire exec (then: styxwire build {ip6(daddr=::1)+icmp6(type=128)})
% echo $?
1
```

Çözülemeyen bir ad hâlâ `Unable to resolve '...'` verir; iki durum artık
ayrıştırılıyor. Belge: `docs/IPV6.txt`.

### 2.2b Alım yolu IPv6'yı sessizce atıyordu

Belgeyi yazarken "`--read` IPv6 içeren bir pcap'i çözümler" diye yazdım ve
doğrulamaya çalıştım: **yanlıştı**. `--read` sıradan alım döngüsünü dosya
üzerinde koşturur; o döngü `ip.ihl*4` ile ilerlediği için bir IPv6 datagramı
"bad IP header len" dalından düşüyor ve **hiçbir şey söylemeden** atılıyordu
(`received: 0`). Kullanıcının `tcpdump` ile gördüğü trafiği sessizce yok
saymak, bu projenin kaçındığı hata türünün ta kendisi.

Düzeltme (`waitpacket.c`): sürüm alanı 6 ise kare atlanır ama **bir kez**
stderr'e söylenir:

```
styxwire: skipping IPv6 datagrams: the receive path is IPv4 only (docs/IPV6.txt)
```

Belgeler düzeltildi: `docs/IPV6.txt` tablosunda `--read` satırı artık "hayır
(uyarıyla atlanır)"; man sayfası ve bu rapor aynı ayrımı yapar — **ARS
çözümleyicisi** IPv6'yı bilir, **alım döngüsü** bilmez.
T: `cli.sh` (IPv6 pcap fixture'ı: reply yok, uyarı bir kez).

### 2.3 Link-layer türleri (WP3, KK-12)

Bulunan kusurlar ve düzeltmeleri:

| Bulgu | Eski durum | Yeni durum |
|---|---|---|
| `#ifdef DLT_IEE802_11` (bir E eksik) | 802.11 dalı hiç derlenmiyordu (ölü kod) | Tablodan kaldırıldı; 802.11 ve radiotap `-1` döndürür (`getlhs.c:31`) |
| `DLT_LINUX_SLL2` yok | `-i any` yakalaması "unknown" | 20 bayt, fixture ile sınanıyor |
| Token ring 14 | MAC başlığı; LLC/SNAP atlanıyor, yanlış ofset | Desteklenmiyor (routing information field 0-18 bayt, sabit değil) |
| `DLT_LANE8023` | 16 (doğru: 2 bayt LANE + 14 Ethernet) | 16 korundu (yeniden yazım sırasında 8'e kaymıştı, diff incelemesinde yakalandı) |
| Desteklenmeyen tür | `ctx.linkhdr_size = (unsigned) -1`, sonraki alımda 4 GiB VLA | `getlhs.c:90` boyutu **değiştirmeden** başarısız olur, türü adıyla anar |
| Tcl `styxwire recv` tanısı | "Unknown link layer header size for this interface" | Tür adı ve arayüz adı ile (`script.c`) |

Ayrıca `waitpacket.c` içindeki `size < ctx.linkhdr_size` karşılaştırması
işaretli/işaretsiz karışımıydı; `scan.c`'deki deyimle aynı hale getirildi.

**Destek matrisi** `docs/PLATFORMS.txt`: her satır "fixture ile sınandı" /
"şartnameden alındı, denenmedi" / "desteklenmiyor" olarak ayrılır; işletim
sistemi tablosu "derleniyor / birim-test edildi / canlı test edildi"
sütunlarını ayrı tutar. Bir `#ifdef`'in varlığı destek sayılmaz.

### 2.4 Performans temeli (WP4, KK-13)

`tests/bench.c` + `make bench`: altı çevrimdışı iş yükü (IPv4/IPv6 kurma,
çözme, describe, checksum), tekrar başına min/medyan/maks ns/op, `--wrap`
ile tahsis sayımı, `getrusage` ile tepe bellek. Başlıkta makine, CPU,
derleyici, bayraklar, yineleme sayıları ve **CPU affinite'si** yazar.

Ölçüm sırasında bulunan ve belgelenen tuzak: sabitlenmemiş koşuda aynı ikili
`build4`'ü art arda 1229 ns/op ve 2988 ns/op ölçtü (P/E çekirdek farkı, 2.4 kat).
Bu nedenle `make bench` varsa `taskset -c 0` ile koşar. Referans koşu
`docs/BENCHMARK.txt`'te; **hedef sayı tanımlanmadı**.

`make check`, `tests/bench --selftest` ile iş yüklerinin doğru şeyi
hesapladığını doğrular (süre ölçmez). Bu selftest ilk koşusunda benim
elle yazdığım beklenen paket boyutlarının (73/93) yanlış olduğunu yakaladı;
doğrusu 66 ve 86 bayt.

### 2.5 Yeni testler

| Test | Kapsam |
|---|---|
| `tests/test_core.c:791` `test_ipv6_vectors` | tel düzeni, üç checksum türü bağımsız hesapla, bayt-eşit tur, 1..47 bayt kırpma, `plen` kırpması, uzantı başlığı, gönderim reddi, hatalı alan adları, IPv4 regresyonu |
| `tests/test_waitpacket.c:275` `test_link_layer_types` | `dltype_to_lhs` tablosu (desteklenen boyutlar + desteklenmeyenler `-1`), her desteklenen DLT için savefile ile `get_linkhdr_size` → `wait_packet` zinciri, link başlığından kısa kare düşürülür, desteklenmeyen türde `ctx.linkhdr_size` **değişmez** |
| `tests/linklayer.sh` | aynı IPv4/TCP datagramı altı farklı link başlığının arkasında pcap fixture'ı olarak; TTL/IP id/port alanları doğrulanır (yanlış ofset testi düşürür — SLL2 boyutu 16'ya bozularak kanıtlandı); 802.11/radiotap temiz hata |
| `tests/bench --selftest` | altı iş yükünün ürettiği değer |

---

## 3. Doğrulama raporu

Ortam: Linux 7.2 x86-64 (13th Gen Intel Core i5-1334U), GCC 16.2.1,
clang 22.1.8, libpcap 1.10.6, Tcl 8.6.16 ve Tcl 9.0.1 (scratchpad'de
kaynaktan), uid 1000. Tarih 2026-09-21.

| Komut | Sonuç |
|---|---|
| `./configure && make -j8 WERROR=1 && make check WERROR=1` (GCC, Tcl 8.6) | 0 uyarı; **13/13 grup, 0 hata** |
| `CC=clang ./configure && make -j8 WERROR=1 && make check WERROR=1` | 0 uyarı; 13/13 |
| `TCL_CONFIG=.../tcl9 ./configure --with-tcl && make -j8 WERROR=1 && TCL_LIBRARY=.../library make check WERROR=1` | 13/13 (`test_script` 102, Tcl 9.0.1) |
| `CC=clang ./configure --no-tcl && make -j8 check SANITIZE=1 WERROR=1` | ASan/UBSan/LSan temiz; 11/11 + 1 skip (Tcl'siz) |
| `make fuzz CC=clang`, her hedef `-runs=200000 -max_len=2048` | crash yok (split/apd/opts) |
| `make bench BENCHFLAGS="-n 50000 -r 9"` | tamamlandı; sayılar `docs/BENCHMARK.txt` |
| `tests/bench` ASan/UBSan/LSan altında (`--selftest` + kısa koşu) | sızıntı yok; `--wrap` yokken sütunlar `n/a` |
| SLL2 boyutunu 20 → 16 bozarak `tests/linklayer.sh` | 6 kontrol düştü (test ayırt ediyor), geri alınca 42/42 |
| `man --warnings -l docs/styxwire.8` | uyarı yok |

Grup dökümü (GCC, Tcl 8.6): `test_core` 418, `test_waitpacket` 102,
`test_scan` 71, `test_loop` 122, `test_parse` 77, `test_output` 18,
`test_script` 102, `cli.sh` 108, `linklayer.sh` 42, `install.sh` 17,
`rcfile.sh` 8, `libars.sh` ve `bench --selftest` (sayısız) — toplam 1085
adlandırılmış kontrol.

**Kabul ölçütleri (prompt §8):**
- IPv6 çevrimdışı vektörleri geçer — ✅ (`test_ipv6_vectors`, bağımsız checksum karşılaştırması).
- Desteklenmeyen IPv6 yolu sessizce yanlış paket üretmez — ✅ (`ars_send` reddi, CLI tanısı, çıkış kodu 1).
- Link-layer türü gerçek DLT'den alınır, Ethernet varsayılmaz — ✅ (`get_linkhdr_size`, altı fixture).
- Destek matrisi "derleniyor ≠ destekleniyor" ayrımını yapar — ✅ (`docs/PLATFORMS.txt`).
- Performans temeli yeniden üretilebilir ve koşulları raporlar — ✅ (`make bench`, affinite dahil).
- Uydurma hedef/eşik yok — ✅ (KK-13; yalnız referans koşu).

**Doğrulanmayan (dürüst liste):** canlı ağ gönderimi/alımı (root gerekir,
yapılmadı); BSD/macOS/Solaris derlemesi ve testi; token ring, FDDI, ATM, PPP,
SLIP türlerinin gerçek yakalamaları; GitHub Actions koşusu; IPv6 gönderim
yolu (kasıtlı olarak yok); `make styxwire-static`.

---

## 4. Uyumluluk notu

**Korunan:** tüm mevcut seçenekler, çıkış kodları, insan çıktı satır biçimleri,
Tcl API, APD dilinin mevcut katmanları, `hping*` adları, `--json` şeması (v1;
IPv6 alanı eklenmedi çünkü alım yolu IPv4).

**Yeni / bilinçli davranış değişiklikleri:**

1. **IPv6 hedef.** Eskiden `Unable to resolve '::1'` (yanıltıcı), şimdi ne
   yapılabileceğini söyleyen bir tanı. Çıkış kodu her iki durumda da 1.
2. **Token ring yakalamaları.** Eskiden 14 baytlık (yanlış) ofsetle
   çözümleniyordu, şimdi adıyla reddediliyor. Bu bir davranış değişikliğidir:
   eski çıktı zaten yanlıştı, sessizce yanlış olmaktansa açıkça reddediliyor.
3. **802.11.** Eskiden ölü koddu (`#ifdef` yazım hatası); davranış aynı
   (desteklenmiyor) ama artık tanı türü adıyla anıyor.
4. **`DLT_LINUX_SLL2`.** Eskiden desteklenmiyordu, şimdi çalışıyor — yalnız
   yetenek eklendi.
5. **`get_linkhdr_size()` imzası.** Artık 0/-1 döndürür (eskiden boyut/-1) ve
   başarısızlıkta `ctx.linkhdr_size`'a dokunmaz. Tek çağıran `lifecycle.c:319`
   zaten yalnız `-1` ile karşılaştırıyordu; dahili API.
6. **Tcl `styxwire recv` hata metni.** Tür ve arayüz adını içerir (metin
   değişti, semantik aynı).
7. **IPv6 kareler alım yolunda.** Eskiden sessizce düşürülüyordu; şimdi bir
   kez stderr'e uyarı yazılır. Çıktı biçimi ve çıkış kodu değişmedi.
8. **`docs/styxwire.8`.** Yeni `IPV6` ve `LINK LAYER TYPES` bölümleri; `AUTHOR`
   içindeki uydurma `www.styxwire.org` adresi gerçek tarihsel adresle
   değiştirildi.

---

## 5. Sonraki iş paketi

Prompt'un beş aşaması bu raporla tamamlandı. Devreden ve önerilen sıradaki
işler:

1. **Canlı ağ doğrulaması** (yerel veth/network namespace, root): gönderim,
   alım, RTT, `--scan`. Bugüne kadarki en büyük doğrulama boşluğu.
2. **B4/KK-5** `sendtcp.c` → ARS geçişi (bayt-eşit vektörler `test_core`'da
   hazır); CLI ve ARS gönderim yollarının çift bakımını bitirir.
3. **IPv6 gönderim yolu**: `AF_INET6` raw socket, kaynak adres seçimi, alım
   filtresi ve yanıt eşleştirme — `docs/IPV6.txt`'teki sıraya göre, her adım
   canlı doğrulamayla.
4. BSD/macOS derlemesi ve `make check`; GitHub Actions matrisinin gerçekten
   koşturulması; kabuk tamamlama; `make styxwire-static`.

**Kalan riskler:** canlı ağ hiçbir aşamada doğrulanmadı; ARS/CLI gönderim
yolları hâlâ ayrı; `docs/PLATFORMS.txt`'te "şartnameden alındı" satırları
gerçek yakalamayla sınanmadı; performans sayıları tek makineden.
