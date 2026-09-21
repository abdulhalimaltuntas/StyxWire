# hping3 için profesyonel analiz ve geliştirme promptu

Bu prompt, `/home/toretto/hping` deposunun kaynak kodu, dokümantasyonu ve geçici bir kopyada yapılan derleme incelemesi esas alınarak hazırlanmıştır. Referans commit: `3547c7691742c6eaa31f8402e0ccbb81387c1b99`. Depodaki uygulama koduna bu hazırlık sırasında müdahale edilmemiştir.

Aşağıdaki metni, projeye erişebilen bir yazılım geliştirme asistanına bütün olarak ver. İlk teslimatın kapsamı açıkça tanımlıdır; sonraki aşamalar bağımlılık sırasıyla yürütülmelidir.

---

## Rolün ve görevin

Kıdemli C/POSIX geliştiricisi, ağ protokolleri mühendisi, yazılım mimarı ve test otomasyonu sorumlusu olarak çalış. Bu depodaki hping3 projesini derinlemesine analiz et; mevcut yeteneklerini koruyarak güvenilir, test edilebilir, taşınabilir ve sürdürülebilir bir ağ teşhis ve protokol deney aracına dönüştür.

Hedef kullanıcılar ağ mühendisleri, sistem yöneticileri, protokol araştırmacıları, eğitmenler ve yetkili laboratuvar ortamlarında çalışan test ekipleridir. Ürünün temel değerini paket oluşturma, paket inceleme, tekrarlanabilir deneyler ve betiklenebilir teşhis oluşturur.

Yalnızca genel öneriler sunma. Her öneriyi mevcut dosyalara, gözlenen probleme, kullanıcı etkisine, uygulanabilir değişikliklere ve doğrulanabilir kabul ölçütlerine bağla. Önce çalışma başlangıcını kaydet, ardından aşağıda tanımlanan ilk teslimatı uygula ve doğrula. Sonraki aşamalar için bağımlılıkları belli bir iş listesi bırak.

Teknik açıklamaları Türkçe yaz. Kod sembollerini, komutları ve mevcut İngilizce teknik dokümantasyonun dilini tutarlı biçimde koru.

## 1. Projenin gerçek başlangıç noktası

Bu proje C, POSIX ağ arayüzleri, raw socket, libpcap ve isteğe bağlı Tcl desteği üzerine kuruludur. İncelenen commit'te Git tarafından izlenen 58 C dosyası, 15 başlık dosyası ve 15 Tcl betiği vardır. `release.h`, sürümü `3.0.0-alpha-1` olarak tanımlar. Bunlar bu checkout'a ilişkin verilerdir; projenin bütün dış geliştirme geçmişi hakkında sonuç çıkarma.

Başlıca bileşenler:

| Alan | Mevcut dosyalar | Analiz odağı |
|---|---|---|
| Başlatma ve CLI | `main.c`, `parseoptions.c`, `antigetopt.c`, `usage.c` | Argüman sözleşmesi, varsayılanlar, yan etkiler, mod seçimi |
| Ortak durum | `globals.h`, `hping2.h`, `main.c` | Global değişkenler, tür tutarlılığı, test edilebilirlik |
| Paket gönderimi | `send.c`, `sendip.c`, `sendtcp.c`, `sendudp.c`, `sendicmp.c`, `sendip_handler.c` | Uzunluklar, checksum, fragmentation, kaynak sahipliği |
| Alım ve çözümleme | `libpcap_stuff.c`, `waitpacket.c`, `display_ipopt.c`, `listen.c` | Yakalanmış veri sınırları, kesilmiş paketler, hata davranışı |
| Ölçüm ve tarama | `scan.c`, `rtt.c`, `getusec.c`, `statistics.c`, `signal.c` | Zamanlama, sayaçlar, yanıt eşleme, kapanış |
| ARS/APD motoru | `ars.c`, `ars.h`, `apd.c`, `split.c`, `rapd.c`, `arsglue.c` | Paket modeli, metin/binary dönüşümü, CLI ile örtüşen işlevler |
| Tcl entegrasyonu | `script.c`, `lib/*.htcl`, `lib/hpingstdlib.htcl` | C API uyumluluğu, olay döngüsü, nesne ömürleri |
| Yardımcı kod | `adbuf.c`, `hex.c`, `memstr.c`, `sbignum.c` | Boyut hesapları, sınır durumları, kullanım gerekçesi |
| Derleme ve belgeler | `configure`, `Makefile.in`, `README`, `INSTALL`, `docs/`, `TODO` | Bağımlılık keşfi, paketleme, doküman/kod tutarlılığı |

Klasik CLI gönderim yolu ile ARS/APD/Tcl yolunu ayrı ayrı haritala. Benzer protokol işlemlerinin iki yerde bulunmasının hata düzeltmelerine etkisini incele. ARS mevcut olduğu için otomatik olarak sağlam veya bütün CLI davranışlarının yerine geçebilir olduğunu varsayma.

### Ön incelemede bulunan somut sorunlar

Aşağıdaki satır numaraları referans commit'e aittir. Güncel ağaçta yeniden doğrula; doğrulanmış bulgu, derleyici tanısı, olası risk ve geliştirme önerisini birbirinden ayır.

| Öncelik | Kanıt | Bulgu ve gerekli iş |
|---|---|---|
| P0 adayı | `libpcap_stuff.c:66–73` | Alıcı kapasitesi için hesaplanan sınır `memcpy` ve dönüş değerinde kullanılmıyor. `caplen` ile hedef kapasite arasındaki sözleşmeyi düzelt; kesilme bilgisini kaybetme. |
| P0 adayı | `scan.c:445–459` | ICMP yapısına `sizeof(subtcp)` uzunluğunda kopyalama yapılıyor. İncelenen derlemede 8 baytlık hedefe 20 bayt yazılması için derleyici tanısı görüldü. |
| P0 adayı | `waitpacket.c:430–455` | Alıntılanmış IP paketi içinde iki bayt kontrolünden sonra bütün UDP başlığı kopyalanıyor; ICMP yolunda kopyalama uzunluk kontrolünden önce gerçekleşiyor. |
| P0 adayı | `waitpacket.c:617–648` | TCP başlık uzunluğu karşılaştırması hatalı; sıfır uzunluklu seçenek döngünün ilerlememesine yol açabiliyor. Kesilmiş seçenekleri ve her iterasyonda ilerleme garantisini ele al. |
| P0 adayı | `display_ipopt.c:93–112` | Record Route alanlarından türetilen uzunluk, sabit `old_rr` tamponuna kopyalanmadan önce kapasiteyle sınırlandırılmıyor. |
| P0 adayı | `script.c:330–347` | Çoklu alımda `pkt` her pakette ilerletiliyor, sonraki okumaya yine tam tampon kapasitesi veriliyor. Her iterasyonda tampon başlangıcını ve kalan uzunluğu doğru kur. |
| P0 adayı | `send.c:42–44`, `memstr.c:19–23` | Dört elemanlı dizilere `%4[...]` ile sonlandırıcı dahil yazma ve `strlen` sonucunu `char` içinde saklama gibi sınır/tür hataları var. |
| P0 adayı | `sendicmp.c:254–262`, `split.c:371–388` | Kaynak başlık boyutu yerine kalan alan kadar okuma; minimum TCP uzunluğu doğrulanmadan alan erişimi. Kaynak ve hedef sınırlarını ayrı ayrı doğrula. |
| P1 | `main.c:294–300`, `send.c:66–91`, `statistics.c:22–52` | Sinyal bağlamından paket üretimi, çıktı, bellek ve kapanış işlemlerine ulaşılıyor. Bu işleri normal yürütme bağlamına taşı. |
| P1 | `script.c:727–779`, `script.c:400–403` | Olay kaydı temizlenirken dosya olayı kaldırılmıyor; bazı Tcl sayısal dönüşümlerinin dönüş kodları denetlenmiyor. |
| P1 | `script.c:267–281` | APD açıklaması üretilirken tahsis sonucu ve split/serializer hataları denetlenmiyor. Başarısızlıkların Tcl'ye aktarımını ve her hata yolunda temizliği doğrula. |
| P1 | `main.c:157–158`, `globals.h:122–134` | `ip_optlen` tanımı `unsigned`, dış bildirimi `char`; tek ve tutarlı tür bildirimi sağla. |
| P1 | `parseoptions.c:236–339`, `parseoptions.c:507–516`, `usage.c:24–25` | Sayısal dönüşümlerin çoğu son karakter/taşma denetimi yapmıyor. `--faster` dalında `break` eksik; hız açıklamaları ve uygulanan aralıklar uyuşmuyor. |
| P1 | `getusec.c:24–28`, `rtt.c:57–58` | Süre hesaplarında gün sonunda sıfırlanan değerler ve ayrı duvar saati okumaları kullanılıyor. Monotonik zaman ve enjekte edilebilir saat tasarla. |
| P1 | `apd.c:92–136`, `rapd.c:329–346` | Parser ile serializer bazı seçeneklerde farklı adlar kullanıyor; TCP timestamp alan ayarlayıcısı boş bir makroyla başarı döndürüyor. Desteklenen dönüşümlerin sözleşmesini düzelt. |
| P1 | `configure:64–113`, `Makefile.in:9–12`, `Makefile.in:74–85` | Tcl keşfi eski sabit sürüm/yol listelerine bağlı. Derleyici ve kurulum yolları sabit; standart kurulum değişkenleri ve staging desteği eksik. |
| P1 | `lib/regtest/rt0.htcl:4–13`, `Makefile.in` | Mevcut regresyon betiği sabit adreslere paket gönderiyor; assertion veya test koşucusu içermiyor. İncelenen ağaçta CI iş akışı bulunmadı. |
| P2 | `README`, `docs/APD.txt:7–29`, `docs/hping3.8:1–5`, `TODO` | CVS talimatları, APD sözdizimi ve ürün adı gibi belgeler kodla uyumsuz. Tarihî TODO maddelerini güncel gereksinim olarak otomatik devralma. |

Ön incelemede geçici kaynak kopyasında `./configure --no-tcl` komutu `0` ile çıkmasına rağmen `line 81: -: command not found` tanısı üretmiştir. `make -j2`, `libpcap_stuff.c:19` içindeki `net/bpf.h` bulunamadığı için `2` ile sonlanmıştır. Ortamda pkg-config üzerinden libpcap `1.10.6` ve Tcl `8.6.16` görülmüştür. Bu sonuçlar tüm platformlarda derlenemediği iddiası değildir; başlangıç ortamının tekrarlanabilir bulgularıdır.

Bazı parser ve yardımcı fonksiyon hataları, kaynak dosyalarını içeren bağımsız ASan/UBSan deneme programlarıyla da yeniden üretilmiştir: kesilmiş TCP başlığı ve alıntılanmış taşıma başlığında sınır dışı okuma, Record Route kopyalamasında sınır dışı yazma, hedef metni ayrıştırmasında tampon taşması ve `memstr` uzunluk dönüşümü hatası. Sıfır uzunluklu TCP seçeneğinde zaman aşımı gözlenmiştir. Bu denemeler geçici uyumluluk başlıklarıyla yapılmıştır; tam uygulamanın başarıyla derlendiği veya canlı ağ üzerinde uçtan uca test edildiği anlamına gelmez. İlk teslimatta bulguları deponun kendi kalıcı testlerine dönüştür.

## 2. Çalışma ilkeleri ve kapsam

1. Önce varsa geçerli `AGENTS.md` talimatlarını, Git durumunu ve mevcut kullanıcı değişikliklerini incele. Kullanıcı çalışmalarını koru.
2. Her bulgu için `dosya: satır`, tetikleyici koşul, gözlenen sonuç, beklenen davranış, etki, kanıt türü, önerilen düzeltme ve doğrulama yöntemi kaydet. Dayanaksız CVE, risk puanı veya uzaktan istismar iddiası üretme.
3. Düzeltmeleri küçük, derlenebilir ve gözden geçirilebilir iş paketleri olarak uygula. Geniş dosya taşıma/formatlama işlemleriyle işlevsel değişiklikleri aynı pakete karıştırma.
4. İlk yaklaşım C kodunu aşamalı iyileştirmek olsun. Dil veya build sistemi değişikliği için somut yarar, geçiş maliyeti, uyumluluk etkisi ve alternatifleri içeren kısa bir karar kaydı hazırla.
5. CLI seçeneklerini, varsayılanları, çıkış kodlarını, `hping`/`hping2` adlarını, Tcl komutlarını ve APD davranışını karakterizasyon testleriyle kaydet. Bir hata düzeltmesi eski davranışı değiştiriyorsa bunu açıkça belgele.
6. Protokol deney aracı olmasının gereği olarak bilinçli hatalı checksum veya başlık üretme yeteneğini koru. Bellek güvenliği ve girdi boyutu kontrollerini, kullanıcının açıkça istediği protokol alanı değerlerinden ayrı tasarla.
7. Rutin kodlama ve dosya düzeni kararlarını gerekçeli varsayımlarla ilerlet. Çalışmayı etkileyen belirsizliği somutlaştır; bağımsız işleri sürdür. Her küçük adım için kullanıcıdan onay isteme.
8. Derleme ve testleri çalışma alanı veya geçici kopyalarda yürüt. Sistem dizinlerine kurulum, yayın, push veya sürüm etiketi oluşturmayı bu promptun örtülü gereği sayma.
9. Varsayılan test paketi ağ trafiği üretmeden ve root gerektirmeden çalışsın. Canlı entegrasyonu ayrı, sonlu, temizliği garantili yerel laboratuvar testleri olarak tanımla. Mevcut `lib/regtest` betiğini doğrudan otomatik çalıştırma.
10. Başarıyla çalıştırılmayan kontrolleri başarılı gösterme. Eksik bağımlılık, test edilmemiş platform ve kalan teknik borcu açıkça raporla.

## 3. İlk analiz çıktıları

Uygulamaya başlamadan önce kısa fakat kanıtlı bir başlangıç raporu oluştur:

- Mimari bileşenler, bağımlılıklar ve CLI/Tcl için başlatma → doğrulama → paket oluşturma → gönderme/alma → yorumlama → çıktı → kapanış akışları.
- Tekrarlanan protokol mantığı, global durum, kaynak sahipliği, doğrudan `exit()` çağrıları ve platforma özgü kod sınırları.
- Derleme komutları, kullanılan derleyici/bağımlılık sürümleri ve ham sonuçların özeti.
- CLI, APD ve Tcl için korunacak davranış matrisi; belgelerin bu matrisle çeliştiği yerler.
- Önceliklendirilmiş risk ve geliştirme listesi. P0: yeniden üretilmiş ciddi doğruluk/bellek hataları; P1: güvenilir derleme, temel testler ve yaşam döngüsü; P2: kullanıcı/otomasyon iyileştirmeleri; P3: geniş kapsamlı yetenekler.
- Her iş için bağımlılık, S/M/L efor tahmini, gerekçe ve kabul ölçütü. Tarih veya performans rakamı uydurma.

Mimariyi açıklarken kısa bir Mermaid bileşen diyagramı kullanabilirsin. Diyagramın kaynak kod akışıyla tutarlı olmasını sağla.

## 4. Aşama 1 — Güvenilir derleme ve kritik düzeltmeler

İlk teslimat bu aşamadır. Analiz raporunda durma; gerekli düzeltmeleri ve regresyon testlerini uygula.

### Derleme

- Önce mevcut `configure`/Makefile akışını işler hale getir. libpcap başlık seçimini desteklenen platforma göre yap; farklı sistemlerin başlıklarını elle kopyalatma.
- `--no-tcl` seçeneği Tcl keşfinden önce etkili olsun. Tcl'nin bulunmadığı, isteğe bağlı olduğu ve açıkça istendiği durumlar ayırt edilsin; başarısız keşif sessiz başarıyla sonuçlanmasın.
- `CC`, `CPPFLAGS`, `CFLAGS`, `LDFLAGS`, `LDLIBS`, `AR` gibi standart değişkenleri tutarlı destekle. pkg-config ve mevcut Tcl yapılandırma verilerini değerlendir.
- Derleyici uyarılarını envanterle. İlk aşamada bütün eski kodu tek seferde `-Werror` ile kilitlemeden yeni uyarıları engelle; temizlenen bileşenlerde daha sıkı kontroller uygula.
- Paralel derleme ve üretilen başlık bağımlılıklarını düzelt. Byte order tespiti için hedef binary çalıştırmaya dayanan tasarımın çapraz derlemeye etkisini kaydet.
- `PREFIX`, `DESTDIR`, `sbindir`, `mandir` ile yetkisiz staging kurulumu sağla. Tekrarlı kurulum, sembolik bağlantılar ve boşluk içeren yollar için açık davranış belirle.
- Yeni bir build sistemi gerekiyorsa Meson/CMake veya mevcut sistemin iyileştirilmesini karar kaydında karşılaştır; tek bir ana akış seç. İki bağımsız build tanımını süresiz birlikte bakıma alma.

### Bellek ve parser doğruluğu

- Her kopyalamada kaynakta kalan gerçek veri ve hedef kapasitesi birlikte denetlensin. Paket üstbilgisindeki iddia edilen uzunluk, yakalanan veri uzunluğu yerine kullanılmasın.
- IP IHL, TCP data offset, UDP/ICMP uzunluğu, iç içe alıntılanmış başlıklar, seçenek uzunlukları ve link header sınırları için ortak kurallar oluştur.
- Her parser döngüsünde ilerleme veya kontrollü sonlanma garantisi bulunsun. Boş, kesilmiş, aşırı uzun ve bilinmeyen alanlar deterministik sonuç versin.
- `size_t`, sabit genişlikli protokol türleri ve işaretli hata kodlarının dönüşüm sınırlarını açıklaştır. Taşma kontrolünü dar türe dönüştürmeden önce yap.
- `strtol`/`strtoul` kullanımlarında `errno`, `endptr`, boş girdi, artık karakter ve alan aralığını denetle. Belgelenmiş özel değerleri ve deney amaçlı seçenekleri dikkate al.
- Tcl paket alımında tampon işaretçisinin yeniden kurulmasını, negatif kalan uzunlukları, nesne referanslarını ve olay kayıtlarının kaldırılmasını düzelt.
- İlk tabloda işaretlenen hataların tamamını triage et; aynı hata kalıbının komşu çağrı noktalarını da kontrol et. Her teyit edilmiş düzeltmeyi hatayı önce gösteren bir regresyon testiyle teslim et.

### İlk teslimatın kabul ölçütleri

- Desteklenen başlangıç Linux ortamında temiz kopyadan derleme başarılıdır; başarısız yapılandırma anlamlı ve sıfırdan farklı bir kod döndürür.
- Zorunlu başlangıç matrisi Tcl kapalı ve seçilen desteklenen Tcl sürümüyle açık yapılandırmaları kapsar. Çalıştırılamayan varyant “atlandı/doğrulanmadı” olarak raporlanır; matris tamamlanmadan tam doğrulama iddiası yapılmaz.
- `--help` ve `--version` root, DNS veya ağ erişimi gerektirmeden çalışır.
- Düzeltmelerin regresyon testleri eski kusuru gösterir, yeni kodla geçer; ASan/UBSan çalıştırmalarında bu testler hata üretmez.
- Varsayılan testlerde raw socket/capture açılmadığı doğrulanır.
- Kurulum testi yalnızca staging dizinine yazar; kaynak ağaç ve sistem dizinlerine beklenmedik yan etki oluşturmaz.
- Mevcut CLI davranışındaki bilinçli değişiklikler listelenir; çözülmeyen P0/P1 maddeleri görünür bırakılır.

## 5. Aşama 2 — Mimari ve çalışma yaşam döngüsü

İlk aşamadaki test tabanı üzerine ilerle:

- Konfigürasyonu, çalışma durumunu, istatistikleri ve platform I/O kaynaklarını açık yapılara ayır. Örneğin `hping_config`, `hping_context`, `hping_stats` adlarını değerlendirebilirsin; asıl ölçüt sorumlulukların ayrılmasıdır.
- Derin fonksiyonlardan `exit()` çağırmak yerine hata kodu ve bağlam taşı. CLI ve Tcl hatayı kendi arayüz sözleşmelerine dönüştürsün.
- `init/run/stop/destroy` yaşam döngüsü tanımla. Kısmi başlatma hatası, kullanıcı kesmesi ve normal tamamlanma aynı sahiplik kurallarına uysun.
- Sinyal işleyicilerini en az işe indir; gönderim, bellek yönetimi ve çıktı normal olay döngüsünde yürüsün. POSIX taşınabilir bir temel kur; Linux'a özel mekanizmaları isteğe bağlı backend olarak ayır.
- RTT, deadline ve aralık hesaplarında tek monotonik saat kullan. Raporlama için duvar saatini ayrı tut; testler için saat ve rastgelelik kaynağı enjekte edilebilsin.
- Sayaçlarda uzun çalışma süresini karşılayan türler kullan. Tekrarlı, geç ve sıra dışı paketleri benzersiz cevaplardan ayır; sıfır gönderim ve yinelenen cevaplarda kayıp hesabını tanımla.
- `scan.c` içindeki süreç/paylaşılan bellek ve zamanlama tasarımını ayrıca incele. `volatile` kullanımını tek başına eşzamanlılık garantisi kabul etme.
- Parser/serializer katmanını ağ erişiminden bağımsızlaştır. CLI ve Tcl'nin ortak çekirdeği kullanmasına testlerle, küçük geçişlerle yaklaş.
- `libars.a` hedefinin bağımsız bağlantı için gerekli yardımcı bağımlılıklarını doğrula. Genel kullanım için kütüphane API'si sunulacaksa ABI kararlılığı sözü vermeden önce yaşam döngüsü ve hata sözleşmesini tamamla.
- Dosyaları `src/cli`, `src/core`, `src/protocols`, `src/platform`, `src/scripting`, `tests`, `docs` gibi bir düzene taşımayı ancak modül sınırları netleştikten sonra değerlendir.

Kabul: ağ açmadan paket oluşturma/ayrıştırma testleri çalışır; test bağlamları birbirini etkilemez; kesme ve hata senaryoları kaynak sızıntısına yol açmaz; saat değişimlerini simüle eden testlerde RTT/deadline hesapları tutarlıdır.

## 6. Aşama 3 — Tcl, APD ve çevrimdışı çalışma

- Tcl desteğini korunacak bir ürün yeteneği kabul et. Desteklenen sürümleri açık bir matrisle belirt; sürüm keşfini düzeltmek ile C API portunu birbirine karıştırma.
- Tcl 8.6 ve Tcl 9 için ayrı uyumluluk değerlendirmesi yap. Tcl 9'da uzunluk ve indeks türleriyle ilgili `Tcl_Size` değişikliklerini resmi geçiş belgesine göre ele al. Destek iddiası gerçek derleme ve çalışma testlerine dayansın. [Resmi Tcl geçiş rehberi](https://core.tcl-lang.org/tcl/wiki?name=Migrating+C+extensions+to+Tcl+9).
- `Tcl_Get*FromObj` hatalarını yay, string/byte-array ayrımını koru, callback kaldırma ve interpreter kapanışını test et. Tcl ortamını kendiliğinden bir güvenlik sandbox'ı olarak tanıtma.
- `script.c:1340–1348` içindeki otomatik `.hpingrc` yüklemesini ve yutulan başlangıç hatalarını ele al. Başlangıç dosyasını devre dışı bırakabilen açık bir seçenek veya enjekte edilebilir yükleyici ile testleri kullanıcı ortamından bağımsızlaştır; başlangıç davranışını ve izin bağlamını belgele.
- Tcl standard library ve örneklerini staging kurulumuna dahil et. Çalışma dizinine bağlı `source` yollarını, örneğin `lib/ping.htcl:2`, betik konumu veya açık paket arama yolu üzerinden çöz. `lib/hpingstdlib.htcl:104` gibi sabit arayüz kullanımını gerçek seçilen arayüzle eşleştir.
- `recv`, `recvraw`, `event` ve `setfilter` için timeout, count, iptal ve kaynak sahipliği sözleşmesini belgeleyip test et. Sınırsız liste birikiminin yerine isteğe bağlı akış/limit yaklaşımını değerlendir.
- APD gramerini uygulamayla eşleştir. `tcp.ts`/`tcp.timestamp` ve `tcp.echo`/`tcp.echoreq` gibi adlar için kanonik gösterim ve geriye uyumlu alias politikası belirle.
- Başarı döndüren fakat alanı uygulamayan setter'ları kaldır veya tamamla. Desteklenmeyen alan açık ve test edilebilir hata versin.
- APD → binary → APD dönüşümünde anlamsal eşdeğerlik kriteri tanımla. Otomatik checksum/uzunluk normalizasyonu ile kullanıcının açık değerlerini ayır; byte-for-byte korunmanın garanti edildiği alt kümeyi belirt.
- `build`, `describe` ve `validate` benzeri çevrimdışı yetenekleri ortak çekirdek üzerinden sun. Dosya girdisi, DNS ve ağ işlemleri açık bağımlılıklar olsun.
- `--dry-run` ve paket dosyasına çıktı için tasarım yap. Dry-run, CLI ve APD yollarında raw socket/capture açılmadan önce devreye girsin. Varsayılan çevrimdışı senaryolar literal adreslerle DNS gerektirmesin.
- PCAP okuma/yazma eklenirse `caplen`, gerçek paket uzunluğu, timestamp ve link-layer türü doğru korunsun; çevrimdışı okuma kendiliğinden yeniden gönderime dönüşmesin.

Kabul: mevcut desteklenen Tcl/APD örnekleri tanımlı davranışı korur; callback ekleme/silme döngüleri ve çoklu paket alımı testlerden geçer; çevrimdışı dönüşümler root ve ağ olmadan çalışır; round-trip farkları belgelenen normalizasyonla sınırlıdır. Staging kurulumundaki betik modülleri farklı çalışma dizininden yüklenebilir; testler kullanıcı başlangıç dosyasını çalıştırmaz.

## 7. Aşama 4 — Profesyonel CLI ve otomasyon

- Mevcut kısa/uzun seçenekleri koru; kullanım yardımını ve man sayfasını aynı davranış matrisiyle doğrula. `--fast`/`--faster` için belgeler, sayısal birimler ve fiilî davranış arasındaki çelişkiyi açık bir uyumluluk kararıyla çöz.
- Parametre ayrıştırma yan etkisiz olsun. Özellikle `--apd-send` gibi erken gönderim yapan yolların doğrulama ve ortak çalıştırma aşamasını atlamasını engelle.
- İnsan tarafından okunabilir çıktıya ek olarak isteğe bağlı JSON/NDJSON çıktı sun. Şema sürümü, olay türü, hedef, protokol, sıra numarası, RTT birimi, zaman damgası, sayaçlar ve hata alanları tanımlansın.
- Yapılandırılmış çıktı etkin olduğunda stdout yalnızca o biçimi taşısın; tanı mesajları stderr'e gitsin. Bilinmeyen değerleri yanıltıcı sıfırlara dönüştürme; alan yokluğu veya `null` davranışını belgeleyip test et.
- Mevcut çıkış kodları ile `--tcpexitcode` davranışını koruyan, yeni arayüzlerde açık hata sınıfları sunan bir sözleşme oluştur.
- Hatalar, sorunlu değeri, beklenen aralığı ve düzeltilebilir bağlamı açıklasın. Tcl desteği eksikliği, arayüz bulunamaması, bağımlılık hatası ve yetersiz izin ayrı tanılar olsun.
- Teşhis çalışmalarına açık paket sayısı, toplam süre ve hız sınırı eklemeyi değerlendir. Değişiklikleri gizli varsayılan değişimi yapmadan belgele; zamanlama doğruluğunu yerel deneylerde ölç.
- İzin gerektirmeyen komutları izinli I/O işlemlerinden ayır. En az yetki yaklaşımını platforma göre incele; tüm Tcl yorumlayıcısına otomatik kalıcı yetki vermeyi veya setuid kurulumu varsayılan yapma.
- Kabuk tamamlama ve komut örneklerini CLI sözleşmesi sabitlendikten sonra ekle.

Kabul: JSON şema testleri ve CLI regresyonları geçer; yardım ile gerçek seçenekler tutarlıdır; hatalı girdi ağ işlemi başlamadan reddedilir; mevcut otomasyonun etkilendiği davranışlar geçiş notunda açıklanır.

## 8. Aşama 5 — IPv6, taşınabilirlik ve performans

Bu aşamadaki işler çekirdek doğruluğu ve test altyapısına bağımlıdır. İlk teslimata gelişigüzel ekleme.

- IPv6'yı yalnızca DNS çözümleyicisini değiştirmek olarak ele alma. `sockaddr_storage`, `getaddrinfo`, IPv6 paket modeli, TCP/UDP pseudo-header checksum, ICMPv6, link-local scope ve arayüz seçimini birlikte tasarla.
- İlk IPv6 dilimini açıkça sınırla: çevrimdışı temel başlık/taşıma protokolü dönüşümü ve test vektörleri; ardından yerel laboratuvarda gönderim/alım. Extension header, fragment ve komşu keşfi kapsamını ayrı iş paketleri olarak değerlendir.
- Desteklenmeyen IPv6 davranışları açık hata versin; IPv4 işlevleri için regresyon matrisi korunsun. Depodaki tarihî RFC kopyalarını güncel standartların tek kaynağı kabul etme.
- libpcap backend'inde gerçek link-layer türünü esas al. Ethernet varsayımına dayanmadan loopback, Linux cooked capture ve desteklenecek diğer türleri fixture'larla sınayıp destek matrisinde belirt.
- Olay döngüsü entegrasyonunda `pcap_get_selectable_fd()` sonucunun her ortamda geçerli bir fd olacağını varsayma. Timeout/nonblocking davranışı ve desteklenmeyen backend durumları için belgeli yol belirle. [Resmi libpcap açıklaması](https://www.tcpdump.org/manpages/pcap_get_selectable_fd.3pcap.html).
- Linux dışındaki platformlar için derleme desteği, unit test ve canlı ağ desteğini ayrı statülerde raporla. Sadece `#ifdef` bulunmasını platform desteği sayma.
- Performans değişikliklerinden önce aynı makinede tekrarlanabilir baseline oluştur: çevrimdışı parse/build süresi, tahsis sayısı, bellek kullanımı, CPU, gecikme sapması ve yakalama kaybı.
- CPU ile ağ/çekirdek kaynaklı kayıpları ayrı ölç. Optimizasyonu profiling sonucuna bağla; doğruluk ve deterministik davranışı koru. Keyfî paket/saniye veya yüzde iyileşme hedefi uydurma.

Kabul: her yetenek için kapsam ve sınırlamalar bellidir; protokol vektörleri geçer; test edilen platformlar açıkça listelenir; performans sonucu donanım, komut, iş yükü ve ölçüm yöntemiyle yeniden üretilebilir.

## 9. Test stratejisi ve CI

Test altyapısını yalnızca dosya varlığı veya mock çağrı sayısını doğrulayacak şekilde kurma. Kullanıcıya etkisi olan davranışları ve hata sınıflarını test et.

| Test katmanı | Gerekli senaryolar |
|---|---|
| Unit | Tek/çift uzunluklu checksum, byte order, sayı dönüşümü, boyut taşması, payload ve imza sınırları |
| Parser regresyonu | 0 bayt, minimumdan kısa başlık, tutarsız uzunluk, option len 0/1, EOL/NOP, iç içe ICMP alıntısı, desteklenmeyen katman |
| Paket vektörü | IPv4/TCP/UDP/ICMP için bağımsız beklenen binary, seçenekler, checksum, fragment sınırları |
| APD/Tcl | Alan alias'ları, binary payload, dönüşüm hataları, nesne ömrü, callback kaldırma, çoklu alım ve zaman aşımı |
| CLI | Help/version, hatalı değerler, seçenek kombinasyonları, varsayılanlar, çıkış kodları, stdout/stderr ayrımı |
| Yaşam döngüsü | Kısmi init hatası, capture EOF/hata, SIGINT/SIGTERM, iptal, dosya/socket temizliği |
| Çevrimdışı entegrasyon | Sabit PCAP fixture'ları, farklı link türleri, build/describe, yapılandırılmış çıktı şeması |
| Yerel ağ entegrasyonu | Ayrı opt-in çalıştırıcı; sınırlı trafik; namespace/veth veya eşdeğer kontrollü topoloji; timeout ve cleanup |
| Fuzz | APD, split/rapd, seçenek parser'ları ve binary girişler; ağsız hedefler, küçük corpus, boyut/süre sınırı |

ASan/UBSan kontrollerini CI'a ekle; sanitizer bulgularının çözüldüğünü ilgili regresyonlarla göster. AddressSanitizer bellek hatalarını saptamak için kullanılabilir; üretim binary'sine test runtime'ı taşıma. [Resmi AddressSanitizer belgesi](https://clang.llvm.org/docs/AddressSanitizer.html).

Fuzz çalıştırıcısı için libFuzzer veya uygun bir alternatifi, araç zinciri ve bakım maliyetine göre seç. Hedefleri deterministik, hızlı ve tekrar çağrılabilir yap; çökme girdilerini küçültüp regresyon corpus'una ekle. CI'da kısa, ayrı periyodik çalıştırmada daha uzun bütçe kullan; sabit süre boyunca hata bulunmamasını bütün hataların yokluğu olarak sunma. [Resmi libFuzzer belgesi](https://llvm.org/docs/LibFuzzer.html).

Başlangıç CI matrisi Linux üzerinde GCC ve Clang ile Tcl açık/kapalı derlemelerini kapsasın. Sanitizer ve staging kurulum testlerini gereksiz matris çarpımı olmadan ekle. Daha sonra doğrulanabilir platformlara genişlet. Gerekli izin veya araç eksikliğiyle atlanan testler açık bir skip gerekçesi versin.

Coverage başlangıcını ölç; önce kritik parser ve boyut kontrolü dallarının eksiklerini kapat. Bütün eski depo için keyfî bir yüzde hedefini ilk teslimatın önüne koyma. Yeni kritik dallarda sınır ve hata yollarını kapsa.

## 10. Dokümantasyon ve sürüm disiplini

- `README`: ürünün amacı, gerçek destek durumu, özellik matrisi, bağımlılıklar, kısa kurulum ve çalıştırılabilir başlangıç örnekleri.
- `INSTALL` veya eşdeğeri: desteklenen platformlar, Tcl açık/kapalı derleme, staging kurulumu, kaldırma ve yaygın hata çözümleri.
- Kullanıcı belgeleri: CLI, APD grameri, Tcl API, offline kullanım, izin modeli ve eski davranışlardan geçiş.
- Geliştirici belgeleri: mimari akış, modül sorumlulukları, kaynak sahipliği, protokol ekleme, test/fuzz çalıştırma ve kod katkısı.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`: kısa, uygulanabilir süreçler; mevcut proje iletişim kanallarını doğrulamadan yeni adres veya sorumlu uydurma.
- Karar kayıtları: build sistemi, ortak çekirdek, zamanlama, çıktı şeması, Tcl sürüm desteği ve IPv6 kapsamı.
- Eski içeriklerin tarihî niteliğini belirt; eski TODO'ları fayda, bakım maliyeti ve güncel ürün amacıyla yeniden değerlendir. Örnekleri varsayılan olarak çevrimdışı veya yerel laboratuvara uygun hale getir.
- Var olan lisans ve telif bildirimlerini koru. Sürüm numarasını sırf görünüm için değiştirme; doğrulanmış kapsam ve uyumluluk politikasına bağla.
- Sürüm hazırlığında temiz kaynak arşivinden build/test, gerekli lisans dosyaları, sürüm notları ve doğrulanabilir artifact üretimini kapsa. Yayın ve dış sistem işlemlerini ayrıca yetkilendirilmiş kapsamla yürüt.

## 11. Beklenen teslimat biçimi

İlk uygulama turunun sonunda şunları teslim et:

1. **Kısa değerlendirme:** Başlangıç durumu, en önemli problemler ve kullanıcıya etkileri.
2. **Kanıtlı analiz:** Dosya referanslarıyla mimari, bulgular ve gözlenen build/test sonuçları.
3. **Öncelikli iş listesi:** P0–P3, bağımlılık, efor, kabul ölçütü ve açık kalan kararlar.
4. **İlk aşamanın kodu:** Derleme düzeltmeleri, triage sonucu doğrulanan kritik hata düzeltmeleri ve anlamlı regresyon testleri.
5. **Doğrulama raporu:** Gerçekte çalıştırılan komutlar, ortam, sonuçlar; başarısız veya atlanan kontrollerin gerekçesi.
6. **Uyumluluk notu:** Korunan davranışlar, bilinçli değişiklikler ve etkilenen betik/komut örnekleri.
7. **Sonraki iş paketi:** Bağımlılıkları tamamlanan en yüksek öncelikli aşama ve kalan riskler.

Doküman adlarını mevcut düzenle uyumlu seç; aynı bilgiyi farklı dosyalarda gereksiz tekrar etme. Her iş paketini somut bir önce/sonra davranışı ve doğrulama kanıtıyla kapat.

**Başlangıç komutun:** Depoyu ve ön bulguları doğrula, build başlangıcını kaydet, ardından Aşama 1'i uygula. İlk teslimat tamamlanmadan geniş IPv6 portu, kapsamlı dosya taşıma veya yeni kullanıcı arayüzü çalışmalarına yayılma. Aşamaların tamamını bitirmiş gibi raporlama; tamamlanan işi ve sonraki bağımlılıkları açıkça göster.
