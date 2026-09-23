# 07 - Network Security Monitor: Ogrenme Notlari (edu.md)

Durum: proje tamamlandi. Bu dosya projeyi sifirdan anlamak icin yazildi; once kavramlar, sonra kutuphaneler, sonra dosya dosya kod, en sonda karsilasilan hatalar ve sorular.

## 1. Ag paketi nedir

Ag uzerindeki veri katmanli paketler halinde ilerler. Her katman bir baslik (header) ekler:
- Ethernet (katman 2): hedef MAC, kaynak MAC, ust katman turu (ethertype, ornek 0x0800 = IPv4). Arada VLAN etiketi (802.1Q) olabilir, 4 bayt ekler.
- IP (katman 3): kaynak/hedef IP, protokol (TCP=6, UDP=17, ICMP=1), TTL. IPv4 basligi degisken uzunluktadir (IHL alani x 4 bayt). IPv6 basligi sabit 40 bayttir ama arkasina uzanti basliklari (extension header) zincirlenebilir.
- TCP/UDP (katman 4): portlar. TCP'de bayraklar (flags): SYN baglanti acar, ACK onaylar, FIN/RST kapatir.
- Uygulama: bu projede yalnizca DNS sorgusunun ilk sorusu okunur.

Ayristirma (parsing): bu basliklari bayt bayt okuyup alanlara cevirmek. Ag baytlari buyuk-once (big-endian, network byte order) gelir; `u16::from_be_bytes` bu yuzden kullanilir.

Ethernet dolgusu (padding): 60 bayttan kisa cerceveler sifirla doldurulur. Bu yuzden IPv4'un "toplam uzunluk" alani esas alinir, cercevenin sonu degil.

## 2. Akis (flow)

Bir akis, ayni 5 degeri (kaynak IP, hedef IP, kaynak port, hedef port, protokol) paylasan paketlerdir. Bu projede akis cift yonludur: A->B ve B->A ayni kayittir. Bunu saglamak icin anahtar "kanonik" yapilir: iki uc nokta siralanir, kucuk olan `a`, buyuk olan `b` olur; paketin yonu ayrica tutulur (`Direction::AtoB` / `BtoA`).

LRU (Least Recently Used): tablo dolunca en uzun suredir dokunulmayan akis atilir. Boylece bellek sinirli kalir (100.000 akis ~ 22 MB).

## 3. Paket yakalama

- libpcap (Linux) / Npcap (Windows): ag kartindan ham cerceveyi uygulamaya veren kutuphaneler.
- Promiscuous mod: kartin kendine gelmeyen cerceveleri de almasi. Yetki ister.
- Snaplen: paketten en fazla kac bayt alinacagi. `caplen` (yakalanan) ile `len` (teldeki gercek boy) farkli olabilir.
- pcap dosyasi: 24 baytlik genel baslik (magic, surum, snaplen, link turu) + her kayit icin 16 baytlik baslik (saniye, mikro/nanosaniye, caplen, len) + veri. Magic degeri bayt sirasini ve zaman hassasiyetini soyler.
- Link turu (DLT): 1 = Ethernet, 0 = BSD loopback (Npcap loopback adaptoru bunu verir), 101 = ham IP.

## 4. Diller arasi entegrasyon kavramlari

- ABI (Application Binary Interface): derlenmis kodlarin birbirini bellek seviyesinde nasil cagirdigi (cagri kurali, struct yerlesimi). C-ABI dillerin ortak dilidir.
- FFI (Foreign Function Interface): bir dilden baska dildeki fonksiyonu cagirmak.
- `extern "C"` + `#[no_mangle]` (Rust): fonksiyon adini bozmadan C cagri kuraliyla disari acar. `#[repr(C)]`: struct alanlarini C'deki gibi sirali ve hizali dizer.
- Opak isaretci (opaque pointer): C tarafinin icini bilmedigi `NcCore*`. Olusturan (`core_create`) ve yok eden (`core_destroy`) ayni taraftir.
- P/Invoke (C#): yonetilen koddan yerel DLL cagirmak. Bu projede eski `DllImport` yerine `LibraryImport` kullanildi: cagri kodu derleme aninda uretilir (source generator), calisma aninda yansima (reflection) gerekmez, AOT ile uyumludur.
- Marshalling: verinin iki dunya arasinda donusturulmesi. Tum structlar "blittable" (yani bellekte iki tarafta ayni) tasarlandi, bu yuzden kopyalama disinda donusum yok.
- `SafeHandle` (C#): yerel kaynagi sarar; `Dispose` unutulsa bile sonlandirici `ReleaseHandle`'i cagirir. Ayrica cagri surerken handle'in serbest birakilmasini referans sayimiyla engeller.
- Panik ve FFI: Rust paniki C sinirini gecerse tanimsiz davranistir. Her disa acik fonksiyon `catch_unwind` icinde calisir ve paniği `NC_STATUS_PANIC` koduna cevirir.
- gRPC: protobuf ile tanimlanan, HTTP/2 uzerinde calisan uzaktan cagri. Bu projede iki yonlu akis (bidirectional streaming) kullanildi: Rust surekli batch yollar, Python surekli skor yollar.

## 5. Kullanilan kutuphane ve araclar (ve neden)

C
- Npcap `wpcap.dll` / libpcap `libpcap.so`: calisma aninda `LoadLibraryExA` / `dlopen` ile yuklenir. Neden: SDK kurmadan derlenir, Npcap yoksa program cokmez, anlasilir `SNIFFER_ERR_NO_LIBRARY` doner. Gerekli tipler (`np_pkthdr`, `np_if`) elle tanimlandi.
- Windows thread API (`CreateThread`, `Interlocked*`) ve POSIX (`pthread`, `__atomic`): yakalama thread'i ve durdurma bayragi.

Rust
- `lru`: akis tablosu ve kural durumu icin hazir LRU; kendi bagli listemizi yazmaktan daha guvenli.
- `serde` + `serde_yaml`: kural dosyasi. `deny_unknown_fields` sayesinde yazim hatasi olan alan sessizce yok sayilmaz, hata verir. Not: `serde_yaml` artik gelistirilmiyor ama kararli ve yaygin; ileride `serde_norway` gibi bir catala gecilebilir.
- `cc`: C sniffer'i Rust build sirasinda MSVC/gcc ile derleyip DLL'e gomer.
- `cbindgen`: Rust tiplerinden `contracts/core_ffi.h` uretir. Baslik elle yazilmadigi icin Rust ile C/C# uyumsuzlugu olusmaz; CI farki yakalar.
- `tonic` + `prost` + `tonic-prost-build`: gRPC istemcisi ve protobuf kod uretimi. `protoc-bin-vendored`: protoc derleyicisini crate icinde getirir, ayrica kurulum gerekmez.
- `tokio`: tonic'in ihtiyac duydugu async calisma zamani; tek thread'li (`current_thread`) kullanildi, cunku tek bir baglanti var.
- `proptest`: rastgele ve bozulmus paketlerle ayristiricinin asla panik yapmadigini test eder (fuzz benzeri).

C#
- Avalonia 11.3: capraz platform masaustu arayuz (Windows/Linux/macOS). Avalonia 12 cikmis olsa da LiveCharts kararli surumu 11 ile uyumlu oldugu icin 11 secildi.
- `CommunityToolkit.Mvvm`: `[ObservableProperty]` ve `[RelayCommand]` ile MVVM kalip kodunu uretir. .NET 10 / C# 14 ile "partial property" bicimi kullanildi.
- `LiveChartsCore.SkiaSharpView.Avalonia`: canli cizgi ve pasta grafik.
- `Microsoft.Extensions.TimeProvider.Testing`: `FakeTimeProvider` ile hiz hesabini gercek beklemeden test etmek icin.

Python
- `grpcio` / `grpcio-tools`: sunucu ve kod uretimi.
- `numpy`: ozellik matrisi. `scikit-learn`: `IsolationForest`.
- `pytest`, `ruff` (lint), `mypy --strict` (tip denetimi).

## 6. Anomali tespiti

- Kural tabanli: bilinen kalip ("10 saniyede 100 farkli porta SYN"). Kesin, aciklanabilir, ama sadece tanimlananı yakalar.
- Kayan pencere (sliding window): son N saniyedeki olaylari tutan kuyruk; eski olaylar bastan atilir. `DistinctWindow` farkli degerleri (port, host) sayac haritasiyla sayar, boylece her pakette O(1) calisir.
- Shannon entropisi: bir metindeki karakter dagiliminin "rastgeleligi". `github` ~2.3 bit, rastgele base32 ~4.6 bit. DNS tunelleri veriyi uzun rastgele etiketlere gomdugu icin entropileri yuksektir.
- Isolation Forest: veriyi rastgele bolen agaclar kurar; aykiri noktalar daha az bolmeyle yalniz kalir, skorlari yuksektir.
- Dayanikli z-skoru (robust z-score): `(x - medyan) / (1.4826 * MAD)`. Ortalama ve standart sapma yerine medyan ve MAD kullanildigi icin egitim verisinde az sayida saldiri olsa bile istatistik bozulmaz.
- Bu projede ML karari iki kosula baglidir: IF skoru egitim skorlarinin %99'unun ustunde VE en az bir ozellikte z >= 6. Biri tek basina yanlis alarm uretebilir, ikisi birlikte cok zor.

## 7. Kod incelemesi

### contracts/
- `core_ffi.h`: cbindgen ciktisi, elle duzenlenmez. C duman testi ve C# struct tanimlari buna gore yazildi.
- `analytics.proto`: `Analytics.Analyze(stream FlowBatch) returns (stream AnomalyScore)` ve `Health`. Rust ve Python kodu bundan uretilir.
- Surumleme: `core_abi_version()` 1 doner; C# acilista kontrol eder, uyusmazsa `NetCoreException` atar. Struct degisirse surum artirilir ve boyut testleri guncellenir.

### sniffer-c/
- `include/sniffer.h`: disa acik API. Tek not: callback'e gelen `data` yalnizca cagri suresince gecerlidir.
- `src/sniffer_internal.h`: ic struct, pcap tiplerinin elle tanimi (`np_pkthdr` vb.), platform farklari (`sniffer_flag`, `sniffer_thread`).
- `src/sniffer.c`: acma/kapama, durum makinesi (IDLE -> RUNNING -> FINISHED), `sniffer_start/stop` (thread), `sniffer_poll_finished` (replay bitti mi), hata metni. Acma hatasinda `goto fail` ile tek noktadan temizlik.
- `src/capture_loop.c`: canli yakalama dongusu (`pcap_next_ex`, 100 ms timeout) ve platform yardimcilari: thread, uyku, monotonik saat, atomik bayrak.
- `src/pcap_replay.c`: pcap dosyasini kendi okuyucusuyla oynatir (Npcap gerekmez). Gercek zamanli modda "hedef duvar saati" yontemiyle hiz ayarlar.
- `src/win_npcap.c` / `src/posix_pcap.c`: kutuphaneyi yukleyip fonksiyon isaretcilerini doldurur (`GetProcAddress` / `dlsym`). Isaretci `memcpy` ile atanir, cunku `void*` -> fonksiyon isaretcisi donusumu ISO C'de tanimsizdir.
- `src/device.c`: `pcap_findalldevs` ile arayuz listesi.
- `tools/sniff.c`: `sniff list | live | replay` deneme araci.
- `tests/`: `check.h` kucuk bir test makrosu; `test_replay.c` 63, `test_device.c` 21 kontrol.

### core-rs/core (netcore-engine)
- `packet/*.rs`: her katman icin `parse(&[u8]) -> Result<(Header, &[u8]), ParseError>`. Donen dilim bir sonraki katmanin girdisidir; hicbir yerde kopya yok (sifir kopya). `need()` her okumadan once uzunluk kontrolu yapar, bu yuzden bozuk paket panik degil hata olur.
- `packet/dns.rs`: sikistirma isaretcileri (0xC0) takip edilir, en fazla 16 atlama; sonsuz dongu saldirisina karsi.
- `flow.rs`: `FlowKey::canonical`, `FlowTable` (LRU + bosta kalma suresi + `top_by_bytes` icin N boyutlu min-heap).
- `engine.rs`: `Engine::process` tek giris noktasi: sayaclar, akis, kurallar. Saat paket zaman damgasindan ilerler.
- `rules/loader.rs`: YAML semasi ve dogrulama. `rules/window.rs`: kayan pencereler. `rules/engine.rs`: kural turlerinin degerlendirmesi, kaynak basina durum ve bekleme suresi (cooldown).
- `pcap.rs`: okuyucu/yazici; 256 KB'den buyuk kaydi reddeder (bellek tuketme saldirisi).
- `synth.rs`: deterministik sentetik trafik (xorshift RNG). Testlerin, demolarin ve olcumlerin kaynagi.

### core-rs/core-ffi (netcore.dll)
- `types.rs`: `#[repr(C)]` structlar ve `NcStatus` kodlari.
- `sniffer.rs`: C sniffer'in Rust sarmalayicisi; `Drop` icinde `sniffer_close`.
- `core.rs`: `NcCore` ve `Shared`. C thread'inden gelen callback `Shared`'a ham isaretci ile ulasir; bu yuzden `NcCore::drop` once analitigi ve yakalamayi durdurur, sonra `Shared` serbest kalir.
- `analytics.rs`: saniyede bir akislari toplayip yollayan exporter thread; akis yonunu yuksek porta gore cevirir; skorlari uyariya donusturur ve host basina 15 s bekleme uygular.
- `lib.rs`: `extern "C"` fonksiyonlar; `guarded()` yardimcisi null kontrolu, `catch_unwind` ve hata metnini tek yerde toplar.
- `build.rs`: C kodunu derler, basligi uretir; icerik degismediyse dosyaya yazmaz.

### core-rs/core-grpc
- `link.rs`: `AnalyticsLink`. Kendi thread'inde tokio calistirir. Baglan -> akis -> koparsa bekle (0.5 s, 1 s, 2 s ... 30 s). Bagli degilken gelen batch'ler sayilip atilir.

### core-rs/cli
- `netmon gen` ve `netmon replay`; arguman ayristirma elle ve test edilmis (`args.rs`).

### ui-cs/
- `NetMonitor.Interop/NativeMethods.cs`: `LibraryImport` tanimlari, `Cdecl` acikca yazili.
- `CoreHandle.cs`: `SafeHandle`; `ReleaseHandle` -> `core_destroy`.
- `Structs.cs`: Rust structlarinin birebir karsiligi; `fixed byte` diziler.
- `Mapping.cs`: ham struct -> C# kaydi (`IPAddress`, `DateTimeOffset`, UTF-8 metin).
- `NetCoreSession.cs`: kullanici dostu API; negatif donus kodunu `NetCoreException`'a cevirir.
- `StatsPoller.cs`: `PeriodicTimer` ile 250 ms'de bir anlik goruntu; hiz hesabi (`RateCalculator`).
- `NetMonitor.App`: `MainViewModel` (kaynaklar, KPI, grafikler, yakalama durumu, kural dosyasi izleme), `AlertsViewModel` (en fazla 500 uyari), XAML gorunumleri.

### analytics-py/
- `features.py`: akislari istemci host basina 8 ozellige toplar; gecersiz akislari sayip atar.
- `model.py`: `AnomalyModel`; isinma (warmup), arka planda egitim, skorlama. Isaretlenen hostlar egitime eklenmez.
- `server.py`: gRPC servisi; `send_initial_metadata` ile header'i hemen yollar.
- `config.py`: ayarlar ve dogrulama. `scripts/gen_proto.py`: stub uretimi. `scripts/bench_model.py`: olcum.

### Olcum sonuclari ve yorumu
- Rust ayristirma 3.55 M paket/s; 4 kural ile 2.39 M paket/s. Kurallar ~%33 maliyet getiriyor, cogu `LruCache` ve `HashMap` erisimi.
- C replay 2.86 M paket/s; darbogaz dosya okuma (`fread`) ve callback.
- 100.000 akis 22 MB: akis basina ~200 bayt (anahtar + istatistik + LRU dugumu).
- C# arayuz 165-176 MB; buyuk kismi .NET calisma zamani, Skia ve fontlar. 40 saniyede artis yok.
- Python 314.000 akis/s ama 231 MB; numpy ve scikit-learn'un sabit maliyeti.
- netcore.dll 1.9 MB; tokio + tonic eklenmeden once 186 KB idi. Ag yigini kolay degil.

## 8. Karsilasilan hatalar ve cozumleri

1. Isim cakismasi: DLL'in adi `netcore` olsun istendi ama cekirdek kutuphane de `netcore` idi. Cozum: cekirdek paket `netcore-engine` olarak yeniden adlandirildi.
2. cbindgen, C sniffer'a ait ic bildirimleri de basliga yazdi. Cozum: `cbindgen.toml` icinde `exclude` listesi.
3. MSVC'de bos derleme birimi uyarisi (C4206): Windows'ta `posix_pcap.c` bos kaliyordu. Cozum: her platform yalnizca kendi yukleyicisini derliyor.
4. Gercek zamanli replay yavasti (~160 paket/s): Windows `Sleep(1)` aslinda ~15 ms uyuyor. Cozum: monotonik saatle "hedef zaman" hesabi, 2 ms'den az ondeyse hic uyuma.
5. Ekran goruntusu betigi baska bir pencereyi yakaladi: Windows arka plandaki bir uygulamanin one gecmesini engelliyor. Cozum: `PrintWindow` ile yalnizca hedef pencerenin icerigi cizdirildi.
6. `std::sync::mpsc::Receiver` `Sync` degil, `Arc` icinde paylasilamadi. Cozum: `Mutex` arkasina alindi.
7. gRPC deadlock: tonic istemcisi sunucunun cevap header'ini bekliyor, Python sunucusu header'i ilk cevapla yolluyor, istemci de beklerken batch yollamiyordu. Sonuc: "bagli ama 0 batch". Cozum: header beklenirken de batch iletimi (`tokio::select!`), Python'da `send_initial_metadata`. Hatayi tekrar ureten bir test (`Lazy` sunucu) eklendi.
8. Test sunucusu kapanirken takildi: nazik kapatma acik akislari bekliyordu. Cozum: runtime dusurulerek sert kapatma; bu Python'un cokmesini de daha gercekci taklit ediyor.
9. Isolation Forest esigi fazla yuksekti: agac derinligi sinirli oldugu icin asiri aykiri noktalar bile ~0.65'te doyuyordu. Cozum: esik payi kaldirildi, karar IF + dayanikli z ikilisine birakildi.
10. Python bellek olcumu 4 MB cikti: venv `python.exe` aslinda bir baslaticidir, asil yorumlayici alt surectir. Cozum: tepe bellek surecin kendi icinden okundu; `ctypes`'ta `HANDLE` donus tipi acikca tanimlanmazsa 64 bit tutamac kirpiliyordu.

## 9. Ogrendiklerim

- Sinir tasarimi kodun kendisinden once gelir: sahiplik (kim ayirdi, kim birakir), hata tasima ve struct yerlesimi en bastan kararlastirilmali.
- Bir sozlesme elle iki yerde yazilirsa bir gun ayrisir; uretilmis baslik + boyut testleri bunu imkansiz hale getirir.
- Zaman bilgisinin paketten gelmesi testleri deterministik yapar; duvar saati sadece arayuz ve hiz ayari icin kullanilmali.
- Asenkron protokollerde "kim once konusur" sorusu deadlock'larin en sinsi kaynagi.
- Olcmeden soylenen performans iddiasi yanlis cikabilir (README'deki tahminlerin cogu gercekte daha iyi, bellek ise daha kotu cikti).

## 10. Kendine sorular

1. `core_last_error` neden Rust'in `String`'ini dondurmek yerine cagiranin tamponuna kopyaliyor?
2. `NcFlow` icindeki `reserved` alani kaldirilsa C# tarafinda ne bozulur?
3. Python'u neden ayri surec ve gRPC ile, Rust'i ise ayni surecte P/Invoke ile bagladik?
4. Callback'teki `data` isaretcisini saklayip sonra okusaydik ne olurdu?
5. Port tarama kurali tek bir kaynaktan gelen dagitik taramayi (cok kaynak, az port) yakalar mi? Hangi kural tipi yakalar?
6. `RuleEngine` durumu neden kaynak basina LRU ile sinirli? Sinirsiz olsa hangi saldiri bellegi bitirir?
7. Egitim verisinde saldiri varken model neden yine calisti? Ortalama/standart sapma kullansaydik ne olurdu?
8. Replay sirasinda saat geriye giderse exporter ne yapiyor, neden?
