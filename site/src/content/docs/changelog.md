---
title: Журнал изменений
description: Все влитые в Citrus pull request’ы по темам, со ссылками, и версии форков utls, tls и http.
---

Всё, что влито в ветку `dev` с начала проекта (196 pull request’ов), по темам. Внутри темы — по номеру PR. Ссылки ведут на PR в [getmikan/Citrus](https://github.com/getmikan/Citrus/pulls?q=is%3Apr+is%3Amerged); там описано, что было не так, что поменялось и как проверяли.

Первый бета-релиз [`v1.0.0-beta.1`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.1) собран из `dev` до [#112](https://github.com/getmikan/Citrus/pull/112). Второй, [`v1.0.0-beta.2`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.2), — из `dev` до [#133](https://github.com/getmikan/Citrus/pull/133). Изменения для третьей беты с #149 собраны в первом разделе ниже.

Что из этого меняет поведение для существующих конфигов, собрано на странице [Переход с mihomo](/Citrus/migration/).

## После v1.0.0-beta.3 (ещё не выпущено)

- [#199](https://github.com/getmikan/Citrus/pull/199) Форк getmikan/utls пересобран на metacubex/utls `v1.9.0-alpha.1` (её требует mihomo v1.19.34): база crypto/tls из Go 1.26, исправление транспортных параметров `UQUICConn`, сжатие ALPN в ECH только для стандартных ClientHello. Изменения форка перенесены (Chrome 155, пост-квантовый REALITY, склейка TLS-записей, исправления TLS и ECH); Firefox 148, Safari 26.3 и перепроверка цепочки при возобновлении сессии теперь из upstream. Отпечатки не изменились: ClientHello всех `client-fingerprint` сверены со старым форком, `chrome` — по-прежнему Chrome 155.
- [#200](https://github.com/getmikan/Citrus/pull/200) QUIC-входящие с диапазоном портов (`port: 20000-40000`) — hysteria2, tuic, shadowquic и HTTP/3 у trusttunnel — держат один QUIC-сервер на весь диапазон, а не по серверу на порт: сокеты портов сведены в один, ответ уходит с порта, на который клиент писал последним. Port hopping клиента hysteria2 больше не рвёт соединение на первом прыжке. Простаивающий порт стоит сокет и одну горутину вместо пяти: на 1000 портах 1005 горутин вместо 5000 и 5–8 МиБ памяти вместо 100–140 МиБ. Входящий с одним портом не изменился; hysteria2 с `realm` держит сервер на порт, как раньше.

## v1.0.0-beta.3 (ещё не выпущена)

Что влито в `dev` с [#149](https://github.com/getmikan/Citrus/pull/149) и войдёт в третью бету. #130 и #134–#148 влиты после тега `v1.0.0-beta.2` и тоже войдут в третью бету; они описаны в тематических разделах ниже.

### Outbound desync

- [#163](https://github.com/getmikan/Citrus/pull/163) Outbound `type: desync`: прямое соединение, у которого первый TLS ClientHello уходит преобразованным библиотекой [desync](https://github.com/Nemu-x/desync) (`tlsrec`, `split`, `split-delay`, на Windows ещё `fake` и UDP-burst). Глобальный DIRECT не меняется; правила и группы выбирают его как DIRECT, fallback и url-test с VPN-нодой в резерве переключаются, когда desync не проходит. Обёртку не обходят fast path relay, на ней действует egress guard, в `/proxies` — тип `Desync` и объект `desync`. См. [Desync](/Citrus/start/desync/).
- [#172](https://github.com/getmikan/Citrus/pull/172) desync v0.1.0: `split-wait`, `disorder`, `oob`, `random`; у `fake` — `auto-ttl`, свои SNI, рандомизация и смещение; у `udp` — шаблон QUIC и `quic-only`. Fake теперь и на Linux/Android и вместе со split, UDP-burst — на Windows, Linux и macOS. Каждый метод сверяется с возможностями ОС, неподдерживаемый — ошибка конфига с причиной; в `/proxies` — последний TTL fake.
- [#180](https://github.com/getmikan/Citrus/pull/180) Android: `fake`, `disorder` и `split-wait: sent`, которые библиотека проверяет на каждом соединении (SELinux не даёт читать неотправленные байты сокета), больше не отклоняются при загрузке конфига. desync обновлён до коммита `main`, который станет v0.2.1.

### Fallbacks и страница-заглушка

- [#153](https://github.com/getmikan/Citrus/pull/153) `fallback-page` для VLESS и Trojan на HTTP-транспортах (WebSocket, gRPC, XHTTP): на чужие запросы к `/` отдаётся HTML-страница вместо голого 404.
- [#159](https://github.com/getmikan/Citrus/pull/159) `fallbacks` для VLESS и Trojan на обычном TCP, как в Xray: чужой поток после TLS уходит в `dest` (порт, `host:port` или unix-сокет, `xver` для PROXY protocol), выбор по SNI, ALPN и пути. Порт 443 можно делить с сайтом, конфиги Xray с fallbacks переносятся. См. [Fallbacks](/Citrus/start/fallbacks/).

### XHTTP поверх HTTP/3

- [#160](https://github.com/getmikan/Citrus/pull/160) VLESS-входящий с `xhttp-config` принимает `alpn`, как `tlsSettings.alpn` в Xray: `[h3]` — XHTTP по QUIC только на UDP, `h3` вместе с `h2`/`http/1.1` — UDP на том же порту, что TCP. Все режимы XHTTP работают по h3, у каждого стрима срок на заголовок; конфиги, которые не могут работать (REALITY, unix-сокет, `proxy-protocol` с h3 и другие), отклоняются.

### Egress guard

- [#162](https://github.com/getmikan/Citrus/pull/162) `egress-guard` (по умолчанию включён): пользователи серверных входящих через DIRECT не достают частные и локальные сети, адреса самого хоста и metadata облаков. Проверяются резолвнутые адреса прямо перед connect, так что DNS rebinding и IP4P его не обходят; UDP-датаграммы на заблокированные адреса отбрасываются. `allow-ips` открывает отдельные адреса или порты, у listener'а свой `egress-guard`. Клиентские входящие не проверяются. На сервере, где пользователи ходили в LAN или на localhost хоста, нужен `allow-ips` или `egress-guard.enable: false`. См. [Сервер без root](/Citrus/start/server-profile/).

### Корневые сертификаты

- [#161](https://github.com/getmikan/Citrus/pull/161) Бандл Mozilla лежит в репозитории (`make ca-bundle` сверяет SHA-256 от curl), а не копируется из раннера при сборке. `tls.ca-roots: both | bundle | system` (по умолчанию `both`, как раньше) и `tls.ca-denylist` (по умолчанию включён): цепочки через Russian Trusted Root/Sub CA и казахстанские перехватывающие корни отклоняются. Пул сертификатов собирается до прокси, так что `ca-roots` и `custom-certifactes` доходят до них и при первом запуске, и при reload; sudoku wss, XDrive и DoH-проба H3 тоже проверяют через него.

### Лимиты

- [#151](https://github.com/getmikan/Citrus/pull/151) Лимиты: `speed-group` — общая скорость для нескольких пользователей на любых входящих; смена скорости без сброса «корзины»; `SetLimits` для многих лимитов за раз и `SetOnLeave` для трафика по адресам назначения у встраивающего приложения.
- [#152](https://github.com/getmikan/Citrus/pull/152) Документация лимитов: `speed-group` в лимите по умолчанию (`user: "*"`) объединяет в одну скорость всех пользователей входящего без своего лимита.
- [#189](https://github.com/getmikan/Citrus/pull/189) Доступ после окончания подписки: вместо полного отключения пользователь получает только Telegram, оплату и страницу подписки с малыми скоростью и квотой, всё на ноде. Собирается из `IN-USER`, лимита без `expire-at` и rule-provider; тест всего сценария и инструкция, см. [Доступ после окончания подписки](/Citrus/start/grace-access/). `IN-USER` со списком имён теперь ищет по множеству, а не перебором.

### Укрепление сервера

- [#155](https://github.com/getmikan/Citrus/pull/155) Исправления по полному сканированию серверной части: транспорт и авторизация контроллера, точная маршрутизация DoH, проверка собеседника SSH, OpenVPN и Realm, SSRF через редиректы, подписанные Ed25519 манифесты самообновления с ротацией ключей, сроком действия и защитой от отката, пины SHA-256 для GEO, установка UI через `os.Root`, бюджеты rule-провайдеров, изоляция NTP, скрытие секретов в argv и адресах провайдеров.
- [#156](https://github.com/getmikan/Citrus/pull/156) Пин `geox-sha256` необязателен: без него удалённые GeoIP/GeoSite/MMDB/ASN снова загружаются (после #155 ядро с конфигом по умолчанию не загружало GeoSite), с ним база с другим хешем отклоняется. `geodata-allow-unsigned` убран.
- [#187](https://github.com/getmikan/Citrus/pull/187) Одно соединение sing-mux (smux, yamux, h2mux) держит не больше 1024 подпотоков, TCP и UDP вместе; меняется через `mux-option: { max-streams: N }`. Лишний подпоток закрывается, соединение и остальные подпотоки работают. Подпоток без заголовка запроса через 20 с закрывается и освобождает место. Ошибки sing-mux о подпотоках, не дошедших до обработчика, теперь пишутся на уровне debug, а не error.

### Второй аудит ядра

- [#166](https://github.com/getmikan/Citrus/pull/166) `common/`: handshake-listener REALITY, ShadowTLS, JLS и restls больше не гаснет навсегда при нехватке сокетов (EMFILE, ENOBUFS), временные ошибки Accept повторяются с back-off; то же для listener'а PROXY protocol; пароли сравниваются за постоянное время; исправлено переполнение `ReadAllLimit`.
- [#167](https://github.com/getmikan/Citrus/pull/167) DNS: `LookupIP4P` больше не падает с panic на части IPv4 и не переписывает адреса Teredo; ошибки DHCP не кешируются на час; OPT от upstream не уходит клиенту, который его не просил; гонка в fake-ip; неаутентифицированный ответ DNSCrypt отбрасывается.
- [#168](https://github.com/getmikan/Citrus/pull/168) `adapter/`: режимы XDrive `local` и `template` отклоняются для прокси из подписок (через них можно было слать запросы на localhost и в LAN и писать в любой путь на диске); ssh и openvpn без политики идентичности в подписке пропускаются, а не валят её; WireGuard не теряет устройства за smux при reload.
- [#169](https://github.com/getmikan/Citrus/pull/169) `listener/`: неудачный reload больше не оставляет входящий закрытым после отката; при ошибке конструктора закрывается всё уже открытое; accept-циклы всех входящих с общим back-off вместо 100% CPU; keep-alive и сравнение токена за постоянное время в Hysteria2 Realm; SOCKS5 UDP учитывает пользователей входящего.
- [#170](https://github.com/getmikan/Citrus/pull/170) TUN: `auto-redirect` без `auto-route` — ошибка конфига, а не nil-panic; детектор петель ловит петли system/mixed-стека после подмены адреса сниффером; ограничено число relay DNS hijack; неудачный CAS не обнуляет `routing-mark`; стек, у которого не прошёл Start, закрывается.
- [#171](https://github.com/getmikan/Citrus/pull/171) Транспорты: AnyTLS не теряет бюджет приёма при локальном close (сессия замерзала); ShadowQUIC не зависает на Close; MASQUE не теряет request stream при отказе CONNECT; `Close` kcptun закрывает сессии; счётчик потоков TUIC не уходит в минус; CPU-бюджет пробы Sudoku; OpenVPN не держит 64 КиБ на каждую датаграмму.
- [#176](https://github.com/getmikan/Citrus/pull/176) Mux.Cool: срок одного стрима не рвёт всю сессию, пустая сессия закрывается через 16 с, как в Xray, write watchdog на 30 с; XHTTP отбрасывает upload-пакеты с уже прочитанным seq; 0-RTT ticket VLESS Encryption не теряется на read deadline и Close; ShadowTLS v3 ретранслирует ClientHello без SNI на handshake-сервер.
- [#177](https://github.com/getmikan/Citrus/pull/177) Правила и туннель: битый MRS DomainSet больше не роняет ядро, panic парсера провайдера становится ошибкой загрузки; хост назначения приводится к нижнему регистру без корневой точки, так что `DOMAIN,youtube.com` срабатывает и на `YouTube.COM.`; `match()` не держит блокировку конфига во время резолва; процесс UDP-сессии ищется один раз.
- [#178](https://github.com/getmikan/Citrus/pull/178) Самообновление: атомарная замена ядра с откатом, работа на ARM32 и loong64, правильный ассет для 386 softfloat; обновление MMDB без munmap под живыми lookup; GEO-апдейтер переживает неудачу, старый UI остаётся до полной копии нового; контроллер перезапускает свой listener после неудачного reload, `/storage` отказывает на ключ, который не может сохранить, restart и upgrade отклоняются при конфиге из stdin; цель redirect сохраняет имя хоста.

### Исправления и зависимости

- [#157](https://github.com/getmikan/Citrus/pull/157) Windows: TUN с `auto-route` замечает Forwarding и WeakHostSend на исходящем адаптере (их включают ICS и мобильный хотспот, и тогда сокеты ядра уходят в собственный TUN). Ядро только пишет предупреждение и шлёт событие `tun.forwarding` в `/events`, настройки адаптера не меняет.
- [#183](https://github.com/getmikan/Citrus/pull/183) Egress guard проверяет IPv6-адрес без зоны (`адрес%x` его обходил); ShadowTLS с `wildcard-sni` проверяет SNI и у авторизованного клиента (через него можно было дойти до localhost и частных хостов на 443); с `egress-guard` на listener'е UDP-сессия Trojan или Mieru больше не переходит к другому пользователю; предупреждение в логе о пользователе с пустым паролем. Обновлены `x/net`, brotli и `x/crypto` (закрыты находки govulncheck), на сайте — undici и zod (предупреждения Dependabot).
- [#188](https://github.com/getmikan/Citrus/pull/188) Гонка в обновлении провайдеров: `hash` и `updatedAt` читаются и пишутся под одной блокировкой, когда обновление через API идёт одновременно с периодическим.
- [#192](https://github.com/getmikan/Citrus/pull/192) GC-балласт выделяется только в сборках для Linux: десктопные клиенты на Windows и macOS не получают поток новых соединений, ради которого он нужен, а лишний мусор между циклами GC до 8 МБ им ни к чему.
- [#194](https://github.com/getmikan/Citrus/pull/194) `client-fingerprint: chrome` (и пустой отпечаток REALITY) теперь Chrome 155, как в Xray 26.11.9: GREASE и ML-DSA в `signature_algorithms`, расширение trust anchors (0xca34). Профиль перенесён в форк utls из refraction-networking/utls и сверен со снимком Chrome 155.0.8059.40. Новые имена `chrome155` и `hellochrome_155`, прежний профиль — `chrome133` (`hellochrome_133`).

### Синхронизация с mihomo

- [#182](https://github.com/getmikan/Citrus/pull/182) Синхронизация с mihomo Alpha: Snell v6 (входящий и исходящий), `dns-mode` для TUN и исправление auto-route, генератор паролей Shadowsocks, закрытие простаивающих соединений mieru, переписанный транспорт Sudoku с перенесёнными на него лимитами Citrus. Исправления: переполнение длины домена в SOCKS, байты после ответа на HTTP CONNECT, ssh, easytier, tfo-go на Go 1.26.9+. Не взяты многопользовательский входящий Shadowsocks с картой `users` (в Citrus `users` — список для SS2022 с учётом и лимитами) и изменения ссылок VMess. Что изменено после ревью: режим Snell v6 `mode: unsafe-raw` отклоняется — он не использует PSK, то есть нет ни аутентификации, ни шифрования, и входящий в этом режиме становится открытым прокси; на Linux без `auto-route` пустой `dns-mode` означает `native`, и systemd-resolved, как и раньше, отправляет DNS в туннель. Учтите: TUN с `auto-route` и префиксом без адреса для DNS (например, только `/32` без IPv6) теперь не запускается, раньше он запускался без DNS.
- [#197](https://github.com/getmikan/Citrus/pull/197) Синхронизация с mihomo v1.19.34: `DecryptBytes` в age пропускает пустой секретный ключ, поэтому провайдер без своего `age-secret-key` расшифровывается глобальными ключами; обновлён easytier-go. Переход mihomo на utls `v1.9.0-alpha.1` не действует: Citrus по-прежнему собирается с форком getmikan/utls (Chrome 155).

### Тесты, CI и документация

- [#149](https://github.com/getmikan/Citrus/pull/149) Журнал изменений дополнен #130–#138, дорожная карта после работы над второй бетой.
- [#150](https://github.com/getmikan/Citrus/pull/150) Отдельная Linux CI-проверка полного inbound-набора с race detector, включая конкурентные подтесты в одном процессе. Логи сохраняются как артефакты; раздельные проверки протоколов сохранены.
- [#154](https://github.com/getmikan/Citrus/pull/154) Число PR в журнале изменений после #150 и #152.
- [#158](https://github.com/getmikan/Citrus/pull/158) Interop с sing-box v1.14.4 в CI: клиент sing-box против сервера Citrus (VLESS, REALITY, Trojan, SS2022, Hysteria2, TUIC v5, AnyTLS) и клиент Citrus против сервера sing-box. Попутно детектор петель перестал отклонять легитимные соединения прокси-входящих.
- [#164](https://github.com/getmikan/Citrus/pull/164) Стенд: Xray закреплён на v26.10.21 (релиз v26.10.17 удалён), baseline памяти пересчитан на новом образе раннера.
- [#165](https://github.com/getmikan/Citrus/pull/165) Тест DNSCrypt берёт случайные пары портов (зарезервированные диапазоны на Windows).
- [#173](https://github.com/getmikan/Citrus/pull/173) Тест XHTTP ждёт `onClose` после срока чтения.
- [#174](https://github.com/getmikan/Citrus/pull/174) Тесты fallback TrustTunnel задают пользователей до `Start`.
- [#175](https://github.com/getmikan/Citrus/pull/175) H3-тесты входящих отличают зарезервированные порты Windows от занятых.
- [#179](https://github.com/getmikan/Citrus/pull/179) `TestInboundUserStats` сразу сообщает об ошибке передачи, а не о расхождении счётчиков.
- [#184](https://github.com/getmikan/Citrus/pull/184) Скрипт синхронизации с mihomo находит выровненные gofmt константы брендинга и не выдаёт ложное предупреждение.
- [#181](https://github.com/getmikan/Citrus/pull/181) Дорожная карта: синхронизация с mihomo, лимит sing-mux и доступ после окончания подписки — сделано.
- [#185](https://github.com/getmikan/Citrus/pull/185) Журнал изменений третьей беты.
- [#186](https://github.com/getmikan/Citrus/pull/186) Флейки inbound-тестов: тест UDP-пользователя SOCKS переотправляет первый датаграм, тесты XHTTP H3 берут порт, свободный и для TCP, и для UDP (на Windows порты резервируются блоками).
- [#190](https://github.com/getmikan/Citrus/pull/190) Тесты UDP-ассоциации SOCKS берут случайный порт ниже эфемерного диапазона (на Windows порты резервируются блоками).
- [#193](https://github.com/getmikan/Citrus/pull/193) Совместимость с Xray перенесена на v26.11.9: interop-проверка идёт против этой версии (её отпечаток `chrome` по умолчанию теперь Chrome 155), клиент REALITY по умолчанию сообщает `26.11.9` вместо `26.10.10`.
- [#196](https://github.com/getmikan/Citrus/pull/196) Под `-race` конкурентный подтест Sudoku пропускается: race-рантайм задерживает старт горутин почти на 2 с и упирается в 2-секундный таймаут первых SETTINGS HTTP/2, без `-race` подтест проходит.

## Инфраструктура, CI и документация

- [#2](https://github.com/getmikan/Citrus/pull/2) Ветка `dev` синхронизирована с `main`.
- [#3](https://github.com/getmikan/Citrus/pull/3) Проверки безопасности в CI (gofmt, vet, `go mod tidy`, govulncheck, CodeQL, dependency review) и CONTRIBUTING.md.
- [#4](https://github.com/getmikan/Citrus/pull/4) Сайт Citrus на GitHub Pages с новостями.
- [#12](https://github.com/getmikan/Citrus/pull/12) Лёгкий CI для PR (около 8 задач), полная сборка только на `main` и тегах.
- [#13](https://github.com/getmikan/Citrus/pull/13) Новость о пост-квантовом REALITY, XHTTP и удалённых протоколах.
- [#24](https://github.com/getmikan/Citrus/pull/24) Еженедельная синхронизация с веткой Alpha mihomo (workflow, пока выключен в настройках).
- [#25](https://github.com/getmikan/Citrus/pull/25) Интеграционные тесты против Xray-core (REALITY PQ, XHTTP, ECH) и задача в CI.
- [#51](https://github.com/getmikan/Citrus/pull/51) Нагрузочный стенд и первые замеры производительности.
- [#74](https://github.com/getmikan/Citrus/pull/74) Интеграционные тесты: клиенты mihomo v1.19.31 и v1.19.32 против сервера Citrus.
- [#98](https://github.com/getmikan/Citrus/pull/98) Страницы сайта: дорожная карта, журнал изменений, совместимость, переход с mihomo и безопасность; обновлённая главная.
- [#99](https://github.com/getmikan/Citrus/pull/99) CI: PR только с сайтом и документацией не запускают проверки Go, сайт собирается на PR с изменениями сайта.
- [#101](https://github.com/getmikan/Citrus/pull/101) Сравнение серверов Xray-core, mihomo и Citrus: пропускная способность, CPU на гигабайт, новые соединения.
- [#108](https://github.com/getmikan/Citrus/pull/108) Журнал изменений дополнен до бета-релиза v1.0.0-beta.1.
- [#110](https://github.com/getmikan/Citrus/pull/110) Go 1.26: обновлены `x/net`, `x/crypto`, `x/text`, `x/sys` (закрыты уязвимости HTTP/2 и другие), убраны отдельные сборки `-go120…-go125`; Windows 7/8 и старый macOS держит пропатченный тулчейн MetaCubeX, Linux нужен с ядром 3.2+.
- [#112](https://github.com/getmikan/Citrus/pull/112) Журнал изменений дополнен: #108, #110 и #111.
- [#114](https://github.com/getmikan/Citrus/pull/114) CI: закреплённый тулчейн Go для тестов, сборки PR и стенда.
- [#120](https://github.com/getmikan/Citrus/pull/120) LF для `*.sh` и Dockerfile; разбор отчётов `-race` в `listener/inbound`.
- [#121](https://github.com/getmikan/Citrus/pull/121) CI: задача `-race` для 30 пакетов без гонок.
- [#126](https://github.com/getmikan/Citrus/pull/126) Сравнение четырёх серверов: Xray, sing-box, mihomo и Citrus, восемь протоколов.
- [#127](https://github.com/getmikan/Citrus/pull/127) Стенд: стабильный замер загрузки REALITY с TLS внутри туннеля; ночная проверка производительности в CI против mihomo.
- [#144](https://github.com/getmikan/Citrus/pull/144) Отдельные серверные профили без root: пользователь systemd с конфигом только для чтения и ограниченными capabilities, Docker-образ с UID 65532. CI запускает реальный unit и проверяет проксирование в Docker без capabilities.
- [#132](https://github.com/getmikan/Citrus/pull/132) Журнал изменений дополнен до второй беты v1.0.0-beta.2.
- [#134](https://github.com/getmikan/Citrus/pull/134) Новость о второй бете, дорожная карта после неё.
- [#135](https://github.com/getmikan/Citrus/pull/135) Зависимости тестов и сайта: клиент Docker в тестах переведён на `moby/moby`, обновлён `postcss-selector-parser` — закрыты предупреждения Dependabot.

## Удалённое наследие

- [#7](https://github.com/getmikan/Citrus/pull/7) Удалены SSR, Hysteria v1, TUIC v4, потоковые шифры Shadowsocks и v2ray-plugin.
- [#38](https://github.com/getmikan/Citrus/pull/38) Общий транспорт TLS/WS/H2 вынесен из `transport/vmess` в `transport/v2ray`.
- [#39](https://github.com/getmikan/Citrus/pull/39) Удалены VMess, mKCP, mekya и TLSMirror.

## Xray и пост-квантовая криптография

- [#8](https://github.com/getmikan/Citrus/pull/8) Пост-квантовый клиент REALITY для Xray 26.9.8+: ML-KEM по умолчанию, ML-DSA-65, `client-version`.
- [#9](https://github.com/getmikan/Citrus/pull/9) XHTTP: быстрый packet-up через CDN, паддинг, query в пути и умолчания xmux как у Xray.
- [#10](https://github.com/getmikan/Citrus/pull/10) Пост-квантовый сервер REALITY и отпечатки Firefox 148 и Safari 26.3 (getmikan/utls).
- [#19](https://github.com/getmikan/Citrus/pull/19) ECH: ключи `echServerKeys` Xray в `ech-key`, `ech-opts.query-server` и формы `ech=` в ссылках.
- [#20](https://github.com/getmikan/Citrus/pull/20) Сервер XHTTP принимает packet-up любым методом и с любым размещением данных, как Xray; `server-max-header-bytes`.
- [#21](https://github.com/getmikan/Citrus/pull/21) HTTP/2-входящие шлют такой же первый кадр SETTINGS, как Caddy (getmikan/http).
- [#34](https://github.com/getmikan/Citrus/pull/34) XHTTP: XMUX по умолчанию как в Xray при пустом `reuse-settings`, исправления менеджера переиспользования.
- [#139](https://github.com/getmikan/Citrus/pull/139) XDrive для клиентов и серверов VLESS: локальное хранилище, Google Drive и шаблоны API, VLESS Encryption, Mux.Cool и XUDP; тесты совместимости с Xray и проверки гонок в CI.

## Возможности для VPN-сервиса

- [#1](https://github.com/getmikan/Citrus/pull/1) TrustTunnel: `fallback` на сайт для запросов без верных учётных данных (из Kinkan).
- [#5](https://github.com/getmikan/Citrus/pull/5) События отклонённой авторизации на входящих (`authevent`, из Kinkan).
- [#36](https://github.com/getmikan/Citrus/pull/36) TrustTunnel: визиты на сайт-заглушку не попадают в события авторизации.
- [#41](https://github.com/getmikan/Citrus/pull/41) Shadowsocks 2022 с несколькими пользователями (EIH) и учётом каждого.
- [#42](https://github.com/getmikan/Citrus/pull/42) Трафик и онлайн-IP по пользователям в ядре, REST и Go API.
- [#43](https://github.com/getmikan/Citrus/pull/43) Пользователи входящих меняются на лету: REST `/inbounds/{name}/users`, перезагрузка без пересоздания листенера.
- [#44](https://github.com/getmikan/Citrus/pull/44) Лимиты пользователей в ядре: скорость, соединения, адреса, квота, срок.
- [#47](https://github.com/getmikan/Citrus/pull/47) Prometheus `/metrics` и пробы `/healthz`, `/readyz`.
- [#63](https://github.com/getmikan/Citrus/pull/63) DNSCrypt v2 для штампов `sdns://`.
- [#64](https://github.com/getmikan/Citrus/pull/64) `PUT /rules`: замена правил во время работы.
- [#68](https://github.com/getmikan/Citrus/pull/68) TCP-листенеры на unix-сокете.
- [#70](https://github.com/getmikan/Citrus/pull/70) `GET /events`: поток событий ядра.
- [#71](https://github.com/getmikan/Citrus/pull/71) TrustTunnel: таймеры HTTP/2-сессии на каждом прокси.
- [#73](https://github.com/getmikan/Citrus/pull/73) Группы `type: chain` для каскадов с проверкой, которая называет сломавшийся хоп.
- [#136](https://github.com/getmikan/Citrus/pull/136) PROXY protocol v1 и v2 на TCP-входящих (`proxy-protocol`, `proxy-protocol-trusted`): адрес клиента из заголовка фронтенда, например SNI-роутера на 443.
- [#146](https://github.com/getmikan/Citrus/pull/146) User-Agent по умолчанию `clash.meta/<версия> citrus/<версия>`: панели по-прежнему узнают mihomo по началу строки, Citrus отличается по токену `citrus/`.
- [#147](https://github.com/getmikan/Citrus/pull/147) Контроллер `GET /version` возвращает `core: "citrus"`, сохраняя прежние поля `meta` и `version` для панелей.

## Производительность

- [#30](https://github.com/getmikan/Citrus/pull/30) Snell v4: буферизованное чтение, примерно в 90 раз меньше системных вызовов.
- [#52](https://github.com/getmikan/Citrus/pull/52) Простаивающие соединения не держат буфер 32 КБ: минус 30 КБ кучи на соединение.
- [#53](https://github.com/getmikan/Citrus/pull/53) XHTTP: вдвое меньше CPU на гигабайт при загрузке по h2 (getmikan/http).
- [#118](https://github.com/getmikan/Citrus/pull/118) Новые соединения: меньше циклов GC и аллокаций на соединение (GC-балласт только в серверной сборке).
- [#119](https://github.com/getmikan/Citrus/pull/119) Загрузка: пакетная запись с чтением наперёд, до +50% на REALITY, Trojan и SS2022, CPU на гигабайт −34%.
- [#124](https://github.com/getmikan/Citrus/pull/124) Скачивание: чтение по 64 КиБ, TLS-записи уходят в сокет вместе (getmikan/tls, getmikan/utls): в 32 потока +40–50%, пинг под нагрузкой −25–30%.
- [#125](https://github.com/getmikan/Citrus/pull/125) Hysteria2 и TUIC: меньше работы на поток, буфер чтения создаётся только при необходимости, без горутины ожидания первых байтов для DIRECT.
- [#129](https://github.com/getmikan/Citrus/pull/129) Память простаивающего туннеля: Trojan −36%, AnyTLS −18%, REALITY −12% (getmikan/tls: буфер чтения по размеру данных, `WaitRead`).
- [#131](https://github.com/getmikan/Citrus/pull/131) Пинг под нагрузкой: цикл пересылки уступает процессор после 256 КиБ и 1 мс; эхо рядом с восемью закачками 55–63 → 20 мс.
- [#130](https://github.com/getmikan/Citrus/pull/130) AnyTLS: принятые кадры в очереди потока, кадры для отправки собираются на месте; в 32 потока скачивание вдвое быстрее, загрузка +23%, CPU на гигабайт почти вдвое меньше; гонка в клиенте устранена.

## Укрепление ядра

- [#14](https://github.com/getmikan/Citrus/pull/14) Контроллер: unix-сокет и канал только для владельца, secret на каждом листенере, `/debug` за авторизацией.
- [#15](https://github.com/getmikan/Citrus/pull/15) TLS 1.2 минимум, проверка сертификата маскировки Hysteria2, файлы только для владельца, скрытые учётные данные DoH.
- [#16](https://github.com/getmikan/Citrus/pull/16) Ограничения на загрузки, распаковку архивов, ответы DoH и бинарные форматы правил и geodata.
- [#17](https://github.com/getmikan/Citrus/pull/17) ShadowTLS: без перехода на частные и локальные адреса для неавторизованных клиентов.
- [#18](https://github.com/getmikan/Citrus/pull/18) SOCKS5 UDP только для авторизованного UDP ASSOCIATE и разрешённых источников.
- [#22](https://github.com/getmikan/Citrus/pull/22) `tcp-concurrent`: ограниченный параллельный набор и отмена проигравших попыток.
- [#23](https://github.com/getmikan/Citrus/pull/23) DIRECT подключается к адресу, который проверили IP-правила.
- [#26](https://github.com/getmikan/Citrus/pull/26) Ограничено состояние до авторизации: тикеты VLESS 0-RTT, сессии XHTTP без данных.
- [#37](https://github.com/getmikan/Citrus/pull/37) Срок рукопожатия до авторизации: VLESS, Trojan, AnyTLS, HTTP-транспорты.
- [#55](https://github.com/getmikan/Citrus/pull/55) getmikan/utls v1.8.8-citrus.2: исправления ошибок TLS-библиотеки.
- [#56](https://github.com/getmikan/Citrus/pull/56) Пакет исправлений после ревью кода: mmdb, проверка сертификатов в ссылках, лимиты obfs и Sudoku, сроки листенеров, таймауты regexp.
- [#58](https://github.com/getmikan/Citrus/pull/58) Исправления безопасности TLS из Go 1.26 (ECH CVE-2026-97031, KeyUpdate) через getmikan/tls и getmikan/utls.

## Исправления по аудиту

- [#75](https://github.com/getmikan/Citrus/pull/75) CI: actions и образы закреплены по digest, токены с минимальными правами.
- [#76](https://github.com/getmikan/Citrus/pull/76) Ограничены объявленные длины кадров (gun, MASQUE h2, UDP TrustTunnel, дополнения VLESS).
- [#77](https://github.com/getmikan/Citrus/pull/77) Самообновление сверяет пакет с `checksums.txt` и игнорирует имена внутри архива.
- [#78](https://github.com/getmikan/Citrus/pull/78) Пути с учётом симлинков, атомарная запись ресурсов, без редиректов в частные сети.
- [#79](https://github.com/getmikan/Citrus/pull/79) Контроллер: secret на сетевых адресах, защита от браузера, применение настроек при перезагрузке.
- [#80](https://github.com/getmikan/Citrus/pull/80) Перезагрузка без `force` применяет политику доступа входящих.
- [#81](https://github.com/getmikan/Citrus/pull/81) Sudoku: ограничены кэш повторов, мультиплексированные потоки и выгрузки http-mask.
- [#82](https://github.com/getmikan/Citrus/pull/82) Учётные данные и файлы ядра вне досягаемости API.
- [#83](https://github.com/getmikan/Citrus/pull/83) Провайдеры: ограничены `override-expr`, размер провайдера и вложенность логики; атомарная замена rule-set.
- [#84](https://github.com/getmikan/Citrus/pull/84) Snell и Shadowsocks: срок рукопожатия до авторизации.
- [#85](https://github.com/getmikan/Citrus/pull/85) HTTP-прокси авторизует каждый запрос на keep-alive соединении.
- [#86](https://github.com/getmikan/Citrus/pull/86) Отзыв сессий глобальной авторизации при перезагрузке; пустые имена запрещены.
- [#87](https://github.com/getmikan/Citrus/pull/87) SSH: предупреждение и явный отказ от проверки ключа хоста; проверки сервера OpenVPN.
- [#88](https://github.com/getmikan/Citrus/pull/88) SOCKS5: UDP-ассоциации привязаны к пользователю и порту.
- [#89](https://github.com/getmikan/Citrus/pull/89) Ограничены скачки часов по NTP; кэш DNS учитывает подсеть клиента.
- [#90](https://github.com/getmikan/Citrus/pull/90) AnyTLS и Trojan: ограничено число потоков в одной mux-сессии.
- [#91](https://github.com/getmikan/Citrus/pull/91) QUIC: ограничены потоки TUIC, ShadowQUIC и TrustTunnel; бюджет TUIC до авторизации.
- [#92](https://github.com/getmikan/Citrus/pull/92) QUIC: ограничены сборка фрагментов TUIC и непривязанные ассоциации ShadowQUIC.
- [#93](https://github.com/getmikan/Citrus/pull/93) UDP-сессии разделены по входящему и пользователю.
- [#94](https://github.com/getmikan/Citrus/pull/94) Ключи и учётные данные не попадают в логи; `age decrypt` пишет файл с правами 0600.
- [#95](https://github.com/getmikan/Citrus/pull/95) Snell: пользователь, проверенный ShadowTLS или JLS, важнее ID клиента.
- [#96](https://github.com/getmikan/Citrus/pull/96) Hysteria2 Realm: заголовок с IP только от `trusted-proxies`; токены сессий не попадают в логи.
- [#97](https://github.com/getmikan/Citrus/pull/97) XHTTP: сессия остаётся в лимитах до авторизации, пока VLESS её не проверит.
- [#102](https://github.com/getmikan/Citrus/pull/102) Snell: ID клиента больше не становится пользователем; без ShadowTLS или JLS у входящего нет пользователя.
- [#103](https://github.com/getmikan/Citrus/pull/103) DNS-листенер: ограничено число запросов в работе, у каждого свой срок.
- [#104](https://github.com/getmikan/Citrus/pull/104) Hysteria2 Realm: один поток событий на сессию, `Close` закрывает активные соединения.
- [#105](https://github.com/getmikan/Citrus/pull/105) Провайдеры: адрес health-check в отладочных логах без пароля и значений query.
- [#107](https://github.com/getmikan/Citrus/pull/107) CI: закреплены оставшиеся actions и fpm, тулчейны Go проверяются по SHA-256.
- [#111](https://github.com/getmikan/Citrus/pull/111) AnyTLS: версия собеседника из настроек сессии разбирается с проверкой границ, значение `-1` больше не включает режим v2 (найдено CodeQL).
- [#113](https://github.com/getmikan/Citrus/pull/113) AnyTLS: ограничены схема паддинга и разбор чисел; обновлены `compress` и `dhcp`.
- [#140](https://github.com/getmikan/Citrus/pull/140) Ограничены replay-cache VLESS и общий бюджет загрузок Sudoku HTTP-mask; запись Sudoku порциями по 64 КиБ; неверный ML-DSA seed не попадает в ошибки.
- [#141](https://github.com/getmikan/Citrus/pull/141) Обновлены форки uTLS и ResTLS во всех трёх модулях: дедлайны REALITY до классификации, точный порог fallback limiter, отсутствие AuthKey/short ID в логах, кэш X25519/буферов, callbacks проверки JLS и атомарные счётчики ResTLS.
- [#142](https://github.com/getmikan/Citrus/pull/142) Ограничены незавершённые handshake REALITY/ShadowTLS/JLS/ResTLS, записи ShadowTLS, Sudoku fallback и сессии/потоки KCPTun; серверный QUIC 0-RTT для TUIC/TrustTunnel включается явно. Добавлены регрессионные и раздельные inbound race-тесты; ограничения совместимости описаны без заявления о закрытии Sudoku key-auth.
- [#143](https://github.com/getmikan/Citrus/pull/143) WebSocket контроллера использует одноразовые билеты с привязкой к запросу (30 секунд, ограниченное хранилище); основной secret в URL разрешается только явной опцией совместимости. Добавлены инструкции для панелей и hub в race-проверку.
- [#145](https://github.com/getmikan/Citrus/pull/145) Инструкции контроллера и событий переведены на одноразовые WS-билеты; для серверного профиля без root описано обновление через пакет или замену образа.
- [#148](https://github.com/getmikan/Citrus/pull/148) Обновлён ResTLS во всех трёх модулях: устранён panic debug-вызова при возобновлении QUIC/TLS; форк теперь проверяет полный TLS/ResTLS-набор на Go 1.20/1.24/1.26, Windows и под race detector.

## Перенесено из mihomo и сообщества

- [#27](https://github.com/getmikan/Citrus/pull/27) WireGuard: одно устройство на ключ при перезагрузках, устройства удалённых прокси закрываются.
- [#28](https://github.com/getmikan/Citrus/pull/28) Без повторов набора при нехватке ресурсов (портов, дескрипторов, буферов).
- [#29](https://github.com/getmikan/Citrus/pull/29) Настраиваемый `tcp-connect-timeout`.
- [#31](https://github.com/getmikan/Citrus/pull/31) DNS: настройки `serve-expired` (по умолчанию поведение прежнее).
- [#32](https://github.com/getmikan/Citrus/pull/32) `trusted-proxy-header` для VLESS и Trojan, только от `trusted-proxies`.
- [#33](https://github.com/getmikan/Citrus/pull/33) Сниффер BitTorrent (TCP, uTP, DHT, трекер) и правило `PROTOCOL`.
- [#60](https://github.com/getmikan/Citrus/pull/60) Hosts: ограничены цепочки доменных отображений, резолвер ядра их учитывает.
- [#61](https://github.com/getmikan/Citrus/pull/61) url-test сохраняет текущий узел при обновлении провайдера.
- [#62](https://github.com/getmikan/Citrus/pull/62) Мелкие переносы: `Close` у TUIC, `disable-mtu-discovery`, лимит памяти, домен из сниффера в логах.
- [#65](https://github.com/getmikan/Citrus/pull/65) Мелкие переносы 2: JSON-логи, `sniffer.skip-threshold`, fake IP для экранированных имён, `tls-version-min` в OpenVPN.
- [#66](https://github.com/getmikan/Citrus/pull/66) Tailscale: `dialer-proxy` работает, и UDP не идёт в обход него.
- [#117](https://github.com/getmikan/Citrus/pull/117) Синхронизация с mihomo от 17 октября 2026.

## Исправления ошибок и тестов

- [#11](https://github.com/getmikan/Citrus/pull/11) Гонки данных в Vision и AnyTLS.
- [#35](https://github.com/getmikan/Citrus/pull/35) Интеграционные тесты ждут готовности Citrus перед отправкой трафика.
- [#40](https://github.com/getmikan/Citrus/pull/40) Тесты TrustTunnel: нестабильная привязка TCP+UDP к одному порту на Windows.
- [#45](https://github.com/getmikan/Citrus/pull/45) Нестабильный тест `TestBindRace`.
- [#46](https://github.com/getmikan/Citrus/pull/46) Статистика: учёт переданных байт, запись которых вернула ошибку (недосчёт в h2mux).
- [#48](https://github.com/getmikan/Citrus/pull/48) Нестабильный `TestInboundRuntimeUsersConcurrent` (детектор петель, TIME_WAIT).
- [#49](https://github.com/getmikan/Citrus/pull/49) Детектор петель DIRECT сравнивает соединение целиком, а не порт источника.
- [#50](https://github.com/getmikan/Citrus/pull/50) Гонки данных в клиентской сессии AnyTLS.
- [#54](https://github.com/getmikan/Citrus/pull/54) Клиент TrustTunnel: ограничено число соединений, мёртвые HTTP/2-сессии закрываются.
- [#57](https://github.com/getmikan/Citrus/pull/57) Предупреждение о порче стека UDP на Windows в Go 1.26.0 и 1.26.1.
- [#59](https://github.com/getmikan/Citrus/pull/59) Нестабильный `TestTrackerSpeedLimit`.
- [#67](https://github.com/getmikan/Citrus/pull/67) Тесты SOCKS: нестабильные порты UDP на Windows.
- [#69](https://github.com/getmikan/Citrus/pull/69) Сервер TrustTunnel закрывает сессии исчезнувших клиентов.
- [#72](https://github.com/getmikan/Citrus/pull/72) XHTTP: истёкший срок не закрывает простаивающее соединение; ранний срок пользователя; гонки в тестах.
- [#100](https://github.com/getmikan/Citrus/pull/100) Нестабильные тесты лимита mux в Trojan, бюджета TUIC до авторизации и загрузки TrustTunnel.
- [#106](https://github.com/getmikan/Citrus/pull/106) Тест скрытия ссылки VLESS пропускает посторонние строки лога.
- [#115](https://github.com/getmikan/Citrus/pull/115) Нестабильные тесты: interop AnyTLS с mihomo и зависшая загрузка TrustTunnel.
- [#116](https://github.com/getmikan/Citrus/pull/116) Лимиты: запоздалое закрытие пользователя сверх квоты не трогает его новые соединения.
- [#122](https://github.com/getmikan/Citrus/pull/122) Тест UDP SOCKS с пользователем берёт свободный TCP-порт (Windows).
- [#123](https://github.com/getmikan/Citrus/pull/123) smux заменён форком getmikan/smux: после возврата `Write` буфер вызывающего больше не читается (его данные могли уйти в чужое соединение).
- [#125](https://github.com/getmikan/Citrus/pull/125) TUIC: `CONNECT` с доменом длиной 255 байт больше не роняет сервер до авторизации.
- [#137](https://github.com/getmikan/Citrus/pull/137) PROXY protocol: строка v1 короче сигнатуры отклоняется сразу, без чтения данных клиента.
- [#138](https://github.com/getmikan/Citrus/pull/138) Тест UDP SOCKS с пользователем берёт порт, свободный и для TCP, и для UDP (Windows).

## Форки

Citrus подменяет пять библиотек mihomo своими форками через `replace` в `go.mod`. Пути модулей не меняются; изменения проходят PR и CI в `dev`, релизы выпускаются отдельно.

### [getmikan/utls](https://github.com/getmikan/utls)

- `v1.8.9-0.20261020173537-32502cba39f4`: исправления REALITY/JLS из [PR 3 форка](https://github.com/getmikan/utls/pull/3), подключены в [#141](https://github.com/getmikan/Citrus/pull/141); это коммит `dev`, не релизный тег.
- `v1.8.9-0.20261110224923-a6dee38a3c8d`: отпечаток Chrome 155 из [PR 4](https://github.com/getmikan/utls/pull/4) и [PR 5](https://github.com/getmikan/utls/pull/5) форка, подключён в [#194](https://github.com/getmikan/Citrus/pull/194); коммит `dev`.
- `v0.0.0-20261111095853-b60cfbd40b44`: форк на metacubex/utls `v1.9.0-alpha.1` из [PR 6](https://github.com/getmikan/utls/pull/6) форка, подключён в [#199](https://github.com/getmikan/Citrus/pull/199); коммит ветки `dev-1.9`.

- `v1.8.8-citrus.1`: серверная сторона пост-квантового REALITY (подпись ML-DSA-65, требование X25519MLKEM768), отпечатки Firefox 148 и Safari 26.3 ([#10](https://github.com/getmikan/Citrus/pull/10)).
- `v1.8.8-citrus.2`: исправления ошибок после ревью кода: возобновление сессий, ECH, минимальная версия сервера, сжатые сертификаты, HKDF ([#55](https://github.com/getmikan/Citrus/pull/55)).
- `v1.8.8-citrus.3`: исправления безопасности из Go 1.26: проверка ссылок на внешние расширения ECH (CVE-2026-97031) и KeyUpdate ([#58](https://github.com/getmikan/Citrus/pull/58)).
- После `v1.8.8-citrus.3`, коммиты `dev`: записи TLS одной операции записи уходят в сокет вместе ([#124](https://github.com/getmikan/Citrus/pull/124)).

### [getmikan/tls](https://github.com/getmikan/tls)

- `v0.1.8-citrus.1`: то же исправление ECH (CVE-2026-97031) для TLS-входящих ([#58](https://github.com/getmikan/Citrus/pull/58)).
- После `v0.1.8-citrus.1`, коммиты `dev`: записи TLS одной операции записи уходят в сокет вместе ([#124](https://github.com/getmikan/Citrus/pull/124)), буфер чтения по размеру данных и `Conn.WaitRead` ([#129](https://github.com/getmikan/Citrus/pull/129)).

### [getmikan/http](https://github.com/getmikan/http)

- `v0.1.8-citrus.1`: первый кадр SETTINGS HTTP/2 как у Caddy ([#21](https://github.com/getmikan/Citrus/pull/21)).
- `v0.1.8-citrus.2`: буфер записи HTTP/2 64 КиБ и пакетная отправка WINDOW_UPDATE ([#53](https://github.com/getmikan/Citrus/pull/53)).

### [getmikan/smux](https://github.com/getmikan/smux)

- Коммит `dev`: `Write` не возвращается, пока цикл отправки может читать буфер вызывающего; брошенный кадр не отправляется ([#123](https://github.com/getmikan/Citrus/pull/123)).

### [getmikan/restls-client-go](https://github.com/getmikan/restls-client-go)

- `v0.1.10-0.20261020174520-8a87bfbeac8c`: атомарные счётчики двусторонней передачи и уведомление о переходе в fallback из [PR 1 форка](https://github.com/getmikan/restls-client-go/pull/1), подключены в [#141](https://github.com/getmikan/Citrus/pull/141). CI форка проверяет протокол ResTLS; старые сбои общего набора TLS-тестов не считаются исправленными.
- `v0.1.10-0.20261020200739-f74a25fc969b`: исправление panic при QUIC/TLS resumption и восстановление полного TLS/ResTLS-набора из [PR 2 форка](https://github.com/getmikan/restls-client-go/pull/2), подключены в [#148](https://github.com/getmikan/Citrus/pull/148). Прежние сбои общего набора устранены; тесты для зелёного результата не отключаются.
