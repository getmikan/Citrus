---
title: Журнал изменений
description: Все влитые в Citrus pull request’ы по темам, со ссылками, и версии форков utls, tls и http.
---

Всё, что влито в ветку `dev` с начала проекта (146 pull request’ов), по темам. Внутри темы — по номеру PR. Ссылки ведут на PR в [getmikan/Citrus](https://github.com/getmikan/Citrus/pulls?q=is%3Apr+is%3Amerged); там описано, что было не так, что поменялось и как проверяли.

Первый бета-релиз [`v1.0.0-beta.1`](https://github.com/getmikan/Citrus/releases/tag/v1.0.0-beta.1) собран из `dev` до [#112](https://github.com/getmikan/Citrus/pull/112). Второй, `v1.0.0-beta.2`, — из `dev` в том состоянии, что описано на этой странице.

Что из этого меняет поведение для существующих конфигов, собрано на странице [Переход с mihomo](/Citrus/migration/).

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
- [#150](https://github.com/getmikan/Citrus/pull/150) Добавлена отдельная Linux CI-проверка полного inbound-набора с race detector, включая конкурентные подтесты в одном процессе. Логи сохраняются как артефакты; раздельные проверки протоколов сохранены.

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
- [#151](https://github.com/getmikan/Citrus/pull/151) Лимиты: `speed-group` — общая скорость для нескольких пользователей на любых входящих; смена скорости без сброса «корзины»; `SetLimits` для многих лимитов за раз и `SetOnLeave` для трафика по адресам назначения у встраивающего приложения.

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
