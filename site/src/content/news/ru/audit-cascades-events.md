---
title: Аудит закрыт, каскады, события, unix-сокеты и DNSCrypt
description: Итоги недели в dev — исправления по аудиту, группы-цепочки, поток событий /events, листенеры на unix-сокете, DNSCrypt и проверка с клиентами mihomo.
date: 2026-10-15
---

Всё ниже влито в ветку `dev` и пока не вышло в релиз. Попробовать можно, [собрав ядро из исходников](/Citrus/start/getting-started/#собрать-из-исходников). Полный список — в [журнале изменений](/Citrus/changelog/).

## Аудит закрыт

Статический аудит ядра разобран: найденное исправлено серией PR с [#75](https://github.com/getmikan/Citrus/pull/75) по [#97](https://github.com/getmikan/Citrus/pull/97), у каждого исправления есть тест, который падает на старом коде. Главное, что заметят пользователи:

- контроллер на сетевом адресе требует `secret`, а без secret на loopback отклоняет запросы браузера с чужих сайтов;
- HTTP-прокси авторизует каждый запрос, UDP через SOCKS5 привязан к пользователю и порту, смена пароля закрывает сессии;
- самообновление сверяет пакет с `checksums.txt` релиза;
- публичный URL провайдера не может перенаправить в частную сеть, пути проверяются с учётом симлинков;
- состояние, которое клиент создаёт до авторизации, ограничено во всех протоколах;
- GitHub Actions и образы закреплены по хешам.

Часть изменений требует правок в конфиге: они собраны на новой странице [Переход с mihomo](/Citrus/migration/). Как сообщить об уязвимости и что сделано для защиты — на странице [Безопасность](/Citrus/security/).

## Каскады ([#73](https://github.com/getmikan/Citrus/pull/73))

Новая группа `type: chain` собирает цепочку из прокси и групп: первый хоп — вход, последний — выход.

```yaml
proxy-groups:
  - name: exits
    type: url-test
    proxies: [exit-de, exit-nl]
    url: https://cp.cloudflare.com/generate_204
  - name: cascade
    type: chain
    proxies: [entry, exits]   # entry → лучший выход
    url: https://cp.cloudflare.com/generate_204
    interval: 300
```

Если цепочка не работает, проверка находит первый сломанный хоп и показывает его в `/proxies`, в `/metrics` и в событии `chain.health`. Подробнее — на странице [Цепочки](/Citrus/start/chains/).

## Поток событий ([#70](https://github.com/getmikan/Citrus/pull/70))

`GET /events` отдаёт события ядра по WebSocket, SSE или NDJSON: авторизации, срабатывания лимитов, изменения пользователей, перезагрузки конфига, обновления провайдеров, состояние листенеров и цепочек. Панели больше не нужно опрашивать `/traffic/users` и `/limits/users`, чтобы узнать, что квота кончилась. См. [События](/Citrus/start/events/).

## Unix-сокеты ([#68](https://github.com/getmikan/Citrus/pull/68))

TCP-листенеры (VLESS, Trojan, TrustTunnel, HTTP, SOCKS и другие) слушают unix-сокет: `listen: unix:/run/citrus/vless.sock`. Так ноду удобно ставить за nginx или Caddy, а настоящий адрес клиента передаётся через `trusted-proxy-header` и `trusted-proxies: [loopback]`.

## DNSCrypt ([#63](https://github.com/getmikan/Citrus/pull/63))

Серверы DNSCrypt v2 задаются штампами `sdns://` в `nameserver`. Запросы идут через тот же диалер, что и у других DNS-клиентов, так что `#proxy` и правила работают, а под TUN нет утечек. Сторонних библиотек DNSCrypt не понадобилось.

## Клиенты mihomo ([#74](https://github.com/getmikan/Citrus/pull/74))

Новые интеграционные тесты запускают официальные релизы mihomo v1.19.31 и v1.19.32 как клиентов против сервера Citrus — так работают приложения пользователей Mikan. Все 31 случая проходят: REALITY с пост-квантовыми настройками, XHTTP, WebSocket, gRPC, Trojan, Shadowsocks 2022, Hysteria2, TUIC v5, AnyTLS, TrustTunnel, Snell, Mieru, Sudoku, HTTP и SOCKS. Несовместимостей не нашлось. Таблица — на странице [Совместимость](/Citrus/compatibility/).

## Ещё

- `PUT /rules` меняет правила без перезагрузки конфига ([#64](https://github.com/getmikan/Citrus/pull/64)).
- XHTTP по h2 тратит вдвое меньше CPU на гигабайт ([#53](https://github.com/getmikan/Citrus/pull/53)), а простаивающее соединение — на 30 КБ меньше памяти ([#52](https://github.com/getmikan/Citrus/pull/52)).
- JSON-логи для Loki и ELK: `log-format: json` ([#65](https://github.com/getmikan/Citrus/pull/65)).
- В форки getmikan/tls и getmikan/utls перенесены исправления безопасности TLS из Go 1.26 ([#58](https://github.com/getmikan/Citrus/pull/58)).

Что дальше — первый релиз и переход панели Mikan на Citrus — на странице [Дорожная карта](/Citrus/roadmap/).
