---
title: Пост-квантовый REALITY, быстрый XHTTP через CDN и чистка протоколов
description: В dev влиты пост-квантовый REALITY на клиенте и сервере, ускорение packet-up через CDN, удаление устаревших протоколов, хук отклонённой авторизации и исправление гонок.
date: 2026-10-12
---

Всё ниже уже влито в ветку `dev`, но ещё не вышло ни в релиз, ни в пререлиз. `dev` больше не собирается в `Prerelease-dev`: попробовать изменения сейчас можно, только [собрав ядро из исходников](/Citrus/start/getting-started/#собрать-из-исходников) ветки `dev`.

## Пост-квантовый REALITY ([#8](https://github.com/getmikan/Citrus/pull/8), [#10](https://github.com/getmikan/Citrus/pull/10))

Начиная с Xray 26.9.8 сервер REALITY молча отбрасывает ClientHello без key share X25519MLKEM768 перед X25519. Поэтому прежний Citrus не мог подключиться к актуальным серверам Xray.

**Клиент (`reality-opts`)**

- X25519MLKEM768 включён по умолчанию. `support-x25519mlkem768: false` возвращает классический hello для старых серверов. Отпечаткам без ML-KEM (ios, edge, randomized и другим) key share добавляется автоматически.
- `client-version`: версия Xray, которую клиент сообщает серверу. По умолчанию `26.10.10`, раньше было зашито `1.8.2`. Это нужно для серверов с `minClientVer`.
- `mldsa65-verify`: проверка подписи ML-DSA-65 во временном сертификате, аналог `mldsa65Verify` в Xray (параметр `pqv` в ссылках).
- `client-fingerprint: firefox` и `safari` теперь отдают настоящие hello Firefox 148 и Safari 26.3 из нашего форка [getmikan/utls](https://github.com/getmikan/utls). Принимаются и имена Xray: `hellofirefox_148`, `hellosafari_26_3`, `hellochrome_131`.

```yaml
proxies:
  - name: vless-reality-vision
    type: vless
    server: server
    port: 443
    uuid: uuid
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: www.microsoft.com
    client-fingerprint: chrome
    reality-opts:
      public-key: xxx
      short-id: xxx
      # support-x25519mlkem768: true  # по умолчанию; false только для старых серверов
      # client-version: 26.10.10      # по умолчанию
      # mldsa65-verify: xxx           # публичный ключ ML-DSA-65 (pqv)
```

**Сервер (`reality-config` у входящих)**

- `mldsa65-seed`: подпись временного сертификата ML-DSA-65, аналог `mldsa65Seed` в Xray. Цепочка сертификатов `dest` должна быть не короче примерно 3,5 КБ, иначе подпись не помещается и рукопожатие не проходит. У Xray то же ограничение.
- `require-x25519mlkem768`: принимать только клиентов с X25519MLKEM768, остальные уходят на `dest`.
- `min-client-ver` и `max-client-ver`: допустимый диапазон версий клиента.

```yaml
listeners:
  - name: vless-in
    type: vless
    port: 443
    users:
      - username: 1
        uuid: uuid
        flow: xtls-rprx-vision
    reality-config:
      dest: test.com:443
      private-key: xxx   # citrus generate reality-keypair
      short-id:
        - 0123456789abcdef
      server-names:
        - test.com
      # max-time-difference: 60000     # миллисекунды
      # mldsa65-seed: xxx              # xray mldsa65
      # require-x25519mlkem768: true
      # min-client-ver: 26.9.8
      # max-client-ver: 26.10.10
```

Проверено вживую против Xray 26.10.10 (VLESS + Vision + REALITY) в обе стороны: клиент Citrus к серверу Xray и клиент Xray к серверу Citrus, с подписью ML-DSA-65 и без неё. Неверный ключ отклоняется.

**Изменение поведения.** `max-time-difference` теперь в миллисекундах, как `maxTimeDiff` в Xray. Раньше значение читалось в микросекундах, и число, скопированное из конфига Xray, допускало расхождение часов в 1000 раз меньше. Если вы подбирали значение под старые единицы, разделите его на 1000.

Все ключи описаны в [справочнике конфига](https://github.com/getmikan/Citrus/blob/dev/docs/config.yaml).

## XHTTP через CDN ([#9](https://github.com/getmikan/Citrus/pull/9))

- В режиме `packet-up` следующий POST больше не ждёт ответа на предыдущий, как и в Xray. Через CDN каждый POST раньше стоил полный круг клиент → CDN → сервер, и отдача упиралась в задержку. В живом тесте против Xray 26.10.10 запрос через packet-up занял 0,4 с вместо 5,4 с. Через HTTP/1.1 ответы по-прежнему ждутся.
- `x-padding-bytes: "0-0"` теперь значит паддинг по умолчанию Xray (100–1000 байт), а не его отсутствие.
- `path` с запросом, например `/xh?ed=2048`, отправляется как путь и query, как в Xray, а не как экранированный `%3F` внутри пути.

## Удалены устаревшие протоколы ([#7](https://github.com/getmikan/Citrus/pull/7))

Удалены ShadowsocksR, Hysteria v1, TUIC v4, потоковые шифры Shadowsocks (rc4-md5, aes-ctr/cfb, chacha20 и другие) и v2ray-plugin. Shadowsocks принимает только `none`, AEAD и `2022-blake3-*`. VMess пока остаётся.

- В провайдерах прокси такой узел пропускается с предупреждением, остальная подписка загружается.
- В основном конфиге это ошибка с понятным текстом, например «TUIC v4 is no longer supported, use uuid/password (v5)».

## Журнал отклонённой авторизации ([#5](https://github.com/getmikan/Citrus/pull/5))

Пакет `component/authevent` сообщает о неудачных попытках входа на входящих TrustTunnel, REALITY, AnyTLS, VLESS, Trojan, TUIC v5, Hysteria2 и Sudoku: протокол, адреса и причину, без учётных данных. Это основа для журнала отклонённых запросов в панели. События идут через очередь и не замедляют рукопожатие.

## Гонки данных в Vision и AnyTLS ([#11](https://github.com/getmikan/Citrus/pull/11))

Исправлены гонки данных в фильтре и чтении XTLS Vision и в потоке AnyTLS, которые находил `go test -race`. Горячий путь Vision после первых пакетов стоит одну атомарную загрузку.
