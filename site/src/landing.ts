// Texts of the landing page, the header and the footer in both languages. Docs pages live
// in src/content/docs (Russian) and src/content/docs/en (English); news posts in
// src/content/news/<lang>.

export const links = {
	github: 'https://github.com/getmikan/Citrus',
	releases: 'https://github.com/getmikan/Citrus/releases',
	latest: 'https://github.com/getmikan/Citrus/releases/latest',
	prereleaseMain: 'https://github.com/getmikan/Citrus/releases/tag/Prerelease-main',
	prereleaseDev: 'https://github.com/getmikan/Citrus/releases/tag/Prerelease-dev',
	issues: 'https://github.com/getmikan/Citrus/issues',
	license: 'https://github.com/getmikan/Citrus/blob/main/LICENSE',
	config: 'https://github.com/getmikan/Citrus/blob/main/docs/config.yaml',
	mikan: 'https://miroshka000.github.io/mikan/',
	mikanRepo: 'https://github.com/Miroshka000/mikan',
	mihomo: 'https://github.com/MetaCubeX/mihomo',
};

export const runCommand = 'citrus -d ~/.config/citrus';

export type Lang = 'ru' | 'en';

const base = import.meta.env.BASE_URL.replace(/\/$/, '');
/** A page of this site in the given language: page('en', 'news/') → /Citrus/en/news/. */
export const page = (lang: Lang, path = '') => `${base}/${lang === 'en' ? 'en/' : ''}${path}`;

export const dateFormat = (lang: Lang, date: Date) =>
	date.toLocaleDateString(lang === 'en' ? 'en-GB' : 'ru-RU', { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });

export const strings = {
	ru: {
		hero: {
			title: 'Сетевое ядро Mikan',
			lead: 'Citrus — ядро VPN-сервиса Mikan, форк mihomo. Совместим с Xray, включая пост-квантовый REALITY, XHTTP и ECH; считает трафик, лимиты и события по каждому пользователю; строит каскады и отдаёт метрики. Конфиг тот же, что у mihomo. GPL-3.0.',
			note: 'Один бинарник для Linux, Windows, macOS, FreeBSD и Android.',
			primary: 'Начать',
			secondary: 'Скачать',
			art: 'Лайм, символ Citrus',
		},
		features: {
			title: 'Что умеет',
			items: [
				{
					title: 'Входящие',
					text: 'HTTP, HTTPS, SOCKS, mixed, redirect и TPROXY. Плюс серверные листенеры для VLESS, Trojan, Hysteria2, TUIC, AnyTLS и других.',
				},
				{
					title: 'Исходящие протоколы',
					text: 'VLESS с REALITY, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, TrustTunnel, Snell, WireGuard и другие.',
				},
				{
					title: 'TUN',
					text: 'Весь трафик системы через ядро, с настраиваемым сетевым стеком.',
				},
				{
					title: 'DNS',
					text: 'DNS over HTTPS, TLS и QUIC, fake IP и правила маршрутизации для DNS-запросов.',
				},
				{
					title: 'Правила',
					text: 'Маршрутизация по домену, диапазону IP, geodata, процессу и логическим комбинациям правил.',
				},
				{
					title: 'Провайдеры и группы',
					text: 'Удалённые провайдеры прокси и правил, проверки доступности, fallback и балансировка нагрузки.',
				},
				{
					title: 'API контроллера',
					text: 'HTTP и WebSocket API, совместимые с клиентами и дашбордами для mihomo, например MetaCubeXD.',
				},
			],
		},
		why: {
			title: 'Зачем отдельное ядро',
			lead: 'Mikan — VPN-сервис: на его нодах ядро работает сервером для многих пользователей сразу. mihomo писался как клиент, и многого, что нужно ноде, в нём нет. Citrus добавляет это в само ядро.',
			items: [
				{
					title: 'Совместимость с Xray',
					text: 'Пост-квантовый REALITY (X25519MLKEM768 и ML-DSA-65) на клиенте и сервере, XHTTP с поведением и значениями по умолчанию как у Xray, ключи и ссылки ECH в форматах Xray. Всё это проверяют автотесты против Xray v26.10.10.',
				},
				{
					title: 'Пользователи — часть ядра',
					text: 'Трафик и онлайн-адреса каждого пользователя, лимиты скорости, соединений, адресов, квоты и срока, смена пользователей входящих без перезапуска. Через REST, Go API и поток событий /events.',
				},
				{
					title: 'Укреплённый сервер',
					text: 'Ревью безопасности, ревью кода и статический аудит: контроллер без secret не слушает сеть, состояние до авторизации ограничено, каждый запрос проходит авторизацию, обновления сверяются с checksums.txt, CI закреплён по хешам.',
				},
				{
					title: 'Каскады',
					text: 'Группа type: chain собирает цепочку «вход → выход» из прокси и групп, а проверка здоровья называет хоп, который сломался.',
				},
				{
					title: 'Наблюдаемость',
					text: 'Prometheus /metrics, пробы /healthz и /readyz, события отклонённой авторизации и JSON-логи для Loki и ELK.',
				},
				{
					title: 'Ничего лишнего',
					text: 'VMess, SSR, Hysteria v1, TUIC v4, потоковые шифры Shadowsocks, v2ray-plugin и mKCP удалены: около 20 тысяч строк, которые сервису не нужны.',
				},
			],
		},
		compare: {
			title: 'Citrus и mihomo',
			lead: 'Формат конфига и API контроллера общие с mihomo, а клиенты на mihomo подключаются к серверу Citrus. В таблице только то, что уже влито в Citrus.',
			headers: ['', 'Citrus', 'mihomo'],
			rows: [
				['Пост-квантовый REALITY', 'X25519MLKEM768 по умолчанию, ML-DSA-65, на сервере require-x25519mlkem768 и mldsa65-seed', 'X25519MLKEM768 только по флагу, без ML-DSA-65'],
				['Статистика пользователей', 'Трафик и онлайн-IP по паре «входящий, пользователь», выборка с обнулением', 'Только общие счётчики'],
				['Лимиты пользователей', 'Скорость, соединения, адреса, квота, срок', 'Нет'],
				['Пользователи входящих', 'Меняются через REST, листенер не пересоздаётся', 'Только перезагрузкой конфига'],
				['События и метрики', '/events (WebSocket, SSE, NDJSON), /metrics, /healthz, /readyz', 'Нет'],
				['Каскады', 'Группа type: chain с проверкой каждого хопа', 'Только dialer-proxy'],
				['Контроллер на сетевом адресе', 'Только с secret', 'Запускается и без secret'],
				['Самообновление', 'Пакет сверяется с checksums.txt релиза', 'Без сверки'],
				['Устаревшие протоколы', 'Удалены', 'Есть'],
			],
			more: 'Подробнее о совместимости',
		},
		quick: {
			title: 'Документация',
			items: [
				{ title: 'Быстрый старт', text: 'Скачать, положить конфиг, запустить.', path: 'start/getting-started/' },
				{ title: 'Переход с mihomo', text: 'Что поменять в конфиге и к чему готовиться.', path: 'migration/' },
				{ title: 'Совместимость', text: 'Клиенты mihomo и Xray с сервером Citrus.', path: 'compatibility/' },
				{ title: 'Дорожная карта', text: 'Что сделано и что дальше.', path: 'roadmap/' },
				{ title: 'Изменения', text: 'Все влитые pull request’ы по темам.', path: 'changelog/' },
				{ title: 'Безопасность', text: 'Как сообщить об уязвимости.', path: 'security/' },
			],
		},
		download: {
			title: 'Скачать',
			lead: 'Готовые сборки лежат в релизах на GitHub. Файлы называются',
			naming: 'citrus-<os>-<arch>-<версия>',
			naming2: ': в релизе версия — это тег (citrus-linux-arm64-v1.2.3.gz), в пререлизе — ветка и коммит (citrus-linux-arm64-main-1a2b3c4.gz). Для Windows это .zip, для Linux есть ещё .deb, .rpm и .pkg.tar.zst.',
			headers: ['Канал', 'Откуда', 'Что это'],
			channels: [
				['release', 'Последний тег vX.Y.Z', 'Стабильные версии.'],
				['Prerelease-main', 'Ветка main', 'Сборка с каждого слияния в main.'],
			],
			arch: 'Файл amd64 собран под x86-64-v3 (Intel Haswell, AMD Excavator и новее); для старых берите amd64-compatible (v1) или amd64-v2. Есть также arm64, armv5–v7, 386, mips, riscv64, loong64, s390x и другие.',
			button: 'Все релизы',
			docs: 'Как запустить',
		},
		mikan: {
			title: 'Citrus и Mikan',
			text: 'Mikan — свободная VPN-панель. Её ноды встраивают ядро как библиотеку и считают трафик по каждому соединению каждого пользователя; сейчас это mihomo, Citrus станет следующим. Ядро живёт в отдельном репозитории, чтобы его можно было использовать и без панели: как обычный клиент или сервер в стиле mihomo.',
			site: 'Сайт Mikan',
			code: 'Mikan на GitHub',
		},
		news: {
			title: 'Новости',
			all: 'Все новости',
			rss: 'RSS',
		},
		header: {
			label: 'Проект',
			githubLabel: 'GitHub: исходный код Citrus',
			news: 'Новости',
			download: 'Скачать',
			downloadLabel: 'Скачать Citrus: релизы на GitHub',
			otherLanguage: 'English version',
		},
		footer: {
			label: 'Ссылки проекта',
			license: 'Citrus: свободная программа под GNU GPL v3, форк MetaCubeX/mihomo.',
			releases: 'Релизы',
			issues: 'Сообщить о проблеме',
			mikan: 'Mikan',
		},
		newsPage: {
			title: 'Новости',
			description: 'Новости Citrus: релизы, изменения в протоколах и планы.',
			empty: 'Пока новостей нет.',
			back: 'Все новости',
			feed: 'Подписаться через RSS',
		},
	},
	en: {
		hero: {
			title: 'The network core of Mikan',
			lead: 'Citrus is the core of the Mikan VPN service, a fork of mihomo. It speaks Xray, post-quantum REALITY, XHTTP and ECH included; keeps per-user traffic, limits and events; builds cascades and exports metrics. Same configuration as mihomo. GPL-3.0.',
			note: 'One binary for Linux, Windows, macOS, FreeBSD and Android.',
			primary: 'Get started',
			secondary: 'Download',
			art: 'A lime, the Citrus mascot',
		},
		features: {
			title: 'What it does',
			items: [
				{
					title: 'Inbound',
					text: 'HTTP, HTTPS, SOCKS, mixed, redirect and TPROXY. Plus server listeners for VLESS, Trojan, Hysteria2, TUIC, AnyTLS and more.',
				},
				{
					title: 'Outbound protocols',
					text: 'VLESS with REALITY, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS, TrustTunnel, Snell, WireGuard and more.',
				},
				{
					title: 'TUN',
					text: 'All system traffic through the core, with a configurable network stack.',
				},
				{
					title: 'DNS',
					text: 'DNS over HTTPS, TLS and QUIC, fake IP and routing rules for DNS queries.',
				},
				{
					title: 'Rules',
					text: 'Routing by domain, IP range, geodata, process and logical combinations of rules.',
				},
				{
					title: 'Providers and groups',
					text: 'Remote proxy and rule providers, health checks, fallback and load balancing.',
				},
				{
					title: 'Controller API',
					text: 'HTTP and WebSocket APIs compatible with mihomo clients and dashboards such as MetaCubeXD.',
				},
			],
		},
		why: {
			title: 'Why a core of its own',
			lead: 'Mikan is a VPN service: on its nodes the core runs as a server for many users at once. mihomo was written as a client, and much of what a node needs is not there. Citrus puts it into the core itself.',
			items: [
				{
					title: 'Xray compatibility',
					text: 'Post-quantum REALITY (X25519MLKEM768 and ML-DSA-65) on the client and the server, XHTTP with Xray’s behaviour and defaults, ECH keys and links in Xray’s formats. Automated tests check all of it against Xray v26.10.10.',
				},
				{
					title: 'Users are part of the core',
					text: 'Per-user traffic and online addresses, limits on speed, connections, addresses, quota and expiry, and inbound users changed without a restart. Through REST, the Go API and the /events stream.',
				},
				{
					title: 'A hardened server',
					text: 'A security review, a code review and a static audit: a controller without a secret stays off the network, pre-authentication state is bounded, every request is authenticated, updates are checked against checksums.txt, CI is pinned by digest.',
				},
				{
					title: 'Cascades',
					text: 'A type: chain group builds an entry → exit chain from proxies and groups, and its health check names the hop that broke.',
				},
				{
					title: 'Observability',
					text: 'Prometheus /metrics, /healthz and /readyz probes, events for rejected authentication and JSON logs for Loki and ELK.',
				},
				{
					title: 'Less to carry',
					text: 'VMess, SSR, Hysteria v1, TUIC v4, Shadowsocks stream ciphers, v2ray-plugin and mKCP are gone: about 20 thousand lines the service does not need.',
				},
			],
		},
		compare: {
			title: 'Citrus and mihomo',
			lead: 'The configuration format and the controller API are shared with mihomo, and mihomo clients connect to a Citrus server. The table lists only what has already landed in Citrus.',
			headers: ['', 'Citrus', 'mihomo'],
			rows: [
				['Post-quantum REALITY', 'X25519MLKEM768 by default, ML-DSA-65, server-side require-x25519mlkem768 and mldsa65-seed', 'X25519MLKEM768 only behind a flag, no ML-DSA-65'],
				['User stats', 'Traffic and online IPs per inbound and user, query with reset', 'Global totals only'],
				['User limits', 'Speed, connections, addresses, quota, expiry', 'None'],
				['Inbound users', 'Changed through REST, the listener stays up', 'Only by reloading the config'],
				['Events and metrics', '/events (WebSocket, SSE, NDJSON), /metrics, /healthz, /readyz', 'None'],
				['Cascades', 'A type: chain group with a check of every hop', 'dialer-proxy only'],
				['Controller on a network address', 'Only with a secret', 'Starts without one'],
				['Self-update', 'The package is checked against the release’s checksums.txt', 'No check'],
				['Legacy protocols', 'Removed', 'Present'],
			],
			more: 'More on compatibility',
		},
		quick: {
			title: 'Documentation',
			items: [
				{ title: 'Getting started', text: 'Download, add a config, run.', path: 'start/getting-started/' },
				{ title: 'Migrating from mihomo', text: 'What to change and what to expect.', path: 'migration/' },
				{ title: 'Compatibility', text: 'mihomo and Xray clients with a Citrus server.', path: 'compatibility/' },
				{ title: 'Roadmap', text: 'What is done and what is next.', path: 'roadmap/' },
				{ title: 'Changelog', text: 'Every merged pull request, by area.', path: 'changelog/' },
				{ title: 'Security', text: 'How to report a vulnerability.', path: 'security/' },
			],
		},
		download: {
			title: 'Download',
			lead: 'Builds are published as GitHub releases. Files are named',
			naming: 'citrus-<os>-<arch>-<version>',
			naming2: ': in a release the version is the tag (citrus-linux-arm64-v1.2.3.gz), in a prerelease the branch and commit (citrus-linux-arm64-main-1a2b3c4.gz). Windows builds are .zip; Linux also gets .deb, .rpm and .pkg.tar.zst.',
			headers: ['Channel', 'Built from', 'What it is'],
			channels: [
				['release', 'The latest vX.Y.Z tag', 'Stable versions.'],
				['Prerelease-main', 'The main branch', 'A build of every merge into main.'],
			],
			arch: 'The amd64 file targets x86-64-v3 (Intel Haswell, AMD Excavator and newer); for older ones take amd64-compatible (v1) or amd64-v2. There are also arm64, armv5–v7, 386, mips, riscv64, loong64, s390x and more.',
			button: 'All releases',
			docs: 'How to run it',
		},
		mikan: {
			title: 'Citrus and Mikan',
			text: 'Mikan is a free VPN panel. Its nodes embed the core as a library and count traffic per user on every connection; today that is mihomo, and Citrus is next. The core lives in its own repository so it can be used without the panel too: as a regular mihomo-style client or server.',
			site: 'Mikan website',
			code: 'Mikan on GitHub',
		},
		news: {
			title: 'News',
			all: 'All news',
			rss: 'RSS',
		},
		header: {
			label: 'Project',
			githubLabel: 'GitHub: the Citrus source code',
			news: 'News',
			download: 'Download',
			downloadLabel: 'Download Citrus: releases on GitHub',
			otherLanguage: 'Русская версия',
		},
		footer: {
			label: 'Project links',
			license: 'Citrus is free software under the GNU GPL v3, a fork of MetaCubeX/mihomo.',
			releases: 'Releases',
			issues: 'Report a problem',
			mikan: 'Mikan',
		},
		newsPage: {
			title: 'News',
			description: 'Citrus news: releases, protocol changes and plans.',
			empty: 'No news yet.',
			back: 'All news',
			feed: 'Subscribe via RSS',
		},
	},
} as const;
