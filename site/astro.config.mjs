// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';

// GitHub Pages serves the project at getmikan.github.io/Citrus/. Links inside the docs are
// written with the base (/Citrus/...), and the link validator checks them on every build.
// The look is the Mikan site's (Miroshka000/mikan, site/): the same stack, theme and header.
export default defineConfig({
	site: 'https://getmikan.github.io',
	base: '/Citrus',
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Citrus',
			description: 'Ядро VPN-сервиса Mikan: форк mihomo с совместимостью с Xray, пост-квантовым REALITY, учётом и лимитами пользователей, каскадами и метриками. GPL-3.0.',
			logo: { src: './src/assets/logo.webp', alt: '' },
			favicon: '/favicon.png',
			defaultLocale: 'root',
			locales: {
				root: { label: 'Русский', lang: 'ru' },
				en: { label: 'English', lang: 'en' },
			},
			editLink: { baseUrl: 'https://github.com/getmikan/Citrus/edit/dev/site/' },
			lastUpdated: false,
			credits: false,
			customCss: [
				'@fontsource-variable/onest',
				'@fontsource-variable/unbounded',
				'@fontsource-variable/jetbrains-mono',
				'./src/styles/theme.css',
			],
			components: {
				Head: './src/components/Head.astro',
				Header: './src/components/Header.astro',
				ThemeSelect: './src/components/ThemeSelect.astro',
				LanguageSelect: './src/components/LanguageSelect.astro',
				Footer: './src/components/Footer.astro',
				Hero: './src/components/Hero.astro',
			},
			expressiveCode: {
				// Code is dark in both modes, as on the Mikan site.
				themes: ['github-dark-default'],
				useStarlightDarkModeSwitch: false,
				useStarlightUiThemeColors: false,
				// Plain blocks for shell commands too: no fake window bar with dots.
				defaultProps: { frame: 'code' },
				styleOverrides: {
					borderRadius: '12px',
					borderColor: 'var(--ct-code-line)',
					codeBackground: 'var(--ct-code-bg)',
					codeForeground: '#e7e9ed',
					codeFontFamily: 'var(--sl-font-mono)',
					codeFontSize: '0.8125rem',
					uiFontFamily: 'var(--sl-font)',
					frames: {
						shadowColor: 'transparent',
						editorActiveTabIndicatorTopColor: 'var(--ct-accent)',
						terminalTitlebarDotsOpacity: '0.35',
					},
				},
			},
			sidebar: [
				{
					label: 'Начало',
					translations: { en: 'Getting started' },
					items: [{ slug: 'start/getting-started' }, { slug: 'start/server-profile' }, { slug: 'start/configuration' }, { slug: 'start/controller' }, { slug: 'start/chains' }, { slug: 'start/user-stats' }, { slug: 'start/inbound-users' }, { slug: 'start/user-limits' }, { slug: 'start/metrics' }, { slug: 'start/events' }],
				},
				{
					label: 'Переход',
					translations: { en: 'Moving to Citrus' },
					items: [{ slug: 'migration' }, { slug: 'compatibility' }],
				},
				{
					label: 'Проект',
					translations: { en: 'Project' },
					items: [{ slug: 'roadmap' }, { slug: 'changelog' }, { slug: 'security' }, { slug: 'project/contributing' }],
				},
			],
			// The news pages (src/pages/**/news) are not docs pages, so the validator does not
			// know them; links to them are checked by the build itself (getStaticPaths).
			plugins: [
				starlightLinksValidator({
					errorOnLocalLinks: true,
					exclude: ['/Citrus/news/', '/Citrus/news/**/*', '/Citrus/en/news/', '/Citrus/en/news/**/*'],
				}),
			],
		}),
	],
});
