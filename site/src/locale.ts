// Russian pages live at the root of the site, English ones under /en/.
const base = import.meta.env.BASE_URL.replace(/\/$/, '');

/** The same page in the given language. */
export function otherLocaleUrl(pathname: string, target: 'ru' | 'en'): string {
	const rest = pathname.startsWith(base) ? pathname.slice(base.length) || '/' : pathname;
	const ru = rest.replace(/^\/en(\/|$)/, '/');
	return `${base}${target === 'en' ? `/en${ru}` : ru}`;
}
