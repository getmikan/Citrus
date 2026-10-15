import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { page, strings } from '../../landing';
import { getPosts } from '../../news';

export async function GET(context: APIContext) {
	const t = strings.ru.newsPage;
	const posts = await getPosts('ru');
	return rss({
		title: `Citrus · ${t.title}`,
		description: t.description,
		site: new URL(page('ru', 'news/'), context.site),
		customData: '<language>ru</language>',
		items: posts.map((p) => ({
			title: p.data.title,
			description: p.data.description,
			pubDate: p.data.date,
			link: page('ru', `news/${p.slug}/`),
			content: p.rendered?.html,
		})),
	});
}
