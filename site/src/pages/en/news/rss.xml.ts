import rss from '@astrojs/rss';
import type { APIContext } from 'astro';
import { page, strings } from '../../../landing';
import { getPosts } from '../../../news';

export async function GET(context: APIContext) {
	const t = strings.en.newsPage;
	const posts = await getPosts('en');
	return rss({
		title: `Citrus · ${t.title}`,
		description: t.description,
		site: new URL(page('en', 'news/'), context.site),
		customData: '<language>en</language>',
		items: posts.map((p) => ({
			title: p.data.title,
			description: p.data.description,
			pubDate: p.data.date,
			link: page('en', `news/${p.slug}/`),
			content: p.rendered?.html,
		})),
	});
}
