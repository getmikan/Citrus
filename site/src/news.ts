import { getCollection, type CollectionEntry } from 'astro:content';
import { page, strings, type Lang } from './landing';

export type Post = CollectionEntry<'news'> & { slug: string };

/** Posts in one language, newest first. The slug is the file name without the language folder. */
export async function getPosts(lang: Lang): Promise<Post[]> {
	const posts = await getCollection('news', (p) => p.id.startsWith(`${lang}/`));
	return posts
		.map((p) => ({ ...p, slug: p.id.slice(lang.length + 1) }))
		.sort((a, b) => b.data.date.getTime() - a.data.date.getTime());
}

/** The <link rel="alternate"> to the feed of one language, for Starlight's `head` frontmatter. */
export const feedLink = (lang: Lang) => [
	{
		tag: 'link' as const,
		attrs: { rel: 'alternate', type: 'application/rss+xml', title: `Citrus · ${strings[lang].newsPage.title}`, href: page(lang, 'news/rss.xml') },
	},
];
