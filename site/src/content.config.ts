import { defineCollection } from 'astro:content';
import { glob } from 'astro/loaders';
import { z } from 'astro/zod';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

export const collections = {
	docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
	// News posts: src/content/news/<ru|en>/<slug>.md. The same slug in both folders is the
	// same post in two languages.
	news: defineCollection({
		loader: glob({ pattern: '{ru,en}/*.{md,mdx}', base: './src/content/news' }),
		schema: z.object({
			title: z.string(),
			description: z.string(),
			date: z.coerce.date(),
		}),
	}),
};
