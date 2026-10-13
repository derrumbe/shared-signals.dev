import { defineCollection, z } from 'astro:content';
import { file } from 'astro/loaders';

// One entry per product or library. Schema-checked at build time, so a typo in
// `roles` or `kind` fails the build instead of rendering wrong.
const implementations = defineCollection({
  loader: file('src/content/implementations/implementations.json'),
  schema: z.object({
    name: z.string(),
    vendor: z.string(),
    kind: z.enum(['product', 'library', 'test-service']),
    roles: z.array(z.enum(['transmitter', 'receiver'])).min(1),
    profiles: z.array(z.enum(['SSF', 'CAEP', 'RISC'])).min(1),
    delivery: z.array(z.enum(['push', 'poll'])).optional(),
    language: z.string().optional(),
    license: z.string().optional(),
    url: z.string().url(),
    source: z.string().url().optional(),
    summary: z.string(),
  }),
});

export const collections = { implementations };
