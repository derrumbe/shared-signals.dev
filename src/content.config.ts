import { defineCollection, z } from 'astro:content';
import { file } from 'astro/loaders';
import { INTEROP_EVENTS } from './data/interop';

const interopIds = Object.keys(INTEROP_EVENTS) as [keyof typeof INTEROP_EVENTS, ...(keyof typeof INTEROP_EVENTS)[]];

// One entry per product or library. Schema-checked at build time, so a typo in
// `roles`, `kind` or an interop event id fails the build instead of rendering wrong.
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
    // Link to the vendor's own SSF documentation. Leave it out when there is none; the page then says
    // so rather than linking somewhere else.
    url: z.string().url().optional(),
    source: z.string().url().optional(),
    summary: z.string(),
    // OpenID Foundation interop events this implementation took part in.
    interop: z.array(z.enum(interopIds)).optional(),
  }),
});

export const collections = { implementations };
