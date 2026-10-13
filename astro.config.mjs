import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';

export default defineConfig({
  site: 'https://shared-signals.dev',
  trailingSlash: 'always',
  integrations: [sitemap()],
  build: { format: 'directory' },
  markdown: {
    shikiConfig: { themes: { light: 'github-light', dark: 'github-dark' }, wrap: true },
  },
});
