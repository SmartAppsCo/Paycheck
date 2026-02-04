import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Paycheck',
  tagline: 'Offline-first licensing for indie developers',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://paycheck.dev',
  baseUrl: '/docs/',

  onBrokenLinks: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          routeBasePath: '/', // Docs at root, no /docs prefix
        },
        blog: false, // Disable blog
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themeConfig: {
    colorMode: {
      defaultMode: 'dark',
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'Paycheck',
      logo: {
        alt: 'Paycheck',
        src: 'img/logo.png',
        href: 'https://paycheck.dev',
        height: 28,
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://paycheck.dev',
          label: 'Home',
          position: 'right',
        },
        {
          href: 'https://github.com/SmartAppsCo/Paycheck',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      copyright: `© ${new Date().getFullYear()} Paycheck`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['rust', 'bash', 'json', 'toml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
