import { defineConfig } from "vitepress";

const zhGuide = [
  { text: "介绍", link: "/guide/introduction" },
  { text: "安全边界", link: "/safety" },
  { text: "CLI 草案", link: "/cli" },
  { text: "架构", link: "/architecture" },
  { text: "路线图", link: "/roadmap" },
];

const enGuide = [
  { text: "Introduction", link: "/en/guide/introduction" },
  { text: "Safety", link: "/en/safety" },
  { text: "CLI", link: "/en/cli" },
  { text: "Architecture", link: "/en/architecture" },
  { text: "Roadmap", link: "/en/roadmap" },
];

export default defineConfig({
  title: "SweepX",
  description:
    "SweepX documentation site for the bilingual design snapshot. Current implementation remains under development.",
  cleanUrls: true,
  lastUpdated: true,
  head: [
    ["meta", { name: "theme-color", content: "#d88c3a" }],
    [
      "meta",
      {
        name: "keywords",
        content:
          "SweepX, disk cleanup, VitePress, bilingual docs, Rust CLI, safety-first",
      },
    ],
  ],
  themeConfig: {
    logo: {
      src: "/mark.svg",
      alt: "SweepX",
    },
    search: {
      provider: "local",
      options: {
        locales: {
          root: {
            translations: {
              button: {
                buttonText: "搜索",
                buttonAriaLabel: "搜索文档",
              },
              modal: {
                noResultsText: "没有找到结果",
                resetButtonTitle: "清除查询",
                footer: {
                  selectText: "选择",
                  navigateText: "切换",
                  closeText: "关闭",
                },
              },
            },
          },
          en: {
            translations: {
              button: {
                buttonText: "Search",
                buttonAriaLabel: "Search docs",
              },
              modal: {
                noResultsText: "No results found",
                resetButtonTitle: "Clear query",
                footer: {
                  selectText: "Select",
                  navigateText: "Navigate",
                  closeText: "Close",
                },
              },
            },
          },
        },
      },
    },
    socialLinks: [],
    footer: {
      message:
        "Design snapshot only. Destructive features are under development and remain unavailable or unqualified.",
      copyright: "Copyright © 2026 SweepX design snapshot",
    },
    nav: [
      { text: "首页", link: "/" },
      { text: "指南", items: zhGuide },
      {
        text: "语言",
        items: [
          { text: "简体中文", link: "/" },
          { text: "English", link: "/en/" },
        ],
      },
    ],
    sidebar: {
      "/": [
        {
          text: "概览",
          items: [
            { text: "首页", link: "/" },
            { text: "介绍", link: "/guide/introduction" },
          ],
        },
        {
          text: "核心主题",
          items: [
            { text: "安全边界", link: "/safety" },
            { text: "CLI 草案", link: "/cli" },
            { text: "架构", link: "/architecture" },
            { text: "路线图", link: "/roadmap" },
          ],
        },
      ],
      "/en/": [
        {
          text: "Overview",
          items: [
            { text: "Home", link: "/en/" },
            { text: "Introduction", link: "/en/guide/introduction" },
          ],
        },
        {
          text: "Core Topics",
          items: [
            { text: "Safety", link: "/en/safety" },
            { text: "CLI", link: "/en/cli" },
            { text: "Architecture", link: "/en/architecture" },
            { text: "Roadmap", link: "/en/roadmap" },
          ],
        },
      ],
    },
  },
  locales: {
    root: {
      label: "简体中文",
      lang: "zh-CN",
      title: "SweepX",
      description: "安全优先的磁盘分析与清理设计文档",
      themeConfig: {
        nav: [
          { text: "首页", link: "/" },
          { text: "指南", items: zhGuide },
          {
            text: "English",
            link: "/en/",
          },
        ],
        sidebar: {
          "/": [
            {
              text: "概览",
              items: [
                { text: "首页", link: "/" },
                { text: "介绍", link: "/guide/introduction" },
              ],
            },
            {
              text: "核心主题",
              items: [
                { text: "安全边界", link: "/safety" },
                { text: "CLI 草案", link: "/cli" },
                { text: "架构", link: "/architecture" },
                { text: "路线图", link: "/roadmap" },
              ],
            },
          ],
        },
        outline: {
          label: "本页内容",
        },
        docFooter: {
          prev: "上一页",
          next: "下一页",
        },
        returnToTopLabel: "返回顶部",
        sidebarMenuLabel: "菜单",
        darkModeSwitchLabel: "主题",
        lightModeSwitchTitle: "切换到浅色模式",
        darkModeSwitchTitle: "切换到深色模式",
      },
    },
    en: {
      label: "English",
      lang: "en-US",
      title: "SweepX",
      description: "Safety-first disk analysis and cleanup design snapshot",
      themeConfig: {
        nav: [
          { text: "Home", link: "/en/" },
          { text: "Guide", items: enGuide },
          {
            text: "简体中文",
            link: "/",
          },
        ],
        sidebar: {
          "/en/": [
            {
              text: "Overview",
              items: [
                { text: "Home", link: "/en/" },
                { text: "Introduction", link: "/en/guide/introduction" },
              ],
            },
            {
              text: "Core Topics",
              items: [
                { text: "Safety", link: "/en/safety" },
                { text: "CLI", link: "/en/cli" },
                { text: "Architecture", link: "/en/architecture" },
                { text: "Roadmap", link: "/en/roadmap" },
              ],
            },
          ],
        },
        outline: {
          label: "On this page",
        },
      },
    },
  },
});
