/**
 * build-docs.js — renders doc/*.md into real pages under /docs/.
 *
 * The documentation was already written and already good; it just was not on the web.
 * It shipped in the image as raw Markdown, served as application/octet-stream, and
 * robots.txt disallowed /doc/ — so the only text the site owned that answers a real
 * question ("how does SecureBit do key exchange", "what does SAS actually verify")
 * was invisible to search. Meanwhile the site's entire indexable surface was one
 * address repeated in thirteen languages, which is why every category query lands on
 * page three or worse.
 *
 * So each document gets its own URL, its own <title> and description, and a place in
 * the sitemap. Pages are static and script-free — no bundle, no framework, no fonts to
 * fetch — because a reference page's job is to be readable and to be read by a crawler
 * on the first request.
 *
 * The raw /doc/*.md files stay disallowed in robots.txt: they are the same text at a
 * second address, and only one of the two should be indexable.
 */

const fs = require('fs');
const path = require('path');
// marked is ESM-only, so it is pulled in with a dynamic import inside build() rather
// than require()d at the top: requiring an ES module works on current Node but only
// behind an ExperimentalWarning, and a release build should not print one.

const ROOT = path.join(__dirname, '..');
const DOC_DIR = path.join(ROOT, 'doc');
const OUT_ROOT = process.env.DOCS_OUT_ROOT || ROOT;

/** README.md is the section's own index, so it owns /docs/ rather than a subdirectory. */
const INDEX_FILE = 'README.md';

/**
 * The one document that is a list of questions. Named explicitly rather than detected
 * from its shape: an earlier version keyed off "has two or more <h2>", which is true of
 * every document here, and shipped ARCHITECTURE.md marked up as a FAQPage. Structured
 * data that describes the page as something it is not is worse than none at all.
 */
const FAQ_FILE = 'FAQ.md';

const REPO = 'https://github.com/SecureBitChat/securebit-chat';
const BASE = 'https://securebit.chat';

const esc = (value) =>
    String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

/** GitHub-compatible heading slug, so the #anchors already written in the docs resolve. */
const slugify = (text) =>
    text.toLowerCase().trim()
        .replace(/[^\w\s-]/g, '')
        .replace(/\s+/g, '-');

/** ARCHITECTURE.md → architecture. The file name is the URL; nothing else has to agree. */
const slugForFile = (file) => path.basename(file, '.md').toLowerCase();

const urlForFile = (file) => (file === INDEX_FILE ? '/docs/' : `/docs/${slugForFile(file)}/`);

/**
 * The document list, in reading order rather than alphabetical: someone arriving at
 * /docs/ should meet the architecture before the wire format of the invitation.
 */
const ORDER = [
    'README.md',
    'FAQ.md',
    'ARCHITECTURE.md',
    'CRYPTOGRAPHY.md',
    'DESCRIPTOR-SBQ2.md',
    'CONFIGURATION.md',
    'CALLS.md',
    'API.md',
    'CONTRIBUTING.md',
    'USE-POLICY.md',
];

function docFiles() {
    const present = fs.readdirSync(DOC_DIR).filter((f) => f.endsWith('.md'));
    const known = ORDER.filter((f) => present.includes(f));
    // Anything added to doc/ without being listed above still gets a page — it just
    // sorts to the end instead of silently never being published.
    const rest = present.filter((f) => !ORDER.includes(f)).sort();
    return [...known, ...rest];
}

/** Rewrite the links the Markdown was written with into the URLs the site serves. */
function rewriteLinks(html) {
    return html.replace(/href="([^"]+)"/g, (whole, href) => {
        if (/^(https?:|mailto:|#)/.test(href)) return whole;
        // Repository-root files have no page of their own; they belong on GitHub.
        if (href === '../README.md') return `href="${REPO}#readme"`;
        const rootFile = href.match(/^\.\.\/([A-Z0-9._-]+\.md)$/);
        if (rootFile) return `href="${REPO}/blob/main/${rootFile[1]}"`;
        const sibling = href.match(/^\.?\/?([A-Za-z0-9._-]+)\.md(#.*)?$/);
        if (sibling) return `href="${urlForFile(`${sibling[1]}.md`)}${sibling[2] || ''}"`;
        return whole;
    });
}

/** Give every heading below the title an id, so in-page anchors and deep links work. */
function anchorHeadings(html) {
    return html.replace(/<h([2-4])>([\s\S]*?)<\/h\1>/g, (whole, level, inner) => {
        const text = inner.replace(/<[^>]+>/g, '').trim();
        const id = slugify(text);
        if (!id) return whole;
        return `<h${level} id="${esc(id)}">${inner}</h${level}>`;
    });
}

/** Snippet-length summary from the document's own opening paragraph. */
function firstParagraph(html) {
    const match = html.match(/<p>([\s\S]*?)<\/p>/);
    if (!match) return '';
    const text = match[1].replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
    if (text.length <= 155) return text;
    const cut = text.slice(0, 155);
    return `${cut.slice(0, cut.lastIndexOf(' ')).replace(/[,;:.]$/, '')}…`;
}

// Self-contained and script-free. The CSP below is stricter than the app's for the
// same reason the page has no bundle: nothing here needs to execute.
const STYLE = `

    /* These pages carry no script — that is the point of them — so the theme can only
       come from the media query. There is no toggle here and no stored preference: a
       reference page follows the reader's system and nothing else. The values are the
       same two palettes as src/styles/theme.css, restated because these pages do not
       load the app's stylesheet and are not going to start for eleven declarations. */
    :root {
        color-scheme: dark;
        --d-ink: 255, 255, 255;
        --d-bg: #0f0f11;
        --d-bg-deep: #0b0b0e;
        --d-code-bg: #17171c;
        --d-text: #d6d6dc;
        --d-heading: #f4f4f6;
        --d-strong: #e8e8eb;
        --d-body: #a9a9b3;
        --d-pre: #c9c9d1;
        --d-muted: #8a8a92;
        --d-faint: #6b6b73;
        --d-accent: #f0892a;
        --d-accent-rgb: 240, 137, 42;
    }
    @media (prefers-color-scheme: light) {
        :root {
            color-scheme: light;
            --d-ink: 0, 0, 0;
            --d-bg: #fbfbfc;
            --d-bg-deep: #f2f3f5;
            --d-code-bg: #f2f3f5;
            --d-text: #26262c;
            --d-heading: #0e0e12;
            --d-strong: #1b1b20;
            --d-body: #43434c;
            --d-pre: #2f3340;
            --d-muted: #63636c;
            --d-faint: #7c7c85;
            --d-accent: #b05c08;
            --d-accent-rgb: 176, 92, 8;
        }
    }
    * { box-sizing: border-box; }
    body {
        margin: 0;
        background: var(--d-bg);
        color: var(--d-text);
        font-family: Inter, system-ui, -apple-system, "Segoe UI", sans-serif;
        font-size: 16px;
        line-height: 1.68;
    }
    .wrap { max-width: 46rem; margin: 0 auto; padding: 28px 24px 90px; }
    .top {
        display: flex; flex-wrap: wrap; gap: 8px 18px; align-items: baseline;
        padding-bottom: 16px; margin-bottom: 40px;
        border-bottom: 1px solid rgba(var(--d-ink),.08);
        font-size: 13.5px;
    }
    .top a { color: var(--d-muted); text-decoration: none; }
    .top a:hover, .top a:focus-visible { color: var(--d-accent); }
    .top .brand { color: var(--d-accent); font-weight: 700; letter-spacing: .04em; }
    .top .here { color: var(--d-text); margin-inline-start: auto; }
    h1 { font-size: clamp(28px, 5vw, 36px); font-weight: 800; letter-spacing: -1px; line-height: 1.14; color: var(--d-heading); margin: 0 0 24px; }
    h2 { font-size: 22px; font-weight: 700; letter-spacing: -.4px; color: var(--d-heading); margin: 46px 0 12px; padding-top: 14px; border-top: 1px solid rgba(var(--d-ink),.07); }
    h3 { font-size: 17.5px; font-weight: 700; color: var(--d-strong); margin: 30px 0 8px; }
    h4 { font-size: 15.5px; font-weight: 700; color: var(--d-strong); margin: 22px 0 6px; }
    p, li { color: var(--d-body); }
    p { margin: 0 0 16px; }
    ul, ol { padding-inline-start: 22px; margin: 0 0 16px; }
    li { margin: 5px 0; }
    a { color: var(--d-accent); text-underline-offset: 2px; }
    strong { color: var(--d-strong); }
    code { font-family: ui-monospace, "SF Mono", Menlo, monospace; font-size: .88em; background: var(--d-code-bg); border: 1px solid rgba(var(--d-ink),.07); border-radius: 4px; padding: 1px 5px; color: var(--d-strong); }
    pre { background: var(--d-bg-deep); border: 1px solid rgba(var(--d-ink),.08); border-radius: 8px; padding: 14px 16px; overflow-x: auto; margin: 0 0 18px; }
    pre code { background: none; border: 0; padding: 0; font-size: 13px; line-height: 1.62; color: var(--d-pre); }
    .tablewrap { overflow-x: auto; margin: 0 0 20px; }
    table { border-collapse: collapse; width: 100%; font-size: 14.5px; min-width: 30rem; }
    th { text-align: start; color: var(--d-muted); font-weight: 600; font-size: 12px; letter-spacing: .08em; text-transform: uppercase; padding: 0 14px 8px 0; border-bottom: 1px solid rgba(var(--d-ink),.12); }
    td { padding: 9px 14px 9px 0; border-bottom: 1px solid rgba(var(--d-ink),.06); vertical-align: top; color: var(--d-body); }
    td:first-child, th:first-child { padding-inline-start: 0; }
    blockquote { margin: 0 0 18px; padding: 2px 0 2px 16px; border-inline-start: 3px solid rgba(var(--d-accent-rgb),.4); color: var(--d-muted); }
    hr { border: 0; border-top: 1px solid rgba(var(--d-ink),.08); margin: 34px 0; }
    img { max-width: 100%; height: auto; }
    a:focus-visible { outline: 2px solid var(--d-accent); outline-offset: 2px; border-radius: 2px; }
    .more { margin-top: 64px; padding-top: 22px; border-top: 1px solid rgba(var(--d-ink),.08); }
    .more h2 { font-size: 13px; letter-spacing: .12em; text-transform: uppercase; color: var(--d-faint); border: 0; margin: 0 0 12px; padding: 0; font-weight: 700; }
    .more ul { list-style: none; padding: 0; margin: 0; display: grid; grid-template-columns: repeat(auto-fit, minmax(15rem, 1fr)); gap: 4px 24px; }
    .more li { margin: 0; padding: 7px 0; border-bottom: 1px solid rgba(var(--d-ink),.05); font-size: 14.5px; }
    @media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
`;

/**
 * FAQ markup, built from the document's own <h2> questions and the prose under each.
 *
 * Worth being honest about the payoff: Google narrowed FAQ rich results to
 * authoritative government and health sites in 2023, so this is unlikely to change how
 * the page looks in their results. It is still the correct description of what the page
 * is, and it is read by other engines and by the assistants people increasingly ask
 * "which messenger should I use" — which is the traffic this page exists for.
 */
function faqSchema(html, url) {
    const questions = [...html.matchAll(/<h2[^>]*>([\s\S]*?)<\/h2>([\s\S]*?)(?=<h2|$)/g)]
        .map(([, heading, answer]) => ({
            name: heading.replace(/<[^>]+>/g, '').trim(),
            // Answers keep their links and emphasis: schema.org allows a limited set of
            // HTML here, and stripping it would drop the references the answers rely on.
            text: answer.replace(/\s+/g, ' ').trim(),
        }))
        .filter((q) => q.name && q.text);

    if (questions.length < 2) return null;
    return {
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        url: BASE + url,
        inLanguage: 'en',
        isPartOf: { '@type': 'WebSite', '@id': `${BASE}/#website` },
        publisher: { '@id': `${BASE}/#organization` },
        mainEntity: questions.map((q) => ({
            '@type': 'Question',
            name: q.name,
            acceptedAnswer: { '@type': 'Answer', text: q.text },
        })),
    };
}

function page({ title, description, url, bodyHtml, siblings, schema }) {
    const related = siblings.length
        ? `        <nav class="more">
            <h2>More documentation</h2>
            <ul>
${siblings.map((s) => `                <li><a href="${s.url}">${esc(s.title)}</a></li>`).join('\n')}
            </ul>
        </nav>
`
        : '';

    return `<!DOCTYPE html>
<!-- Generated by scripts/build-docs.js from doc/*.md. Edits here are overwritten;
     change the Markdown instead. -->
<html lang="en" dir="ltr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; upgrade-insecure-requests;">
    <meta http-equiv="X-Content-Type-Options" content="nosniff">
    <meta http-equiv="Referrer-Policy" content="strict-origin-when-cross-origin">
    <title>${esc(title)} - SecureBit.chat</title>
    <meta name="description" content="${esc(description)}">
    <meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1">
    <link rel="canonical" href="${BASE}${url}">
    <link rel="icon" type="image/x-icon" href="/logo/favicon.ico">
    <meta property="og:site_name" content="SecureBit.chat">
    <meta property="og:title" content="${esc(title)} - SecureBit.chat">
    <meta property="og:description" content="${esc(description)}">
    <meta property="og:url" content="${BASE}${url}">
    <meta property="og:type" content="article">
    <meta property="og:locale" content="en_US">
    <meta property="og:image" content="${BASE}/assets/social-card.png">
    <meta name="twitter:card" content="summary_large_image">
    <meta name="twitter:title" content="${esc(title)} - SecureBit.chat">
    <meta name="twitter:description" content="${esc(description)}">
    <meta name="twitter:image" content="${BASE}/assets/social-card.png">
    <script type="application/ld+json">
${JSON.stringify(schema, null, 2)}
    </script>
    <style>${STYLE}    </style>
</head>
<body>
    <div class="wrap">
        <nav class="top">
            <a class="brand" href="/">SecureBit.chat</a>
            <a href="/docs/">Documentation</a>
            <a href="${REPO}" rel="noopener">GitHub</a>
            <span class="here">${esc(title)}</span>
        </nav>
${bodyHtml}
${related}    </div>
</body>
</html>
`;
}

/**
 * Public URLs and titles of the documentation. Deliberately free of marked, so that
 * build-i18n.js can require this module for the sitemap without pulling a Markdown
 * parser — and without being async — just to learn a list of paths.
 */
function docPages() {
    return docFiles().map((file) => {
        const markdown = fs.readFileSync(path.join(DOC_DIR, file), 'utf8');
        const heading = markdown.match(/^#\s+(.+?)\s*$/m);
        return {
            file,
            url: urlForFile(file),
            title: heading ? heading[1] : path.basename(file, '.md'),
        };
    });
}

async function build() {
    const { marked } = await import('marked');
    const pages = docPages();
    const written = [];

    for (const entry of pages) {
        const markdown = fs.readFileSync(path.join(DOC_DIR, entry.file), 'utf8');
        let html = marked.parse(markdown);
        html = anchorHeadings(rewriteLinks(html));
        // Wide tables must scroll inside their own box; 129 table rows across these
        // documents would otherwise make the page itself scroll sideways on a phone.
        html = html.replace(/<table>[\s\S]*?<\/table>/g, (t) => `<div class="tablewrap">${t}</div>`);

        const body = html
            .split('\n')
            .map((line) => (line ? `        ${line}` : line))
            .join('\n');

        const dest = entry.file === INDEX_FILE
            ? path.join(OUT_ROOT, 'docs', 'index.html')
            : path.join(OUT_ROOT, 'docs', slugForFile(entry.file), 'index.html');

        fs.mkdirSync(path.dirname(dest), { recursive: true });
        const description = firstParagraph(html)
            || `${entry.title} — SecureBit.chat technical documentation.`;

        fs.writeFileSync(dest, page({
            title: entry.title,
            description,
            url: entry.url,
            bodyHtml: body,
            siblings: pages.filter((p) => p.url !== entry.url),
            schema: (entry.file === FAQ_FILE && faqSchema(html, entry.url)) || {
                '@context': 'https://schema.org',
                '@type': 'TechArticle',
                headline: entry.title,
                description,
                url: BASE + entry.url,
                inLanguage: 'en',
                isPartOf: { '@type': 'WebSite', '@id': `${BASE}/#website` },
                publisher: { '@id': `${BASE}/#organization` },
            },
        }), 'utf8');
        written.push(path.relative(OUT_ROOT, dest));
    }

    return written;
}

async function main() {
    console.log('📄 Generating documentation pages...');
    for (const file of await build()) console.log(`   ✅ ${file}`);
    console.log('✅ documentation page generation completed');
}

if (require.main === module) {
    main().catch((error) => {
        console.error('❌ docs build failed:', error.message);
        process.exit(1);
    });
}

module.exports = { docPages, urlForFile, slugify, build };
