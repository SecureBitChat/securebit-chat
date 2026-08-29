/**
 * build-i18n.js — renders one static index.html per locale from a single template.
 *
 * Why static generation rather than swapping strings at runtime: the whole app is
 * client-rendered into <div id="root">, so a crawler only ever sees <head>. A locale
 * that has no URL of its own has no way of being indexed. Each locale therefore gets
 * a real file at a real path, with its own title, description, canonical and hreflang
 * cluster, produced at build time.
 *
 * Runs before post-build.js, which re-stamps ?v= and sw.js. The ?v=BUILD_VERSION
 * placeholders are filled here from meta.json so the generated files are already
 * correct on their own; post-build's later pass over index.html is idempotent.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const TEMPLATE = path.join(ROOT, 'templates', 'index.template.html');

// Overridable so the test can render a throwaway multi-locale site into a temp
// directory: the machinery that matters here only shows itself with two locales,
// and a half-translated locale is not something to ship just to exercise it.
const LOCALES_DIR = process.env.I18N_LOCALES_DIR || path.join(ROOT, 'locales');
const OUT_ROOT = process.env.I18N_OUT_ROOT || ROOT;

const read = (p) => fs.readFileSync(p, 'utf8');
const readJson = (p) => JSON.parse(read(p));

/** Escape the four characters that can break out of a double-quoted attribute. */
const attr = (value) =>
    String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;');

/** Public URL of a locale. The default locale owns the root, so existing links keep working. */
function localeUrl(site, code) {
    return code === site.defaultLocale ? `${site.baseUrl}/` : `${site.baseUrl}/${code}/`;
}

/** Where the rendered file lands on disk. */
function outputPath(site, code) {
    return code === site.defaultLocale
        ? path.join(OUT_ROOT, 'index.html')
        : path.join(OUT_ROOT, code, 'index.html');
}

/**
 * hreflang cluster. Every locale lists every locale including itself — Google treats a
 * cluster that omits its own page as invalid and ignores it. A single-locale site gets
 * no cluster at all, since there is nothing to point at.
 */
function hreflangLinks(site) {
    if (site.locales.length < 2) return '';
    const links = site.locales.map(
        (code) => `    <link rel="alternate" hreflang="${attr(site.byCode[code].htmlLang)}" href="${attr(localeUrl(site, code))}">`
    );
    links.push(`    <link rel="alternate" hreflang="x-default" href="${attr(localeUrl(site, site.defaultLocale))}">`);
    return links.join('\n');
}

function ogLocaleAlternate(site, code) {
    if (site.locales.length < 2) return '';
    return site.locales
        .filter((other) => other !== code)
        .map((other) => `    <meta property="og:locale:alternate" content="${attr(site.byCode[other].ogLocale)}">`)
        .join('\n');
}

/**
 * schema.org graph, rebuilt per locale so the descriptions and feature list are
 * translated too — a page whose visible text is German and whose structured data is
 * English is describing something other than itself.
 */
function structuredData(site, code) {
    const locale = site.byCode[code];
    const url = localeUrl(site, code);
    const graph = {
        '@context': 'https://schema.org',
        '@graph': [
            {
                '@type': 'WebSite',
                '@id': `${site.baseUrl}/#website`,
                name: site.siteName,
                url: `${site.baseUrl}/`,
                description: locale.schema.siteDescription,
                inLanguage: locale.htmlLang,
            },
            {
                '@type': 'WebApplication',
                name: site.siteName,
                url,
                applicationCategory: 'CommunicationApplication',
                operatingSystem: locale.schema.operatingSystem,
                browserRequirements: locale.schema.browserRequirements,
                description: locale.schema.appDescription,
                inLanguage: locale.htmlLang,
                image: site.baseUrl + site.socialCard,
                license: 'https://opensource.org/licenses/MIT',
                isAccessibleForFree: true,
                offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
                featureList: locale.schema.featureList,
                sameAs: [site.repository],
            },
        ],
    };
    // Indent to sit under the <script> tag that wraps it.
    return JSON.stringify(graph, null, 2)
        .split('\n')
        .map((line) => `    ${line}`)
        .join('\n');
}

/**
 * Substitute {{TOKENS}}. A block token that renders empty takes its whole line with it,
 * so an unused hreflang cluster leaves no blank gap behind.
 */
function render(template, values) {
    let out = template;
    for (const [key, value] of Object.entries(values)) {
        if (value === '') {
            out = out.replace(new RegExp(`^[ \\t]*\\{\\{${key}\\}\\}\\n`, 'm'), '');
        }
        out = out.split(`{{${key}}}`).join(value);
    }
    const leftover = out.match(/\{\{[A-Z_]+\}\}/g);
    if (leftover) throw new Error(`unresolved placeholders: ${[...new Set(leftover)].join(', ')}`);
    return out;
}

function loadSite() {
    const site = readJson(path.join(LOCALES_DIR, 'site.json'));
    site.byCode = {};
    for (const code of site.locales) {
        const file = path.join(LOCALES_DIR, `${code}.json`);
        if (!fs.existsSync(file)) throw new Error(`locale listed in site.json has no file: locales/${code}.json`);
        site.byCode[code] = readJson(file);
    }
    if (!site.locales.includes(site.defaultLocale)) {
        throw new Error(`defaultLocale "${site.defaultLocale}" is not in the locales list`);
    }
    return site;
}

/** The build version already stamped into meta.json, so generated files are never stale. */
function buildVersion() {
    const metaPath = path.join(ROOT, 'meta.json');
    if (!fs.existsSync(metaPath)) return 'BUILD_VERSION';
    return readJson(metaPath).version || 'BUILD_VERSION';
}

function buildPages(site, template, version) {
    const written = [];
    for (const code of site.locales) {
        const locale = site.byCode[code];
        const html = render(template, {
            HTML_LANG: attr(locale.htmlLang),
            // Written into <html> rather than left to the app: the page is styled and
            // painted long before React mounts, so a direction applied in JS would show
            // the reader one frame of a mirrored layout first.
            HTML_DIR: attr(locale.dir || 'ltr'),
            TITLE: attr(locale.meta.title),
            DESCRIPTION: attr(locale.meta.description),
            KEYWORDS: attr(locale.meta.keywords),
            AUTHOR: attr(site.author),
            SITE_NAME: attr(site.siteName),
            CANONICAL: attr(localeUrl(site, code)),
            MANIFEST: code === site.defaultLocale ? '/manifest.json' : `/${code}/manifest.json`,
            HREFLANG_LINKS: hreflangLinks(site),
            OG_TITLE: attr(locale.meta.ogTitle),
            OG_DESCRIPTION: attr(locale.meta.ogDescription),
            OG_LOCALE: attr(locale.ogLocale),
            OG_LOCALE_ALTERNATE: ogLocaleAlternate(site, code),
            OG_IMAGE_ALT: attr(locale.meta.ogImageAlt),
            TWITTER_TITLE: attr(locale.meta.twitterTitle),
            TWITTER_DESCRIPTION: attr(locale.meta.twitterDescription),
            TWITTER_IMAGE_ALT: attr(locale.meta.twitterImageAlt),
            SOCIAL_CARD: attr(site.baseUrl + site.socialCard),
            JSONLD: structuredData(site, code),
        }).replace(/\?v=BUILD_VERSION/g, `?v=${version}`);

        const dest = outputPath(site, code);
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, html, 'utf8');
        written.push(path.relative(OUT_ROOT, dest));
    }
    return written;
}

/**
 * Per-locale web app manifests.
 *
 * The root manifest.json stays hand-maintained: its "./" start_url, scope and icon
 * paths already resolve correctly for the default locale, which owns the root. A
 * locale in a subdirectory cannot reuse it — "./logo/icon.png" fetched from
 * /de/manifest.json resolves to /de/logo/icon.png — so each one gets a derived copy
 * with absolute paths, its own start_url, and its own translated name. The scope
 * stays "/" so a single installed app still covers the whole site.
 */
function buildManifests(site) {
    const source = path.join(ROOT, 'manifest.json');
    if (!fs.existsSync(source)) {
        console.warn('   ⚠️  manifest.json not found, skipping per-locale manifests');
        return [];
    }
    const base = readJson(source);
    const absolutize = (value) => (typeof value === 'string' && value.startsWith('./') ? value.slice(1) : value);
    const written = [];

    for (const code of site.locales) {
        if (code === site.defaultLocale) continue;
        const locale = site.byCode[code];
        const manifest = {
            ...base,
            lang: locale.htmlLang,
            dir: locale.dir,
            start_url: `/${code}/`,
            scope: '/',
            icons: (base.icons || []).map((icon) => ({ ...icon, src: absolutize(icon.src) })),
        };
        if (Array.isArray(base.screenshots)) {
            manifest.screenshots = base.screenshots.map((shot) => ({ ...shot, src: absolutize(shot.src) }));
        }
        if (Array.isArray(base.shortcuts)) {
            manifest.shortcuts = base.shortcuts.map((cut) => ({
                ...cut,
                url: cut.url && cut.url.startsWith('./') ? `/${code}/${cut.url.slice(2)}` : cut.url,
                icons: (cut.icons || []).map((icon) => ({ ...icon, src: absolutize(icon.src) })),
            }));
        }
        if (locale.manifest) {
            for (const key of ['name', 'short_name', 'description']) {
                if (locale.manifest[key]) manifest[key] = locale.manifest[key];
            }
        }

        const dest = path.join(OUT_ROOT, code, 'manifest.json');
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.writeFileSync(dest, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8');
        written.push(path.relative(OUT_ROOT, dest));
    }
    return written;
}

/**
 * Stamp the locale list into sw.js. The Service Worker caches by exact path, so it has
 * to know which subdirectories are app shells; hard-coding the list in two places is
 * how it would eventually go out of step with locales/site.json.
 */
function stampServiceWorker(site) {
    const source = path.join(ROOT, 'sw.js');
    const dest = path.join(OUT_ROOT, 'sw.js');
    if (!fs.existsSync(source)) return [];
    const marker = /const SW_LOCALES = \[[^\]]*\];/;
    const sw = read(source);
    if (!marker.test(sw)) {
        console.warn('   ⚠️  SW_LOCALES marker not found in sw.js — locale shells will not be cached');
        return [];
    }
    const secondary = site.locales.filter((code) => code !== site.defaultLocale);
    const next = sw.replace(marker, `const SW_LOCALES = [${secondary.map((c) => `'${c}'`).join(', ')}];`);
    // Rendering into a scratch directory must never write back over the real sw.js.
    if (next === sw && dest === source) return [];
    fs.writeFileSync(dest, next, 'utf8');
    return ['sw.js'];
}

/**
 * Rewrite the generated block between BEGIN/END markers in a served-config file.
 * Both web server configs need to know the locale list, and a list kept by hand in
 * three files is a list that drifts.
 */
function stampConfig(site, relPath, renderLines) {
    const source = path.join(ROOT, relPath);
    const dest = path.join(OUT_ROOT, relPath);
    if (!fs.existsSync(source)) return [];
    const text = read(source);
    const region = /([ \t]*)# BEGIN generated locale shells\n[\s\S]*?[ \t]*# END generated locale shells/;
    const match = text.match(region);
    if (!match) {
        console.warn(`   ⚠️  locale-shell markers not found in ${relPath}`);
        return [];
    }
    const indent = match[1];
    const secondary = site.locales.filter((code) => code !== site.defaultLocale);
    const body = renderLines(secondary)
        .map((line) => `${indent}${line}`)
        .join('\n');
    const replacement = [
        `${indent}# BEGIN generated locale shells`,
        ...(body ? [body] : []),
        `${indent}# END generated locale shells`,
    ].join('\n');
    const next = text.replace(region, replacement);
    if (next === text && dest === source) return [];
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, next, 'utf8');
    return [relPath];
}

function stampServerConfigs(site) {
    return [
        // One plain regex per locale rather than one clever one: a named capture or an
        // alternation that nginx rejects takes the whole site down at boot, and this
        // file cannot be syntax-checked without nginx present.
        ...stampConfig(site, 'deploy/nginx.conf', (codes) =>
            codes.map((code) => `~^/${code}/  /${code}/index.html;`)
        ),
        ...stampConfig(site, '.htaccess', (codes) =>
            codes.flatMap((code) => [
                'RewriteCond %{REQUEST_FILENAME} !-f',
                'RewriteCond %{REQUEST_FILENAME} !-d',
                `RewriteRule ^${code}(/.*)?$ /${code}/index.html [L]`,
            ])
        ),
    ];
}

/**
 * Emit the locale registry and UI dictionaries as a plain ES module.
 *
 * The strings live in locales/*.json next to the SEO copy, so a translator edits one
 * file per language rather than two. They reach the app through a generated module
 * instead of a direct JSON import: esbuild would handle the import, but the Node test
 * runner needs import attributes for it, and a generated .js file works in both
 * without anyone having to remember which.
 */
function buildDictionaries(site) {
    const meta = {};
    const dictionaries = {};
    for (const code of site.locales) {
        const locale = site.byCode[code];
        meta[code] = {
            htmlLang: locale.htmlLang,
            nativeName: locale.nativeName,
            // Short form for the switcher, which shows a code rather than a full name
            // so nine languages fit without crowding the header.
            abbr: locale.abbr || code.toUpperCase(),
            dir: locale.dir || 'ltr',
            path: code === site.defaultLocale ? '/' : `/${code}/`,
        };
        dictionaries[code] = locale.ui || {};
    }

    const body = `// Generated by scripts/build-i18n.js from locales/*.json — do not edit by hand.
// Add or change strings in locales/<code>.json, then run \`npm run build:i18n\`.

export const DEFAULT_LOCALE = ${JSON.stringify(site.defaultLocale)};
export const SUPPORTED_LOCALES = ${JSON.stringify(site.locales)};
export const LOCALE_META = ${JSON.stringify(meta, null, 4)};
export const DICTIONARIES = ${JSON.stringify(dictionaries, null, 4)};
`;

    const dest = path.join(OUT_ROOT, 'src', 'i18n', 'generated.js');
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.writeFileSync(dest, body, 'utf8');
    return [path.relative(OUT_ROOT, dest)];
}

function buildSitemap(site) {
    const entries = site.locales
        .map((code) => {
            const alternates = site.locales.length < 2
                ? ''
                : '\n' + site.locales
                    .map((other) => `        <xhtml:link rel="alternate" hreflang="${attr(site.byCode[other].htmlLang)}" href="${attr(localeUrl(site, other))}"/>`)
                    .join('\n')
                  + `\n        <xhtml:link rel="alternate" hreflang="x-default" href="${attr(localeUrl(site, site.defaultLocale))}"/>`;
            return `    <url>
        <loc>${attr(localeUrl(site, code))}</loc>${alternates}
        <changefreq>weekly</changefreq>
        <priority>1.0</priority>
    </url>`;
        })
        .join('\n');

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
${entries}
</urlset>
`;
    fs.writeFileSync(path.join(OUT_ROOT, 'sitemap.xml'), xml, 'utf8');
    return 'sitemap.xml';
}

function buildRobots(site) {
    // Nothing is disallowed on purpose. The app is client-rendered, so a crawler has
    // to fetch the very CSS and JS under /src/, /dist/ and /libs/ in order to see any
    // content at all — blocking them would leave Google looking at an empty <div>.
    const txt = `# SecureBit.chat — generated by scripts/build-i18n.js, do not edit by hand.
User-agent: *
Allow: /

# Repository files that ship in the image but are not part of the site.
Disallow: /tests/
Disallow: /doc/

Sitemap: ${site.baseUrl}/sitemap.xml
`;
    fs.writeFileSync(path.join(OUT_ROOT, 'robots.txt'), txt, 'utf8');
    return 'robots.txt';
}

function main() {
    console.log('🌍 Generating localized pages...');
    const site = loadSite();
    const template = read(TEMPLATE);
    const version = buildVersion();

    const written = [
        ...buildPages(site, template, version),
        ...buildManifests(site),
        ...buildDictionaries(site),
        ...stampServiceWorker(site),
        ...stampServerConfigs(site),
        buildSitemap(site),
        buildRobots(site),
    ];

    console.log(`   Locales: ${site.locales.join(', ')} (default: ${site.defaultLocale})`);
    console.log(`   Build version: ${version}`);
    for (const file of written) console.log(`   ✅ ${file}`);
    console.log('✅ i18n page generation completed');
}

if (require.main === module) {
    try {
        main();
    } catch (error) {
        console.error('❌ i18n build failed:', error.message);
        process.exit(1);
    }
}

module.exports = { loadSite, buildManifests, localeUrl, outputPath, hreflangLinks, structuredData, render };
