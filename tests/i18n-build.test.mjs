// The localized pages are generated, so the thing worth asserting is not their
// content but the invariants a generator can silently break: that the committed
// HTML is what the template actually produces, that every locale carries its own
// canonical rather than pointing at the default one, and that the hreflang cluster
// is complete. A canonical that points elsewhere tells Google not to index the page
// at all, which is the exact opposite of why the locale exists.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

const site = JSON.parse(read('locales/site.json'));
const localeFile = (code) => JSON.parse(read(`locales/${code}.json`));
const pageFor = (code) => (code === site.defaultLocale ? 'index.html' : `${code}/index.html`);
const urlFor = (code) => (code === site.defaultLocale ? `${site.baseUrl}/` : `${site.baseUrl}/${code}/`);

// Every locale in the registry must have a file and a generated page.
{
    assert.ok(site.locales.includes(site.defaultLocale), 'defaultLocale must be listed in locales');
    for (const code of site.locales) {
        assert.ok(existsSync(path.join(ROOT, `locales/${code}.json`)), `locales/${code}.json is missing`);
        assert.ok(existsSync(path.join(ROOT, pageFor(code))), `${pageFor(code)} was never generated`);
    }
}

// The committed pages must be exactly what the generator produces. If someone edits
// index.html by hand the change is lost on the next build, so catch it here instead.
{
    const before = Object.fromEntries(site.locales.map((code) => [code, read(pageFor(code))]));
    execFileSync('node', [path.join(ROOT, 'scripts/build-i18n.js')], { stdio: 'pipe' });
    for (const code of site.locales) {
        assert.equal(
            read(pageFor(code)), before[code],
            `${pageFor(code)} is not what scripts/build-i18n.js generates — edit templates/ or locales/, then run \`npm run build:i18n\``
        );
    }
}

// Per-locale SEO identity.
for (const code of site.locales) {
    const html = read(pageFor(code));
    const locale = localeFile(code);

    assert.match(html, new RegExp(`<html lang="${locale.htmlLang}" dir="${locale.dir}">`), `${code}: wrong <html lang>/<html dir>`);
    assert.ok(
        html.includes(`<link rel="canonical" href="${urlFor(code)}">`),
        `${code}: canonical must point at its own URL, not another locale's`
    );
    assert.ok(html.includes(`<title>${locale.meta.title}</title>`), `${code}: title not from the locale file`);
    assert.ok(html.includes(`content="${locale.ogLocale}"`), `${code}: og:locale missing`);

    // The structured data must describe this page in this language.
    const ld = JSON.parse(html.match(/application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
    const app = ld['@graph'].find((node) => node['@type'] === 'WebApplication');
    assert.equal(app.inLanguage, locale.htmlLang, `${code}: JSON-LD inLanguage disagrees with the page`);
    assert.equal(app.url, urlFor(code), `${code}: JSON-LD url disagrees with the canonical`);

    // A hreflang cluster only counts if every page lists every page, itself included.
    if (site.locales.length > 1) {
        for (const other of site.locales) {
            const lang = localeFile(other).htmlLang;
            assert.ok(
                html.includes(`hreflang="${lang}" href="${urlFor(other)}"`),
                `${code}: hreflang cluster is missing ${other}`
            );
        }
        assert.ok(html.includes('hreflang="x-default"'), `${code}: x-default is missing`);
    }
}

// robots.txt must not block what the crawler needs to render the page. The app is
// client-rendered: block /src/ or /dist/ and Google sees an empty <div id="root">.
{
    const robots = read('robots.txt');
    assert.ok(robots.includes(`Sitemap: ${site.baseUrl}/sitemap.xml`), 'robots.txt must advertise the sitemap');
    for (const critical of ['/src/', '/dist/', '/libs/', '/assets/', '/config/']) {
        assert.equal(
            robots.includes(`Disallow: ${critical}`), false,
            `robots.txt disallows ${critical}, which the page needs in order to render for a crawler`
        );
    }
}

// The sitemap must list every locale exactly once.
{
    const sitemap = read('sitemap.xml');
    for (const code of site.locales) {
        const loc = `<loc>${urlFor(code)}</loc>`;
        assert.equal(sitemap.split(loc).length - 1, 1, `sitemap.xml must list ${urlFor(code)} exactly once`);
    }
    assert.equal(
        (sitemap.match(/<url>/g) || []).length, site.locales.length,
        'sitemap.xml has entries for URLs that are not locales'
    );
}

// Every shell must carry the same build stamp. scripts/build-i18n.js fills in ?v= from
// meta.json, but meta.json is regenerated afterwards by post-build.js — which for a
// while re-stamped only the root page, leaving the localized ones pointing at the
// previous build.
{
    const stamps = new Map();
    for (const code of site.locales) {
        const found = [...new Set(read(pageFor(code)).match(/\?v=[0-9A-Z_]+/g) || [])];
        assert.equal(found.length, 1, `${pageFor(code)} carries more than one build stamp: ${found.join(', ')}`);
        stamps.set(code, found[0]);
    }
    const distinct = new Set(stamps.values());
    assert.equal(
        distinct.size, 1,
        `the app shells disagree on the build stamp: ${[...stamps].map(([c, v]) => `${c}=${v}`).join(', ')}`
    );
    const meta = JSON.parse(read('meta.json'));
    assert.equal([...distinct][0], `?v=${meta.version}`, 'the shells are stamped with a version other than meta.json');
}

// Every key a component asks for must exist, and every key defined must be asked for.
// A typo in t('community.titel') renders the key itself on the page — visible, but only
// to whoever happens to look; and a string nobody uses is a string a translator pays to
// translate. Only files that actually import the module are scanned, so an unrelated
// local function called t() cannot be mistaken for a lookup.
{
    // Match the module however it is reached — app.jsx sits a level up from the
    // components and imports it by a shorter path.
    const sources = execFileSync('grep', ['-rlE', "from '[^']*i18n/index\\.js'", path.join(ROOT, 'src')], {
        encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'],
    }).trim().split('\n').filter(Boolean);

    const used = new Set();
    // Keys built from a template literal — t(`roadmap.${d.k}.title`) — cannot be read
    // literally, so each becomes a pattern and any defined key it matches counts as used.
    const patterns = [];
    for (const file of sources) {
        const text = readFileSync(file, 'utf8');
        for (const match of text.matchAll(/\bt(?:List)?\(\s*['"]([^'"]+)['"]/g)) used.add(match[1]);
        for (const match of text.matchAll(/\bt(?:List)?\(\s*`([^`]+)`/g)) {
            const source = match[1]
                .split(/\$\{[^}]*\}/)
                .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
                .join('.+');   // a key built from a variable may itself contain dots
            patterns.push(new RegExp(`^${source}$`));
        }
    }

    // These dictionaries are the SHARED source for two clients: this one and the
    // Tauri desktop client, which lives in a separate repository and is not
    // scanned here. Its keys are therefore unused *by this scan* and always
    // will be — that is the cost of one dictionary rather than two drifting
    // ones, not a defect to fix by deleting them.
    //
    // The exemption is deliberately narrow: the `desktop.` prefix, plus the
    // message-lifetime labels below by exact name. Anything else that stops
    // being used still fails, which is the point of the check.
    const CONSUMED_BY_DESKTOP = new Set([
        'msg.after5s', 'msg.after15s', 'msg.after30s', 'msg.after1m',
        'msg.sec30', 'msg.min5', 'msg.hour1',
    ]);
    const belongsToDesktop = (key) => key.startsWith('desktop.') || CONSUMED_BY_DESKTOP.has(key);

    const defined = new Set(Object.keys(JSON.parse(read(`locales/${site.defaultLocale}.json`)).ui || {}));
    const isUsed = (key) => used.has(key) || belongsToDesktop(key) || patterns.some((re) => re.test(key));
    const missing = [...used].filter((key) => !defined.has(key)).sort();
    const unused = [...defined].filter((key) => !isUsed(key)).sort();

    assert.deepEqual(missing, [],
        `these keys are used but not defined in locales/${site.defaultLocale}.json — they would render as the key itself`);
    assert.deepEqual(unused, [],
        `these keys are defined but never used — remove them rather than have them translated`);
    assert.ok(used.size > 0, 'the scan found no t() calls at all, which means it is not scanning anything');
    // If the desktop client ever stops sharing these dictionaries, the exemption
    // above turns into a hiding place for dead strings. This fails when that
    // day comes, instead of letting them accumulate unnoticed.
    assert.ok(
        [...defined].some(belongsToDesktop),
        'no desktop-owned keys are defined any more — drop CONSUMED_BY_DESKTOP and the desktop. exemption'
    );
    assert.ok(patterns.length > 0, 'no template-literal keys were found — the dynamic-key scan is not working');
}

// Every locale must define exactly the same keys, or a language silently falls back to
// English in the places its translator missed.
for (const code of site.locales) {
    const base = Object.keys(JSON.parse(read(`locales/${site.defaultLocale}.json`)).ui || {}).sort();
    const theirs = Object.keys(JSON.parse(read(`locales/${code}.json`)).ui || {}).sort();
    assert.deepEqual(theirs, base, `locales/${code}.json does not define the same ui keys as the default locale`);
}

// Most of what the generator does only becomes visible with a second locale, and a
// half-translated locale is not something to add to the live site just to exercise
// the code. So render a throwaway two-locale site into a temp directory instead.
{
    const tmp = mkdtempSync(path.join(tmpdir(), 'sb-i18n-'));
    const localesDir = path.join(tmp, 'locales');
    const outRoot = path.join(tmp, 'out');
    mkdirSync(localesDir, { recursive: true });
    mkdirSync(outRoot, { recursive: true });

    const en = JSON.parse(read('locales/en.json'));
    const xx = JSON.parse(JSON.stringify(en));
    // Right-to-left on purpose: direction is carried from the locale file all the way
    // into <html dir> and the per-locale manifest, and the throwaway site is where that
    // plumbing can be exercised without a real RTL locale having to be the one under test.
    Object.assign(xx, { htmlLang: 'xx', ogLocale: 'xx_XX', nativeName: 'Test', dir: 'rtl' });
    xx.manifest = { name: 'XX name', short_name: 'XX', description: 'XX description' };
    writeFileSync(path.join(localesDir, 'en.json'), JSON.stringify(en, null, 2));
    writeFileSync(path.join(localesDir, 'xx.json'), JSON.stringify(xx, null, 2));
    writeFileSync(
        path.join(localesDir, 'site.json'),
        JSON.stringify({ ...site, locales: ['en', 'xx'] }, null, 2)
    );

    execFileSync('node', [path.join(ROOT, 'scripts/build-i18n.js')], {
        stdio: 'pipe',
        env: { ...process.env, I18N_LOCALES_DIR: localesDir, I18N_OUT_ROOT: outRoot },
    });

    const at = (rel) => readFileSync(path.join(outRoot, rel), 'utf8');
    const secondary = at('xx/index.html');
    const primary = at('index.html');

    // The secondary locale points at itself, not at the default one.
    assert.ok(secondary.includes('<link rel="canonical" href="https://securebit.chat/xx/">'),
        'a secondary locale must be canonical to itself, or Google will not index it');
    assert.match(secondary, /<html lang="xx" dir="rtl">/,
        'the locale\'s writing direction must be on <html>, not applied later by the app');
    assert.match(primary, /<html lang="en" dir="ltr">/,
        'a left-to-right locale must still say so explicitly');

    // hreflang has to be reciprocal: both pages list both locales plus x-default.
    for (const page of [primary, secondary]) {
        assert.ok(page.includes('hreflang="en" href="https://securebit.chat/"'));
        assert.ok(page.includes('hreflang="xx" href="https://securebit.chat/xx/"'));
        assert.ok(page.includes('hreflang="x-default" href="https://securebit.chat/"'));
    }
    assert.ok(secondary.includes('<meta property="og:locale:alternate" content="en_US">'));

    // Nothing on a subdirectory page may use a relative asset path: "src/app.js" from
    // /xx/ resolves to /xx/src/app.js and 404s. CSP forbids <base>, so absolute is the
    // only option available.
    const relative = [...secondary.matchAll(/\b(?:src|href)="(?!https?:|data:|#|\/)([^"]+)"/g)];
    assert.deepEqual(relative.map((m) => m[1]), [],
        'subdirectory pages must reference every asset with a root-absolute path');

    // The locale needs its own manifest: the root one resolves "./" against itself.
    assert.ok(secondary.includes('<link rel="manifest" href="/xx/manifest.json">'));
    const manifest = JSON.parse(at('xx/manifest.json'));
    assert.equal(manifest.lang, 'xx');
    assert.equal(manifest.dir, 'rtl', 'an installed RTL locale must launch right-to-left');
    assert.equal(manifest.start_url, '/xx/', 'an installed locale must launch into its own page');
    assert.equal(manifest.scope, '/', 'scope must still cover the whole site');
    assert.equal(manifest.name, 'XX name', 'manifest name should come from the locale file');
    for (const icon of manifest.icons) {
        assert.ok(icon.src.startsWith('/'), `manifest icon ${icon.src} would resolve under /xx/`);
    }

    // The Service Worker caches by exact path, so it needs the locale list stamped in;
    // without it a localized page has no shell to fall back to when offline.
    const sw = at('sw.js');
    assert.ok(sw.includes("const SW_LOCALES = ['xx'];"),
        'scripts/build-i18n.js must stamp the secondary locales into sw.js');
    assert.ok(sw.includes('LOCALE_SHELLS'), 'sw.js lost the localized-shell wiring');

    // Both served configs must route deep links inside a locale to that locale's shell.
    const nginx = at('deploy/nginx.conf');
    assert.ok(nginx.includes('~^/xx/  /xx/index.html;'), 'nginx.conf lost its locale shell entry');
    assert.ok(nginx.includes('try_files $uri $uri/ $sb_shell;'), 'nginx.conf must use the shell map');
    const htaccess = at('.htaccess');
    assert.ok(htaccess.includes('RewriteRule ^xx(/.*)?$ /xx/index.html [L]'), '.htaccess lost its locale rewrite');

    // The sitemap must carry the alternates too, not just the URLs.
    const sitemap = at('sitemap.xml');
    assert.equal((sitemap.match(/<url>/g) || []).length, 2);
    assert.ok(sitemap.includes('<xhtml:link rel="alternate" hreflang="xx" href="https://securebit.chat/xx/"/>'));

    rmSync(tmp, { recursive: true, force: true });
}

console.log('i18n-build.test.mjs: all assertions passed');
