// What is worth pinning down here is precedence, not lookup. Get the order wrong and
// the bugs are the quiet kind: a shared /de/ link that opens in English because the
// recipient once picked English, or a visitor bounced away from the page they asked
// for. Both look like "the language switcher works" until someone shares a link.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// The committed generated.js must match what the generator produces, or the strings
// the app ships are not the strings in locales/.
{
    const before = readFileSync(path.join(ROOT, 'src/i18n/generated.js'), 'utf8');
    execFileSync('node', [path.join(ROOT, 'scripts/build-i18n.js')], { stdio: 'pipe' });
    assert.equal(
        readFileSync(path.join(ROOT, 'src/i18n/generated.js'), 'utf8'), before,
        'src/i18n/generated.js is stale — run `npm run build:i18n` after editing locales/'
    );
}

// A dictionary has to reach the page that needs it — and only that page.
//
// Every locale used to be bundled into dist/app.js, into dist/app-boot.js, and fetched
// a third time as raw source by the page modules that import the runtime directly: 215 KB
// transferred to hand a Russian reader twelve dictionaries they will never read. Now the
// default locale is bundled (t() falls back to it) and each other locale is a module its
// own shell loads. Both halves of that are pinned here, because either one failing is
// silent: bundling them all again only shows up as a slow page, and dropping the shell's
// script only shows up as an English page under a Russian <html lang>.
{
    const bundle = readFileSync(path.join(ROOT, 'dist/app.js'), 'utf8');
    const { DEFAULT_LOCALE, SUPPORTED_LOCALES } = await import(
        pathToFileURL(path.join(ROOT, 'src/i18n/generated.js'))
    );
    const dictOf = async (code) => (await import(
        pathToFileURL(path.join(ROOT, `src/i18n/dict/${code}.js`))
    )).DICTIONARY;

    // esbuild escapes anything outside ASCII, so nothing but pure Latin is findable as
    // literal text: Latin-1 becomes \xNN, everything above it \uXXXX, both uppercase.
    // Escape the needle the same way before looking for it.
    const asEmitted = (text) =>
        [...text]
            .map((ch) => {
                const code = ch.codePointAt(0);
                if (code < 0x80) return ch;
                const hex = (n, width) => n.toString(16).toUpperCase().padStart(width, '0');
                if (code <= 0xff) return `\\x${hex(code, 2)}`;
                return [...ch].map((unit) => `\\u${hex(unit.charCodeAt(0), 4)}`).join('');
            })
            .join('');

    const headlineOf = async (code) => (await dictOf(code))['hero.headlineTop'];

    assert.ok(bundle.includes(asEmitted(await headlineOf(DEFAULT_LOCALE))),
        `dist/app.js carries no strings for the default locale — run \`npm run build\`, ` +
        'and check that build:i18n still runs before build:js');

    // The saving is the assertion. If another locale turns up in the bundle, something
    // has started importing dictionaries statically again and the page grew by 200 KB.
    for (const code of SUPPORTED_LOCALES.filter((c) => c !== DEFAULT_LOCALE)) {
        assert.equal(bundle.includes(asEmitted(await headlineOf(code))), false,
            `dist/app.js bundles the ${code} dictionary — only the default locale belongs in it`);
    }

    // ...and each of those locales must still reach its own page.
    const site = JSON.parse(readFileSync(path.join(ROOT, 'locales/site.json'), 'utf8'));
    for (const code of SUPPORTED_LOCALES) {
        const shell = readFileSync(
            path.join(ROOT, code === site.defaultLocale ? 'index.html' : `${code}/index.html`), 'utf8'
        );
        const tag = `src="/src/i18n/dict/${code}.js`;
        if (code === site.defaultLocale) {
            assert.equal(shell.includes('/src/i18n/dict/'), false,
                'the default locale already has its dictionary in the bundle; loading it again is dead weight');
        } else {
            assert.ok(shell.includes(tag), `${code}/index.html never loads its own dictionary`);
            // It has to run before anything that asks for a string.
            assert.ok(shell.indexOf(tag) < shell.indexOf('/dist/app-boot.js'),
                `${code}/index.html loads its dictionary after the app that reads it`);
        }
    }

    // The registry has to survive into the bundle as a whole list, not just as loose
    // strings the assertion above would also accept. What it must NOT depend on is the
    // shape esbuild emits: --minify drops the spaces after the commas and renames the
    // binding, so match the array literal in either spelling and never the variable
    // name — otherwise turning minification on reads as a missing locale.
    const registry = JSON.stringify(SUPPORTED_LOCALES);
    assert.ok(bundle.includes(registry) || bundle.includes(registry.replace(/,/g, ', ')),
        'the bundled locale registry disagrees with src/i18n/generated.js');
}

// The real module, as shipped.
{
    const live = await import(pathToFileURL(path.join(ROOT, 'src/i18n/index.js')));
    assert.ok(live.SUPPORTED_LOCALES.includes(live.DEFAULT_LOCALE));
    assert.equal(live.t('language.label'), 'Language');
    assert.equal(live.t('no.such.key'), 'no.such.key', 'a missing key should show itself, not blank UI');
    assert.equal(live.t('community.title'), 'Join the future of privacy');
}

// A window without the parts this reads is a real environment, not a hypothetical one:
// test harnesses and workers both provide partial shims. Reading through them blindly
// threw, and since t() runs inside constructors, one missing property took whole
// components down rather than just showing an untranslated string.
{
    const saved = globalThis.window;
    try {
        globalThis.window = {};                       // no location, no navigator
        const tmp = mkdtempSync(path.join(tmpdir(), 'sb-i18n-win-'));
        copyFileSync(path.join(ROOT, 'src/i18n/generated.js'), path.join(tmp, 'generated.js'));
        copyFileSync(path.join(ROOT, 'src/i18n/index.js'), path.join(tmp, 'index.js'));
        // index.js imports its default dictionary for the fallback, so a copy of the
        // module is only a working copy if that comes with it.
        const { DEFAULT_LOCALE: fallbackLocale } = await import(
            pathToFileURL(path.join(ROOT, 'src/i18n/generated.js'))
        );
        mkdirSync(path.join(tmp, 'dict'), { recursive: true });
        for (const name of ['default.js', `${fallbackLocale}.js`]) {
            copyFileSync(path.join(ROOT, 'src/i18n/dict', name), path.join(tmp, 'dict', name));
        }
        const partial = await import(pathToFileURL(path.join(tmp, 'index.js')));
        assert.equal(partial.currentLocale(), partial.DEFAULT_LOCALE,
            'a window without location must fall back to the default locale, not throw');
        assert.equal(typeof partial.t('language.label'), 'string');
        rmSync(tmp, { recursive: true, force: true });
    } finally {
        if (saved === undefined) delete globalThis.window;
        else globalThis.window = saved;
    }
}

// Precedence only becomes visible with more than one locale, so build a two-locale
// copy of the module in a temp directory and exercise it there.
{
    const tmp = mkdtempSync(path.join(tmpdir(), 'sb-i18n-rt-'));
    mkdirSync(path.join(tmp, 'dict'), { recursive: true });
    writeFileSync(path.join(tmp, 'generated.js'), `
export const DEFAULT_LOCALE = "en";
export const SUPPORTED_LOCALES = ["en", "de"];
export const LOCALE_META = {
    en: { htmlLang: "en", nativeName: "English", dir: "ltr", path: "/" },
    de: { htmlLang: "de", nativeName: "Deutsch", dir: "ltr", path: "/de/" }
};
export const CROSS_LOCALE_STRINGS = { en: {}, de: { "language.suggest.cta": "Auf Deutsch lesen" } };
`);
    // Dictionaries register themselves on a global, the same way the generated ones do.
    const fixtureDict = (code, entries) => writeFileSync(path.join(tmp, 'dict', `${code}.js`), `
export const DICTIONARY = ${JSON.stringify(entries)};
const registry = globalThis.__SECUREBIT_I18N__ || (globalThis.__SECUREBIT_I18N__ = Object.create(null));
registry[${JSON.stringify(code)}] = DICTIONARY;
`);
    fixtureDict('en', { greeting: 'Hello', 'only.en': 'English only', welcome: 'Hello, {name}' });
    fixtureDict('de', { greeting: 'Hallo' });
    writeFileSync(path.join(tmp, 'dict', 'default.js'), 'import "./en.js";\n');
    copyFileSync(path.join(ROOT, 'src/i18n/index.js'), path.join(tmp, 'index.js'));

    // That global is shared with the real module imported earlier in this file, so the
    // fixture is swapped in around this block rather than left to overwrite it.
    const savedRegistry = globalThis.__SECUREBIT_I18N__;
    globalThis.__SECUREBIT_I18N__ = Object.create(null);
    const i18n = await import(pathToFileURL(path.join(tmp, 'index.js')));
    // The German dictionary is one the fixture's page would have loaded for itself.
    await import(pathToFileURL(path.join(tmp, 'dict', 'de.js')));

    // Reading a path.
    assert.equal(i18n.localeFromPathname('/de/'), 'de');
    assert.equal(i18n.localeFromPathname('/de/anything'), 'de');
    assert.equal(i18n.localeFromPathname('/'), null);
    assert.equal(i18n.localeFromPathname('/deutschland/'), null, 'a prefix match is not a locale match');

    // Browser languages, full tag then base tag, in the browser's own order.
    assert.equal(i18n.localeFromLanguages(['de-AT', 'en-US']), 'de');
    assert.equal(i18n.localeFromLanguages(['fr-FR', 'de']), 'de');
    assert.equal(i18n.localeFromLanguages(['fr', 'ja']), null);

    // The URL outranks everything. This is what keeps a shared link shareable.
    assert.equal(
        i18n.detectLocale({ pathname: '/de/', stored: 'en', languages: ['en-US'] }), 'de',
        'a /de/ URL must render German even for someone who once chose English'
    );

    // The root is the default locale's own page, not a blank slate: honour a stored
    // choice or the browser there, but never treat it as "no locale".
    assert.equal(i18n.detectLocale({ pathname: '/', stored: 'de', languages: ['en'] }), 'en',
        'the root URL is the default locale, so it must not silently render another one');
    assert.equal(i18n.detectLocale({ pathname: '/somewhere', stored: 'de' }), 'de');
    assert.equal(i18n.detectLocale({ pathname: '/somewhere', languages: ['de-DE'] }), 'de');
    assert.equal(i18n.detectLocale({ pathname: '/somewhere' }), 'en');

    // Switching language keeps you on the page you were reading.
    assert.equal(i18n.localeHref('de', '/'), '/de/');
    assert.equal(i18n.localeHref('de', '/de/'), '/de/');
    assert.equal(i18n.localeHref('en', '/de/'), '/');
    assert.equal(i18n.localeHref('en', '/de/index.html'), '/index.html');
    assert.equal(i18n.localeHref('de', '/index.html'), '/de/index.html');

    // A suggestion, never a redirect: redirecting on Accept-Language sends Googlebot,
    // which crawls from one place, into a single locale and leaves the rest unindexed.
    assert.equal(i18n.suggestedLocale({ pathname: '/', languages: ['de-DE'] }), 'de');
    assert.equal(i18n.suggestedLocale({ pathname: '/de/', languages: ['de-DE'] }), null);
    assert.equal(
        i18n.suggestedLocale({ pathname: '/', stored: 'de', languages: ['en-US'] }), 'de',
        'a past explicit choice is the strongest reason to offer the other page'
    );
    assert.equal(
        i18n.suggestedLocale({ pathname: '/', languages: ['de-DE'], stored: 'en' }), null,
        'an explicit choice of the language already shown outranks the browser list'
    );
    assert.equal(i18n.suggestedLocale({ pathname: '/de/', stored: 'de' }), null);

    // The switcher is a list of real links, each pointing at the same page in another
    // language, each labelled in that language.
    const links = i18n.languageLinks({ pathname: '/de/roadmap', active: 'de' });
    assert.deepEqual(links.map((l) => l.code), ['en', 'de']);
    assert.deepEqual(links.map((l) => l.href), ['/roadmap', '/de/roadmap']);
    assert.deepEqual(links.map((l) => l.label), ['English', 'Deutsch']);
    assert.deepEqual(links.map((l) => l.isCurrent), [false, true]);
    assert.deepEqual(links.map((l) => l.hrefLang), ['en', 'de']);

    // Lookup falls back to the default locale before it falls back to the key.
    assert.equal(i18n.t('greeting', null, 'de'), 'Hallo');
    assert.equal(i18n.t('only.en', null, 'de'), 'English only', 'an untranslated string shows English, not blank');
    assert.equal(i18n.t('missing', null, 'de'), 'missing');
    assert.equal(i18n.t('welcome', { name: 'Ada' }, 'en'), 'Hello, Ada');
    assert.equal(i18n.t('welcome', {}, 'en'), 'Hello, {name}', 'an absent variable stays literal rather than blank');

    // A locale whose dictionary this page never loaded still answers for the handful of
    // keys the language suggestion needs, and falls back to the default for the rest.
    assert.equal(i18n.t('language.suggest.cta', null, 'de'), 'Auf Deutsch lesen',
        'the suggestion bar must speak the language it is offering');

    globalThis.__SECUREBIT_I18N__ = savedRegistry;
    rmSync(tmp, { recursive: true, force: true });
}

console.log('i18n-runtime.test.mjs: all assertions passed');
