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
    mkdirSync(tmp, { recursive: true });
    writeFileSync(path.join(tmp, 'generated.js'), `
export const DEFAULT_LOCALE = "en";
export const SUPPORTED_LOCALES = ["en", "de"];
export const LOCALE_META = {
    en: { htmlLang: "en", nativeName: "English", dir: "ltr", path: "/" },
    de: { htmlLang: "de", nativeName: "Deutsch", dir: "ltr", path: "/de/" }
};
export const DICTIONARIES = {
    en: { "greeting": "Hello", "only.en": "English only", "welcome": "Hello, {name}" },
    de: { "greeting": "Hallo" }
};
`);
    copyFileSync(path.join(ROOT, 'src/i18n/index.js'), path.join(tmp, 'index.js'));
    const i18n = await import(pathToFileURL(path.join(tmp, 'index.js')));

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

    rmSync(tmp, { recursive: true, force: true });
}

console.log('i18n-runtime.test.mjs: all assertions passed');
