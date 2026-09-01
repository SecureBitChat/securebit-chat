// The language bar is the safe half of "show the visitor their own language". The unsafe
// half — redirecting on navigator.language — is invisible from a browser and fatal for
// the twelve translated pages: a crawler asking for /de/ with an English Accept-Language
// would be handed the English document, so no locale but one ever gets indexed, and the
// hreflang cluster in every page would describe URLs that do not serve what they claim.
//
// These assertions exist because that redirect is a two-line change someone will
// eventually be tempted to make.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');
const suggestion = read('src/components/ui/LanguageSuggestion.jsx');
const app = read('src/app.jsx');
const i18n = read('src/i18n/index.js');

// ── No automatic navigation, anywhere in the locale path ───────────────────────────────
for (const [name, source] of [['the bar', suggestion], ['the i18n module', i18n]]) {
    for (const forbidden of [/location\s*\.\s*replace\s*\(/, /location\s*\.\s*assign\s*\(/, /location\s*\.\s*href\s*=/, /window\.location\s*=/]) {
        assert.equal(forbidden.test(source), false,
            `${name} must never navigate on its own — an automatic locale redirect leaves every other locale unindexed`);
    }
}
assert.equal(/preventDefault/.test(suggestion), false,
    'the offer must be an ordinary link the browser follows, not an intercepted click');
assert.match(suggestion, /React\.createElement\('a',/, 'the offer must be an anchor');
assert.match(suggestion, /href,/, 'the anchor needs a real href a crawler could follow');

// ── It is an offer, and only when there is something to offer ──────────────────────────
assert.match(suggestion, /suggestedLocale\(/,
    'the bar must ask suggestedLocale, which returns null when the page already matches');
assert.match(suggestion, /if \(!target \|\| gone\) return null;/,
    'nothing renders when the visitor is already on the right locale');
assert.match(suggestion, /localeSuggestionDismissed\(\)/, 'a past dismissal must suppress the bar');
assert.match(suggestion, /dismissLocaleSuggestion\(\)/, 'dismissing must be remembered');

// ── The copy is in the language being offered ──────────────────────────────────────────
// Someone on the English page whose browser is Arabic cannot read an English offer.
for (const key of ['language.suggest.text', 'language.suggest.cta', 'language.suggest.dismiss']) {
    assert.match(suggestion, new RegExp(`t\\('${key.replace(/\./g, '\\.')}', null, target\\)`),
        `${key} must be rendered in the offered locale, not the page's`);
}
assert.match(suggestion, /lang: meta\.htmlLang \|\| target/, 'the bar must declare its own language');
assert.match(suggestion, /dir,/, 'an RTL offer on an LTR page needs its own direction');

// ── Landing only, like the switcher ────────────────────────────────────────────────────
assert.match(app, /\(!isConnectedAndVerified && !showSidebar\) && React\.createElement\(LanguageSuggestion/,
    'following the link navigates, which would drop a live peer connection mid-session');
assert.match(app, /import \{ LanguageSuggestion \} from '\.\/components\/ui\/LanguageSuggestion\.jsx';/);

// ── Every locale carries the three strings ─────────────────────────────────────────────
{
    const site = JSON.parse(read('locales/site.json'));
    for (const code of site.locales) {
        const ui = JSON.parse(read(`locales/${code}.json`)).ui;
        for (const key of ['language.suggest.text', 'language.suggest.cta', 'language.suggest.dismiss']) {
            const value = ui[key];
            assert.ok(value && value.trim(), `locales/${code}.json is missing ${key}`);
            // A translation left in English would defeat the point: the offer is read by
            // someone who does not read the page it appears on.
            if (code !== 'en') {
                assert.notEqual(value, JSON.parse(read('locales/en.json')).ui[key],
                    `locales/${code}.json: ${key} is still the English string`);
            }
        }
    }
}

// ── The dismissal survives, and a blocked storage does not throw ───────────────────────
{
    const dom = new JSDOM('', { url: 'https://securebit.chat/' });
    global.window = dom.window;
    global.localStorage = dom.window.localStorage;
    const mod = await import('../src/i18n/index.js');

    assert.equal(mod.localeSuggestionDismissed(), false, 'nothing dismissed on a first visit');
    mod.dismissLocaleSuggestion();
    assert.equal(mod.localeSuggestionDismissed(), true, 'a dismissal must be remembered');

    // Private mode: reads and writes throw, and neither may take the caller with it.
    const throwing = { getItem() { throw new Error('blocked'); }, setItem() { throw new Error('blocked'); } };
    Object.defineProperty(dom.window, 'localStorage', { value: throwing, configurable: true });
    global.localStorage = throwing;
    assert.equal(mod.localeSuggestionDismissed(), false, 'blocked storage reads as "not dismissed"');
    mod.dismissLocaleSuggestion();
}

// ── The offer is computed from the browser's languages, and only when it differs ───────
{
    const mod = await import('../src/i18n/index.js');
    assert.equal(mod.suggestedLocale({ pathname: '/', languages: ['de-DE', 'en'] }), 'de');
    assert.equal(mod.suggestedLocale({ pathname: '/de/', languages: ['de-DE'] }), null);
    assert.equal(mod.suggestedLocale({ pathname: '/', languages: ['en-US'] }), null);
    // A crawler sends no languages at all: it must see no offer and, above all, no move.
    assert.equal(mod.suggestedLocale({ pathname: '/ru/', languages: [] }), null);
}

console.log('language-suggestion.test.mjs: all assertions passed');
