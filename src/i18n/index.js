/**
 * Language selection and string lookup.
 *
 * Every locale is a real page at a real URL (/, /de/, ...), generated at build time,
 * because the app is client-rendered: a language that exists only as a runtime string
 * swap has no URL for a crawler to index. This module is the runtime half — it decides
 * which locale the current page is, and hands components their strings.
 *
 * The rule that matters: the URL wins over everything. Someone who opens /de/ gets
 * German even if they once chose English here, or a shared link would open in whatever
 * language the recipient happened to pick last, which makes links unshareable.
 */

import { DEFAULT_LOCALE, SUPPORTED_LOCALES, LOCALE_META, CROSS_LOCALE_STRINGS } from './generated.js';
// Side-effect import: loading the default locale's dictionary registers the strings
// t() falls back to when a translation is missing a key. It is the one dictionary that
// has to be present on every page, so it is the one that gets bundled.
import './dict/default.js';

export { DEFAULT_LOCALE, SUPPORTED_LOCALES, LOCALE_META };

/**
 * Loaded dictionaries, by locale code.
 *
 * On a global rather than in module scope, and that is the point. index.js exists twice
 * on a page: once bundled inside dist/app.js, and once as raw source, because the PWA
 * install prompt, the PWA manager and the update checker import it directly. Two module
 * instances mean two module-scoped registries, and the /ru/ dictionary loaded by the
 * page would have been invisible to the half of the app that needed it.
 *
 * A page loads its own dictionary through a <script type="module"> that runs before the
 * bundles; every locale other than the default arrives that way. See scripts/build-i18n.js.
 */
const REGISTRY = globalThis.__SECUREBIT_I18N__ || (globalThis.__SECUREBIT_I18N__ = Object.create(null));

/** The dictionary for a locale, or an empty one if that locale was never loaded. */
function dictionary(code) {
    return REGISTRY[code] || null;
}

const STORAGE_KEY = 'securebit-locale';

/** The locale a path belongs to, or null for the default locale at the root. */
export function localeFromPathname(pathname = '/') {
    const segment = String(pathname).split('/')[1];
    return SUPPORTED_LOCALES.includes(segment) && segment !== DEFAULT_LOCALE ? segment : null;
}

/**
 * Best match for a browser's language list. "de-AT" should get German if German is all
 * we have, so the base tag is tried after the full one, in the order the browser gave.
 */
export function localeFromLanguages(languages = []) {
    for (const tag of languages) {
        const lower = String(tag).toLowerCase();
        const exact = SUPPORTED_LOCALES.find((code) => code.toLowerCase() === lower);
        if (exact) return exact;
        const base = lower.split('-')[0];
        const partial = SUPPORTED_LOCALES.find((code) => code.toLowerCase().split('-')[0] === base);
        if (partial) return partial;
    }
    return null;
}

/**
 * Which locale to render, given everything we know. Pure, so the precedence can be
 * tested without a browser: URL, then a previous explicit choice, then the browser's
 * languages, then the default.
 */
export function detectLocale({ pathname = '/', stored = null, languages = [] } = {}) {
    const fromPath = localeFromPathname(pathname);
    if (fromPath) return fromPath;

    // The root path is the default locale's own page, not an absence of information —
    // redirecting away from it would break every link to the site's canonical URL.
    if (isLocaleRoot(pathname)) return DEFAULT_LOCALE;

    if (stored && SUPPORTED_LOCALES.includes(stored)) return stored;
    return localeFromLanguages(languages) || DEFAULT_LOCALE;
}

/** True for "/" and "/index.html" — the pages the default locale is served from. */
function isLocaleRoot(pathname) {
    return pathname === '/' || pathname === '/index.html';
}

/**
 * The URL of the current page in another locale. Switching keeps you where you are
 * rather than dumping you back on the home page.
 */
export function localeHref(code, pathname = '/') {
    const current = localeFromPathname(pathname);
    const rest = current ? String(pathname).slice(current.length + 1) : String(pathname);
    const tail = rest.replace(/^\/+/, '');
    return code === DEFAULT_LOCALE ? `/${tail}` : `/${code}/${tail}`;
}

/** Remember an explicit choice. Storage can throw in private mode; a preference is not worth an exception. */
export function rememberLocale(code) {
    try {
        localStorage.setItem(STORAGE_KEY, code);
    } catch (_) {
        // Private mode or blocked storage: the URL still carries the choice.
    }
}

export function storedLocale() {
    try {
        return localStorage.getItem(STORAGE_KEY);
    } catch (_) {
        return null;
    }
}

/**
 * The locale of the page as actually loaded. Resolved once: it cannot change without a
 * navigation, and t() is called dozens of times per render — re-reading localStorage
 * on each of those would be a synchronous storage hit per string.
 */
let resolvedLocale = null;
export function currentLocale() {
    if (resolvedLocale) return resolvedLocale;
    // A window may exist without the parts this needs: test harnesses and workers both
    // provide partial shims. Reading through them blindly threw and took the caller with
    // it, which for t() means a missing string becomes a crash.
    const w = typeof window === 'undefined' ? null : window;
    if (!w || !w.location) return DEFAULT_LOCALE;
    resolvedLocale = detectLocale({
        pathname: w.location.pathname || '/',
        stored: storedLocale(),
        languages: w.navigator?.languages || [],
    });
    return resolvedLocale;
}

/**
 * Writing direction of a locale. Arabic, Hebrew, Persian and Urdu read right to left,
 * and the whole layout — not just the text — has to follow: an avatar that sits before
 * a name in English sits after it in Arabic.
 *
 * The generated page already carries dir on <html>, so nothing here needs to apply it
 * at load. This exists for the handful of decisions CSS cannot express on its own —
 * which way an arrow points, which edge a drawer slides in from.
 */
export function localeDir(code = currentLocale()) {
    return LOCALE_META[code]?.dir === 'rtl' ? 'rtl' : 'ltr';
}

export function isRTL(code = currentLocale()) {
    return localeDir(code) === 'rtl';
}

/**
 * +1 or -1, for arithmetic on a horizontal offset: a swipe threshold, a translate, the
 * side a sheet enters from. `x * direction()` is the whole of what a mirrored gesture
 * needs, and it reads better than an `isRTL ? -x : x` at every call site.
 */
export function direction(code = currentLocale()) {
    return isRTL(code) ? -1 : 1;
}

/**
 * Force a fragment to be laid out left to right inside right-to-left text.
 *
 * Bidi reordering is done by the browser on the rendered text, and it mangles exactly
 * the strings this app is made of: a key fingerprint, a base64 session descriptor, a
 * URL, a version number. In an RTL paragraph "a1b2:c3d4" can come out as "c3d4:a1b2" —
 * the characters are all there, so nothing looks broken, and the reader compares the
 * wrong thing against their peer's screen. Any element showing machine text gets these
 * props.
 */
export const LTR_TEXT = { dir: 'ltr', style: { unicodeBidi: 'isolate', textAlign: 'start' } };

/**
 * The suggestion is an offer, and an offer that keeps coming back after it was turned
 * down is an ad. One dismissal is remembered for good; storage can be unavailable, in
 * which case the bar simply comes back — a worse experience, never a broken one.
 */
const SUGGEST_KEY = 'securebit-locale-suggest-dismissed';

export function localeSuggestionDismissed() {
    try {
        return localStorage.getItem(SUGGEST_KEY) === '1';
    } catch (_) {
        return false;
    }
}

export function dismissLocaleSuggestion() {
    try {
        localStorage.setItem(SUGGEST_KEY, '1');
    } catch (_) {
        // Nothing to do: the bar reappears next visit, which is not worth an exception.
    }
}

/**
 * A locale the visitor would probably rather read, when it is not the one they are on.
 * Used to offer a link, never to redirect: an automatic redirect sends Googlebot —
 * which crawls from one place — to a single locale and leaves the rest unindexed.
 */
export function suggestedLocale({ pathname = '/', languages = [], stored = null } = {}) {
    const shown = localeFromPathname(pathname) || DEFAULT_LOCALE;
    // An explicit past choice outranks the browser's list: someone who picked a
    // language once meant it, and it is exactly when their page does not match that
    // choice that the offer is worth making.
    const preferred = (SUPPORTED_LOCALES.includes(stored) && stored) || localeFromLanguages(languages);
    return preferred && preferred !== shown ? preferred : null;
}

/**
 * A list-valued string, for the handful of places where the copy is a set of short
 * labels rather than a sentence — a language may need a different number of them, so
 * the count belongs to the translation, not to the component.
 */
export function tList(key, locale = currentLocale()) {
    const value = dictionary(locale)?.[key] ?? dictionary(DEFAULT_LOCALE)?.[key];
    return Array.isArray(value) ? value : [];
}

/**
 * The rows a language switcher renders. Built here rather than in the component so the
 * URLs can be tested without a DOM, and so the switcher stays what it must be: a list
 * of real links. A control that swaps strings in place would leave every language on
 * one URL, which is the thing this whole arrangement exists to avoid.
 */
export function languageLinks({ pathname = '/', active = DEFAULT_LOCALE } = {}) {
    return SUPPORTED_LOCALES.map((code) => ({
        code,
        href: localeHref(code, pathname),
        hrefLang: LOCALE_META[code]?.htmlLang || code,
        // Listed in its own language: someone looking for German is looking for
        // "Deutsch", not for the English word for it.
        label: LOCALE_META[code]?.nativeName || code,
        // Short code for the collapsed switcher.
        abbr: LOCALE_META[code]?.abbr || code.toUpperCase(),
        // The row renders a name in its own script, so it needs its own direction:
        // "العربية" laid out left-to-right is the word spelled backwards.
        dir: LOCALE_META[code]?.dir || 'ltr',
        isCurrent: code === active,
    }));
}

/**
 * Look up a string. Falls back to the default locale and then to the key itself, so a
 * missing translation shows English rather than blank UI.
 */
export function t(key, vars, locale = currentLocale()) {
    const template =
        dictionary(locale)?.[key] ??
        // Asked for a locale whose dictionary is not on this page. Only the language
        // suggestion does that, and only for the handful of keys it needs, so those
        // ship for every locale; anything else falls through to the default below.
        CROSS_LOCALE_STRINGS[locale]?.[key] ??
        dictionary(DEFAULT_LOCALE)?.[key] ??
        key;
    if (!vars) return template;
    return String(template).replace(/\{(\w+)\}/g, (match, name) =>
        Object.prototype.hasOwnProperty.call(vars, name) ? String(vars[name]) : match
    );
}
