// An offer to switch language — never a redirect.
//
// The tempting version of this feature is to read navigator.language on load and send
// the visitor to the matching locale. It breaks the site for search engines in a way
// that is invisible from a browser: Googlebot crawls with a single language (en) from a
// single place, so a language redirect answers every one of the thirteen locale URLs
// with the English page. The twelve translations then have no indexable document of
// their own, the hreflang cluster they are declared in contradicts what the crawler
// actually receives, and the work of translating the site earns nothing. It is also
// wrong for people: a link shared into a German group chat has to open in German for
// everyone who follows it, including the person whose laptop is set to English.
//
// So the URL stays authoritative and this bar carries the whole feature. It appears only
// when the page being read is not the language the visitor probably wants, it says so in
// that language, and it offers a normal link. Dismissing it is remembered for good.
//
// Landing only, like the switcher: following the link is a navigation, and a navigation
// during a session drops the peer connection.

import {
    LOCALE_META,
    dismissLocaleSuggestion,
    localeHref,
    localeSuggestionDismissed,
    rememberLocale,
    storedLocale,
    suggestedLocale,
    t,
} from '../../i18n/index.js';
import { prefersReducedMotion } from '../../ui/motion.js';

const LanguageSuggestion = () => {
    // Resolved once, at mount: the answer cannot change without a navigation, and
    // re-deriving it on every render would mean a storage read per render.
    const [target] = React.useState(() => {
        if (typeof window === 'undefined' || !window.location) return null;
        if (localeSuggestionDismissed()) return null;
        return suggestedLocale({
            pathname: window.location.pathname || '/',
            languages: window.navigator?.languages || [],
            stored: storedLocale(),
        });
    });
    const [gone, setGone] = React.useState(false);
    // Mounted invisible, then raised on the next frame, so the bar arrives rather than
    // being part of the first paint — the page's own content should land first.
    const [shown, setShown] = React.useState(false);

    React.useEffect(() => {
        if (!target) return undefined;
        const id = setTimeout(() => setShown(true), 600);
        return () => clearTimeout(id);
    }, [target]);

    if (!target || gone) return null;

    const meta = LOCALE_META[target] || {};
    const dir = meta.dir === 'rtl' ? 'rtl' : 'ltr';
    const pathname = typeof window !== 'undefined' ? window.location.pathname : '/';
    const href = localeHref(target, pathname);
    const still = prefersReducedMotion();

    const close = () => {
        dismissLocaleSuggestion();
        setGone(true);
    };

    // The copy is in the language being offered — the point of the bar is to be readable
    // by someone who cannot read the page it sits on. `dir` and `lang` come with it, so
    // Arabic in this bar is laid out as Arabic even on the English page.
    const line = React.createElement('div', {
        key: 'line',
        lang: meta.htmlLang || target,
        dir,
        style: { fontSize: '13px', lineHeight: 1.45, color: 'var(--sb-text-4)', textAlign: 'start' },
    }, t('language.suggest.text', null, target));

    const link = React.createElement('a', {
        key: 'cta',
        href,
        hrefLang: meta.htmlLang || target,
        lang: meta.htmlLang || target,
        dir,
        // Following the link is an explicit choice, so it is remembered — the bar has
        // then done its job and will not be offered again.
        onClick: () => { rememberLocale(target); dismissLocaleSuggestion(); },
        style: {
            display: 'inline-flex', alignItems: 'center', gap: '6px',
            padding: '7px 12px', borderRadius: '9px',
            border: '1px solid rgba(var(--sb-orange-rgb), 0.30)', background: 'rgba(var(--sb-orange-rgb), 0.12)',
            color: 'var(--sb-orange)', fontSize: '12.5px', fontWeight: 600,
            textDecoration: 'none', whiteSpace: 'nowrap',
        },
    }, t('language.suggest.cta', null, target));

    const dismiss = React.createElement('button', {
        key: 'dismiss',
        type: 'button',
        onClick: close,
        // Labelled in the offered language too: this button is for the same reader.
        'aria-label': t('language.suggest.dismiss', null, target),
        style: {
            padding: '7px 10px', borderRadius: '9px',
            border: '1px solid rgba(var(--sb-ink), 0.07)', background: 'rgba(var(--sb-ink), 0.02)',
            color: 'var(--sb-text-7)', font: 'inherit', fontSize: '12.5px', fontWeight: 500,
            cursor: 'pointer', whiteSpace: 'nowrap',
        },
    }, t('language.suggest.dismiss', null, target));

    return React.createElement('div', {
        // A region rather than a dialog: it interrupts nothing and takes no focus.
        role: 'region',
        'aria-label': t('language.label'),
        style: {
            // Bottom inline-start, because the install prompt owns the opposite corner.
            position: 'fixed', bottom: '24px', insetInlineStart: '24px', zIndex: 50,
            maxWidth: 'min(340px, calc(100vw - 48px))',
            display: 'flex', flexDirection: 'column', gap: '11px',
            padding: '14px 16px', borderRadius: '14px',
            border: '1px solid rgba(var(--sb-ink), 0.08)', background: 'var(--sb-surface)',
            boxShadow: '0 16px 40px rgba(var(--sb-shadow-rgb), calc(0.5 * var(--sb-shadow-k)))',
            opacity: shown ? 1 : 0,
            transform: shown || still ? 'none' : 'translateY(10px)',
            transition: still ? 'opacity .2s linear' : 'opacity .3s ease, transform .3s cubic-bezier(.2,.7,.3,1)',
            // Invisible and untouchable until raised, so it cannot swallow a tap during
            // the fade.
            pointerEvents: shown ? 'auto' : 'none',
        },
    }, [
        line,
        React.createElement('div', {
            key: 'actions',
            style: { display: 'flex', alignItems: 'center', gap: '8px' },
        }, [link, dismiss]),
    ]);
};

window.LanguageSuggestion = LanguageSuggestion;

export { LanguageSuggestion };
