// Switching language is a navigation, not a state change: every locale is its own
// document at its own URL, generated at build time. So the entries are ordinary links —
// they work before React has mounted, they open in a new tab, they can be copied and
// shared, and a crawler can follow them. A <button> that re-rendered the page in another
// language would leave every language sharing one URL, which is the one thing this
// arrangement exists to prevent.
//
// The list is a dropdown showing short codes: with nine languages, a row of full native
// names does not fit a phone header. Every link stays in the DOM whether the menu is open
// or shut — hiding is visual only, so nothing depends on the menu having been opened.
//
// Because it navigates, the switcher belongs on the landing page only. Offering it during
// a call or a chat would invite someone to reload the document and drop the peer
// connection mid-conversation.

import { SUPPORTED_LOCALES, currentLocale, languageLinks, rememberLocale, t } from '../../i18n/index.js';

const LanguageSwitcher = () => {
    if (SUPPORTED_LOCALES.length < 2) return null;

    const [open, setOpen] = React.useState(false);
    const rootRef = React.useRef(null);

    const pathname = typeof window !== 'undefined' ? window.location.pathname : '/';
    const links = languageLinks({ pathname, active: currentLocale() });
    const active = links.find((l) => l.isCurrent) || links[0];

    // Close on an outside press or Escape — the two ways people expect a menu to go away.
    React.useEffect(() => {
        if (!open) return undefined;
        const onDown = (e) => {
            if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
        };
        const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
        document.addEventListener('pointerdown', onDown);
        document.addEventListener('keydown', onKey);
        return () => {
            document.removeEventListener('pointerdown', onDown);
            document.removeEventListener('keydown', onKey);
        };
    }, [open]);

    const trigger = React.createElement('button', {
        key: 'trigger',
        type: 'button',
        onClick: () => setOpen((v) => !v),
        'aria-haspopup': 'menu',
        'aria-expanded': open ? 'true' : 'false',
        'aria-label': t('language.label'),
        style: {
            display: 'flex', alignItems: 'center', gap: '6px',
            padding: '7px 10px', borderRadius: '9px',
            border: '1px solid rgba(255,255,255,0.07)',
            background: open ? 'rgba(255,255,255,0.06)' : 'rgba(255,255,255,0.02)',
            color: '#cfcfd4', font: 'inherit', fontSize: '12.5px', fontWeight: 600,
            cursor: 'pointer', transition: 'background .15s, color .15s',
        },
    }, [
        React.createElement('span', { key: 'c' }, active ? active.abbr : ''),
        React.createElement('svg', {
            key: 'v', width: 11, height: 11, viewBox: '0 0 24 24', fill: 'none',
            stroke: 'currentColor', strokeWidth: 2.4, strokeLinecap: 'round', strokeLinejoin: 'round',
            style: { transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .18s' },
            dangerouslySetInnerHTML: { __html: '<path d="M6 9l6 6 6-6"/>' },
        }),
    ]);

    const menu = React.createElement('div', {
        key: 'menu',
        role: 'menu',
        // The same scrollbar the chat uses, rather than the browser's default slab —
        // a 170px menu is exactly where a 15px stock scrollbar looks like a mistake.
        className: 'sb-scroll',
        // Kept in the DOM when shut: the links stay followable and the menu costs nothing
        // to reopen.
        style: {
            position: 'absolute', top: 'calc(100% + 6px)', insetInlineEnd: 0, zIndex: 60,
            display: open ? 'block' : 'none',
            minWidth: '170px', padding: '5px', borderRadius: '11px',
            border: '1px solid rgba(255,255,255,0.08)', background: '#161618',
            boxShadow: '0 14px 34px rgba(0,0,0,0.45)',
            // Thirteen languages is taller than a phone in landscape. Cap it and scroll
            // rather than let the list run off the bottom, where the last few entries
            // would be unreachable.
            maxHeight: 'min(62vh, 420px)', overflowY: 'auto', overscrollBehavior: 'contain',
        },
    }, links.map((link) => React.createElement('a', {
        key: link.code,
        href: link.href,
        hrefLang: link.hrefLang,
        lang: link.hrefLang,
        // Each row is a word in its own script, so it gets its own direction — the menu
        // around it stays in the direction of the page being read.
        dir: link.dir,
        role: 'menuitem',
        // aria-current names the page you are on for a screen reader; the weight and
        // contrast below say the same thing to everyone else.
        'aria-current': link.isCurrent ? 'page' : undefined,
        // Remember the choice, then let the browser navigate. The click is deliberately
        // not intercepted — the next locale is a different document.
        onClick: () => rememberLocale(link.code),
        style: {
            display: 'flex', alignItems: 'center', gap: '10px',
            padding: '8px 10px', borderRadius: '8px',
            fontSize: '13px',
            fontWeight: link.isCurrent ? 600 : 500,
            color: link.isCurrent ? '#e8e8eb' : '#9a9aa2',
            background: link.isCurrent ? 'rgba(255,255,255,0.06)' : 'transparent',
            textDecoration: 'none', whiteSpace: 'nowrap',
        },
    }, [
        React.createElement('span', {
            key: 'a',
            style: { fontSize: '11px', fontWeight: 700, letterSpacing: '0.4px', color: '#6b6b73', width: '22px', flex: 'none', textAlign: 'start' },
        }, link.abbr),
        React.createElement('span', { key: 'n' }, link.label),
    ])));

    return React.createElement('nav', {
        ref: rootRef,
        'aria-label': t('language.label'),
        style: { position: 'relative', display: 'inline-flex' },
    }, [trigger, menu]);
};

window.LanguageSwitcher = LanguageSwitcher;

export { LanguageSwitcher };
