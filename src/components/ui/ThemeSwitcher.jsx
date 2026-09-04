// The three-state theme control, modelled on the language switcher next to it.
//
// Three states rather than a two-way toggle, because "follow the system" is a real
// preference and not the same as "dark": someone whose laptop turns light at sunrise
// wants the page to follow, and a two-way switch has nowhere to say so. The stored
// value is the *mode* ('system' | 'light' | 'dark'), never the colour it resolved to,
// so a page opened tomorrow in system mode answers the question again rather than
// replaying yesterday's answer.
//
// Nothing here owns the theme. src/scripts/theme-boot.js does — it runs blocking in
// <head>, long before React exists, because the theme has to be right on the first
// paint. This component is a view onto it: it reads window.SecureBitTheme, calls set(),
// and re-renders from the subscription rather than from its own state, so the header
// stays correct when the OS theme changes under it or another tab switches.
//
// Landing page only, like the language switcher, though for a different reason: there
// is no room for it in the connected header, which already carries the security pill,
// the connection status and the network settings, and the preference persists across
// the transition into the chat anyway.

import { t } from '../../i18n/index.js';

// 24×24 line icons, drawn to match the chevron the language switcher uses.
const ICON = {
    system: '<rect x="2.5" y="4" width="19" height="13" rx="2"/><path d="M8 20.5h8M12 17.5v3"/>',
    light: '<circle cx="12" cy="12" r="4.2"/><path d="M12 2.6v2.4M12 19v2.4M2.6 12h2.4M19 12h2.4M5.3 5.3l1.7 1.7M17 17l1.7 1.7M18.7 5.3L17 7M7 17l-1.7 1.7"/>',
    dark: '<path d="M20.5 14.3A8.6 8.6 0 0 1 9.7 3.5a8.6 8.6 0 1 0 10.8 10.8z"/>',
};

const svg = (path, size, width) => React.createElement('svg', {
    width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeWidth: width, strokeLinecap: 'round', strokeLinejoin: 'round',
    'aria-hidden': 'true',
    dangerouslySetInnerHTML: { __html: path },
});

const ThemeSwitcher = () => {
    const api = typeof window !== 'undefined' ? window.SecureBitTheme : null;
    // Without the boot script there is nothing to drive, and a control that cannot
    // change anything is worse than no control.
    if (!api) return null;

    const [open, setOpen] = React.useState(false);
    const [mode, setMode] = React.useState(() => api.get());
    const [resolved, setResolved] = React.useState(() => api.resolved());
    const rootRef = React.useRef(null);

    // The mode can change without this component doing it — the OS flipping while in
    // system mode, or another tab writing the preference.
    React.useEffect(() => api.subscribe((nextMode, nextResolved) => {
        setMode(nextMode);
        setResolved(nextResolved);
    }), []);

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

    const OPTIONS = [
        { mode: 'system', icon: ICON.system, label: t('theme.system') },
        { mode: 'light', icon: ICON.light, label: t('theme.light') },
        { mode: 'dark', icon: ICON.dark, label: t('theme.dark') },
    ];

    // The trigger shows what you are *getting*, not what you picked: in system mode the
    // useful thing to see is whether the page is currently light or dark. Which mode is
    // selected is the menu's job, and the check mark there says it.
    const triggerIcon = mode === 'system' ? ICON.system : (resolved === 'light' ? ICON.light : ICON.dark);
    const current = OPTIONS.find((o) => o.mode === mode) || OPTIONS[0];

    const trigger = React.createElement('button', {
        key: 'trigger',
        type: 'button',
        onClick: () => setOpen((v) => !v),
        'aria-haspopup': 'menu',
        'aria-expanded': open ? 'true' : 'false',
        'aria-label': t('theme.label') + ': ' + current.label,
        title: t('theme.label'),
        style: {
            display: 'flex', alignItems: 'center', gap: '6px',
            padding: '8px 9px', borderRadius: '9px',
            border: '1px solid rgba(var(--sb-ink), 0.07)',
            background: open ? 'rgba(var(--sb-ink), 0.06)' : 'rgba(var(--sb-ink), 0.02)',
            color: 'var(--sb-text-4)', font: 'inherit',
            cursor: 'pointer', transition: 'background .15s, color .15s',
        },
    }, [
        React.createElement('span', { key: 'i', style: { display: 'grid', placeItems: 'center' } }, svg(triggerIcon, 15, 1.9)),
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
        style: {
            position: 'absolute', top: 'calc(100% + 6px)', insetInlineEnd: 0, zIndex: 60,
            display: open ? 'block' : 'none',
            minWidth: '158px', padding: '5px', borderRadius: '11px',
            border: '1px solid rgba(var(--sb-ink), 0.08)', background: 'var(--sb-surface)',
            boxShadow: '0 14px 34px rgba(var(--sb-shadow-rgb), calc(0.45 * var(--sb-shadow-k)))',
        },
    }, OPTIONS.map((option) => {
        const active = option.mode === mode;
        return React.createElement('button', {
            key: option.mode,
            type: 'button',
            role: 'menuitemradio',
            'aria-checked': active ? 'true' : 'false',
            onClick: () => { api.set(option.mode); setOpen(false); },
            style: {
                width: '100%', display: 'flex', alignItems: 'center', gap: '10px',
                padding: '8px 10px', borderRadius: '8px', border: 'none',
                fontSize: '13px', fontFamily: 'inherit',
                fontWeight: active ? 600 : 500,
                color: active ? 'var(--sb-text-2)' : 'var(--sb-text-6)',
                background: active ? 'rgba(var(--sb-ink), 0.06)' : 'transparent',
                cursor: 'pointer', textAlign: 'start', whiteSpace: 'nowrap',
            },
        }, [
            React.createElement('span', {
                key: 'i',
                style: { flex: 'none', display: 'grid', placeItems: 'center', width: '16px', color: active ? 'var(--sb-orange)' : 'var(--sb-text-9)' },
            }, svg(option.icon, 14, 1.9)),
            React.createElement('span', { key: 'l', style: { flex: 1 } }, option.label),
            // The check is the only thing that distinguishes "system, currently dark"
            // from "dark" — the trigger icon cannot, because both look dark.
            active && React.createElement('span', {
                key: 'c',
                style: { flex: 'none', display: 'grid', placeItems: 'center', color: 'var(--sb-orange)' },
            }, svg('<path d="M4.5 12.5l5 5 10-11"/>', 12, 2.6)),
        ]);
    }));

    return React.createElement('div', {
        ref: rootRef,
        style: { position: 'relative', display: 'inline-flex' },
    }, [trigger, menu]);
};

window.ThemeSwitcher = ThemeSwitcher;

export { ThemeSwitcher };
