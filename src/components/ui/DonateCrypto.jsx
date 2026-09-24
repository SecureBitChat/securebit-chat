import { t, isRTL } from '../../i18n/index.js';

// "Keep SecureBit independent" — crypto donation card.
// Translated from the Claude Design component (Crypto Donate v3.dc.html): coin switcher,
// address with copy, and a QR on the right.
//
// Everything is served from this origin. The design pulled the coin icons from jsDelivr
// and built the QR with a CDN script; the site's CSP (`img-src 'self' data:`) would block
// the first, and both would hand a third party the address of every visitor. The
// addresses are fixed, so the QRs are pre-rendered SVGs in /assets/crypto/.

const WALLETS = [
    { id: 'usdt', tab: 'USDT', coin: 'Tether USDT', badge: 'trx', address: 'TMopDoco5EwJB1QvQYsuhjUJdMvzPXNQYu' },
    { id: 'btc', tab: 'BTC', coin: 'Bitcoin', badge: null, address: 'bc1qnmc2xl7p0pxcy6lzf2tyf52wnslgzkgaq9kxpr' },
    { id: 'eth', tab: 'ETH', coin: 'Ethereum', badge: null, address: '0xCDfDfaD4EC1fa657C3d2A7EFabc1cb751bf1dAf7' }
];

const icon = (id) => `/assets/crypto/${id}.svg`;

// A disconnect asks for the page to be brought here (see handleDisconnect in app.jsx).
// The request is a timestamped flag rather than just an event, because the landing — and
// this card with it — usually mounts only after the chat has been torn down. It expires
// so that a request made while no landing was shown cannot fire minutes later.
const SCROLL_FLAG = '__sbScrollToDonate';
const SCROLL_EVENT = 'securebit:scroll-to-donate';
const SCROLL_TTL_MS = 5000;

const DonateCrypto = () => {
    const [isMobile, setIsMobile] = React.useState(
        typeof window !== 'undefined' && window.matchMedia('(max-width:767px)').matches
    );
    const [sel, setSel] = React.useState(0);
    const [copied, setCopied] = React.useState(false);
    // +1 when the new coin comes in from the end side, -1 from the start side; the QR
    // slides in accordingly so a swipe feels like moving along the row of tabs.
    const [slide, setSlide] = React.useState(0);
    const touchStart = React.useRef(null);
    const sectionRef = React.useRef(null);
    const copyTimer = React.useRef(null);

    React.useEffect(() => {
        const mq = window.matchMedia('(max-width:767px)');
        const onChange = () => setIsMobile(mq.matches);
        mq.addEventListener ? mq.addEventListener('change', onChange) : mq.addListener(onChange);
        return () => {
            mq.removeEventListener ? mq.removeEventListener('change', onChange) : mq.removeListener(onChange);
            clearTimeout(copyTimer.current);
        };
    }, []);

    React.useEffect(() => {
        let timer = null;
        const scrollHere = () => {
            const at = window[SCROLL_FLAG];
            window[SCROLL_FLAG] = 0;
            if (!at || Date.now() - at > SCROLL_TTL_MS) return;
            clearTimeout(timer);
            // Let the landing finish laying out first, or the target moves under the scroll.
            timer = setTimeout(() => {
                const el = sectionRef.current;
                if (!el) return;
                const reduce = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
                el.scrollIntoView({ behavior: reduce ? 'auto' : 'smooth', block: 'center' });
            }, 350);
        };
        scrollHere();
        document.addEventListener(SCROLL_EVENT, scrollHere);
        return () => {
            document.removeEventListener(SCROLL_EVENT, scrollHere);
            clearTimeout(timer);
        };
    }, []);

    const cur = WALLETS[sel];

    const pick = (i) => {
        const next = (i + WALLETS.length) % WALLETS.length;
        if (next === sel) return;
        setSlide(i > sel ? 1 : -1);
        setSel(next);
        setCopied(false);
    };

    // Swipe across the QR to change coin on a phone. Horizontal only, and only past a
    // clear threshold, so a vertical scroll that starts on the QR still scrolls the page
    // (touch-action: pan-y hands vertical pans to the browser). In a right-to-left locale
    // the tab row runs the other way, and so does the swipe.
    const onTouchStart = (e) => {
        const p = e.touches[0];
        touchStart.current = { x: p.clientX, y: p.clientY };
    };
    const onTouchEnd = (e) => {
        const start = touchStart.current;
        touchStart.current = null;
        if (!start) return;
        const p = e.changedTouches[0];
        const dx = p.clientX - start.x;
        const dy = p.clientY - start.y;
        if (Math.abs(dx) < 40 || Math.abs(dx) < Math.abs(dy) * 1.5) return;
        const forward = isRTL() ? dx > 0 : dx < 0;
        pick(sel + (forward ? 1 : -1));
    };

    const copy = async () => {
        try {
            await navigator.clipboard.writeText(cur.address);
        } catch (e) {
            const ta = document.createElement('textarea');
            ta.value = cur.address;
            document.body.appendChild(ta);
            ta.select();
            try { document.execCommand('copy'); } catch (_) {}
            ta.remove();
        }
        setCopied(true);
        clearTimeout(copyTimer.current);
        copyTimer.current = setTimeout(() => setCopied(false), 1800);
    };

    const SANS = "'Manrope', system-ui, -apple-system, sans-serif";
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
    const FIELD = {
        borderRadius: '14px', background: 'var(--sb-bg)', border: '1px solid rgba(var(--sb-ink), 0.07)'
    };

    const tabs = React.createElement('div', {
        key: 'tabs', role: 'tablist',
        style: { ...FIELD, display: 'flex', gap: '6px', padding: '5px', marginBottom: '14px' }
    }, WALLETS.map((w, i) => {
        const on = i === sel;
        return React.createElement('button', {
            key: w.id, type: 'button', role: 'tab', 'aria-selected': on,
            onClick: () => pick(i),
            style: {
                flex: '1 1 0', minWidth: 0, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                gap: '9px', padding: '11px 10px', borderRadius: '10px', border: 'none', cursor: 'pointer',
                fontFamily: SANS, fontSize: '14px', fontWeight: 700, transition: 'all .18s',
                background: on ? 'var(--sb-surface-2)' : 'transparent',
                color: on ? 'var(--sb-text-1)' : 'var(--sb-text-7)',
                boxShadow: on ? 'inset 0 0 0 1px rgba(var(--sb-orange-rgb), 0.45)' : 'none'
            }
        }, [
            React.createElement('span', { key: 'ic', style: { position: 'relative', flex: 'none', width: '22px', height: '22px' } }, [
                React.createElement('img', { key: 'logo', src: icon(w.id), alt: '', width: 22, height: 22, style: { display: 'block', width: '22px', height: '22px' } }),
                w.badge && React.createElement('img', {
                    key: 'badge', src: icon(w.badge), alt: '', width: 11, height: 11,
                    style: {
                        position: 'absolute', right: '-3px', bottom: '-3px', width: '11px', height: '11px', borderRadius: '50%',
                        border: '1.5px solid var(--sb-surface-2)', background: 'var(--sb-surface-2)'
                    }
                })
            ]),
            w.tab
        ]);
    }));

    const copyBtn = React.createElement('button', {
        key: 'copy', type: 'button', onClick: copy,
        style: {
            flex: 'none', display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '12px 16px',
            borderRadius: '10px', fontFamily: SANS, fontSize: '13.5px', fontWeight: 700, cursor: 'pointer',
            background: 'rgba(var(--sb-ink), 0.05)', color: 'var(--sb-text-2)',
            border: '1px solid rgba(var(--sb-ink), 0.1)', transition: 'all .18s'
        },
        onMouseEnter: (e) => { e.currentTarget.style.background = 'rgba(var(--sb-ink), 0.09)'; },
        onMouseLeave: (e) => { e.currentTarget.style.background = 'rgba(var(--sb-ink), 0.05)'; }
    }, [
        copied
            ? React.createElement('svg', {
                key: 'ok', width: 15, height: 15, viewBox: '0 0 24 24', fill: 'none', stroke: 'var(--sb-green-solid)',
                strokeWidth: 2.4, strokeLinecap: 'round', strokeLinejoin: 'round',
                dangerouslySetInnerHTML: { __html: '<path d="M5 12.5l4.2 4.2L19 6.5"/>' }
            })
            : React.createElement('svg', {
                key: 'cp', width: 15, height: 15, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
                strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round',
                dangerouslySetInnerHTML: { __html: '<rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15V5a2 2 0 0 1 2-2h8"/>' }
            }),
        React.createElement('span', { key: 'l', 'aria-live': 'polite' }, copied ? t('donate.copied') : t('donate.copy'))
    ]);

    const addressField = React.createElement('div', {
        key: 'addr',
        style: { ...FIELD, display: 'flex', alignItems: 'center', gap: '12px', padding: '8px 8px 8px 18px' }
    }, [
        React.createElement('div', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
            React.createElement('div', { key: 'net', style: { fontSize: '11.5px', fontWeight: 600, color: 'var(--sb-text-9)', marginBottom: '2px' } }, t(`donate.net.${cur.id}`)),
            React.createElement('div', {
                key: 'a', title: cur.address, dir: 'ltr',
                style: { fontFamily: MONO, fontSize: '14px', color: 'var(--sb-text-2)', letterSpacing: '0.3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }
            }, cur.address.slice(0, 8) + '…' + cur.address.slice(-8))
        ]),
        copyBtn
    ]);

    const warn = React.createElement('div', {
        key: 'warn',
        style: { display: 'flex', alignItems: 'center', gap: '7px', marginTop: '14px', fontSize: '12px', color: 'var(--sb-text-9)' }
    }, [
        React.createElement('svg', {
            key: 'i', width: 13, height: 13, viewBox: '0 0 24 24', fill: 'none', stroke: 'var(--sb-orange-solid)',
            strokeWidth: 2, strokeLinecap: 'round', strokeLinejoin: 'round', style: { flex: 'none' },
            dangerouslySetInnerHTML: { __html: '<path d="M12 3l9.5 17h-19z"/><path d="M12 10v4M12 17.5v.01"/>' }
        }),
        t(`donate.warn.${cur.id}`)
    ]);

    const left = React.createElement('div', {
        key: 'left',
        style: { flex: '1 1 440px', minWidth: 0, padding: isMobile ? '32px 22px 8px' : '44px', display: 'flex', flexDirection: 'column' }
    }, [
        React.createElement('div', {
            key: 'eyebrow',
            style: { fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: 'var(--sb-text-9)', textTransform: 'uppercase', letterSpacing: '1.8px', marginBottom: '14px' }
        }, t('donate.eyebrow')),
        React.createElement('h2', {
            key: 'title',
            style: { margin: '0 0 10px', fontSize: isMobile ? '28px' : '34px', fontWeight: 800, letterSpacing: '-1px', lineHeight: 1.08, color: 'var(--sb-text-1)' }
        }, t('donate.title')),
        React.createElement('p', {
            key: 'desc',
            style: { margin: '0 0 30px', fontSize: '15px', lineHeight: 1.6, color: 'var(--sb-text-7)' }
        }, t('donate.description')),
        tabs,
        addressField,
        warn
    ]);

    // The QR plate is white in both themes: scanners want dark modules on a light ground.
    const dirSign = isRTL() ? -1 : 1;
    const slideAnim = slide === 0 ? 'none'
        : `${slide * dirSign > 0 ? 'cdInEnd' : 'cdInStart'} .28s cubic-bezier(.2,.7,.3,1)`;

    const plate = React.createElement('div', {
        key: 'plate',
        onTouchStart, onTouchEnd,
        style: {
            position: 'relative', width: '232px', height: '232px', padding: '14px', borderRadius: '20px', background: '#fff',
            boxShadow: '0 24px 60px rgba(var(--sb-shadow-rgb), calc(0.45 * var(--sb-shadow-k)))',
            border: '1px solid rgba(var(--sb-ink), 0.07)', overflow: 'hidden', touchAction: 'pan-y', userSelect: 'none'
        }
    }, React.createElement('div', {
        key: cur.id,
        style: { position: 'relative', width: '100%', height: '100%', animation: slideAnim }
    }, [
        React.createElement('img', {
            key: 'qr', src: `/assets/crypto/qr-${cur.id}.svg`, alt: t('donate.qrAlt', { coin: cur.coin }),
            width: 204, height: 204, draggable: false,
            style: { display: 'block', width: '100%', height: '100%', imageRendering: 'pixelated' }
        }),
        React.createElement('div', {
            key: 'logo',
            style: { position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%,-50%)', width: '48px', height: '48px', borderRadius: '12px', background: '#fff', display: 'grid', placeItems: 'center' }
        }, React.createElement('img', { src: icon(cur.id), alt: '', width: 34, height: 34, draggable: false, style: { display: 'block', width: '34px', height: '34px' } }))
    ]));

    // Page dots under the QR on a phone — the hint that it can be swiped.
    const dots = isMobile && React.createElement('div', {
        key: 'dots', 'aria-hidden': true,
        style: { display: 'flex', justifyContent: 'center', gap: '7px', marginTop: '18px' }
    }, WALLETS.map((w, i) => React.createElement('span', {
        key: w.id,
        style: {
            width: i === sel ? '18px' : '7px', height: '7px', borderRadius: '4px', transition: 'all .25s',
            background: i === sel ? 'var(--sb-orange-solid)' : 'rgba(var(--sb-ink), 0.16)'
        }
    })));

    const right = React.createElement('div', {
        key: 'right',
        style: { flex: '0 0 auto', minWidth: isMobile ? 0 : '300px', margin: '0 auto', padding: isMobile ? '24px 22px 32px' : '44px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }
    }, [plate, dots]);

    const card = React.createElement('div', {
        key: 'card',
        style: {
            width: '100%', maxWidth: '1000px', position: 'relative', overflow: 'hidden', borderRadius: '24px',
            background: 'radial-gradient(520px 420px at 100% 50%, rgba(var(--sb-orange-rgb), 0.09), transparent 70%), var(--sb-surface)',
            border: '1px solid rgba(var(--sb-ink), 0.07)', display: 'flex', flexWrap: 'wrap', alignItems: 'stretch',
            animation: 'cdUp .45s cubic-bezier(.2,.7,.3,1)'
        }
    }, [
        left,
        right
    ]);

    return React.createElement('section', {
        id: 'donate', ref: sectionRef,
        style: {
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'var(--sb-bg)', color: 'var(--sb-text-2)', fontFamily: SANS,
            padding: isMobile ? '48px 18px' : '64px 32px'
        }
    }, [
        React.createElement('style', { key: 'kf', dangerouslySetInnerHTML: { __html: '@keyframes cdUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}' +
            '@keyframes cdInEnd{from{opacity:0;transform:translateX(36px)}to{opacity:1;transform:none}}' +
            '@keyframes cdInStart{from{opacity:0;transform:translateX(-36px)}to{opacity:1;transform:none}}' +
            '@media (prefers-reduced-motion: reduce){#donate [style*="cdIn"]{animation:none!important}}' } }),
        card
    ]);
};

DonateCrypto.SCROLL_FLAG = SCROLL_FLAG;
DonateCrypto.SCROLL_EVENT = SCROLL_EVENT;

window.DonateCrypto = DonateCrypto;
