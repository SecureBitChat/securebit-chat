import { t } from '../../i18n/index.js';

// "Join the future of privacy" — community / open-source call-to-action.
// Translated from the Claude Design component (Community CTA.dc.html): a centered
// glowing card with GitHub + Feedback actions on a full-bleed dark band.
const CommunityCTA = () => {
    const [isMobile, setIsMobile] = React.useState(
        typeof window !== 'undefined' && window.matchMedia('(max-width:767px)').matches
    );

    React.useEffect(() => {
        const mq = window.matchMedia('(max-width:767px)');
        const onChange = () => setIsMobile(mq.matches);
        mq.addEventListener ? mq.addEventListener('change', onChange) : mq.addListener(onChange);
        return () => {
            mq.removeEventListener ? mq.removeEventListener('change', onChange) : mq.removeListener(onChange);
        };
    }, []);

    const ACCENT = 'var(--sb-orange)';
    // Fill form: brand colour in both themes. See app.jsx.
    const ACCENT_SOLID = 'var(--sb-orange-solid)';
    const SANS = "'Manrope', system-ui, -apple-system, sans-serif";

    const githubUrl = 'https://github.com/SecureBitChat/securebit-chat/';
    const feedbackUrl = 'mailto:lockbitchat@tutanota.com';

    const githubBtn = React.createElement('a', {
        key: 'gh',
        href: githubUrl,
        target: '_blank',
        rel: 'noopener noreferrer',
        style: {
            display: 'inline-flex', alignItems: 'center', gap: '11px', padding: '15px 26px',
            borderRadius: '13px', background: ACCENT_SOLID, color: 'var(--sb-on-accent)', textDecoration: 'none',
            fontSize: '15.5px', fontWeight: 700, letterSpacing: '-0.2px',
            boxShadow: '0 8px 24px rgba(var(--sb-orange-rgb), 0.28)', whiteSpace: 'nowrap',
            transition: 'all .2s cubic-bezier(.2,.7,.3,1)'
        },
        onMouseEnter: (e) => { e.currentTarget.style.background = 'var(--sb-orange-hi)'; e.currentTarget.style.transform = 'translateY(-2px)'; },
        onMouseLeave: (e) => { e.currentTarget.style.background = ACCENT_SOLID; e.currentTarget.style.transform = 'none'; }
    }, [
        React.createElement('svg', {
            key: 'i', width: 20, height: 20, viewBox: '0 0 24 24', fill: 'currentColor',
            dangerouslySetInnerHTML: { __html: '<path d="M12 2C6.48 2 2 6.58 2 12.26c0 4.5 2.87 8.32 6.84 9.67.5.09.68-.22.68-.49 0-.24-.01-.87-.01-1.71-2.78.62-3.37-1.36-3.37-1.36-.46-1.18-1.11-1.5-1.11-1.5-.91-.63.07-.62.07-.62 1 .07 1.53 1.05 1.53 1.05.89 1.56 2.34 1.11 2.91.85.09-.66.35-1.11.63-1.36-2.22-.26-4.55-1.14-4.55-5.07 0-1.12.39-2.03 1.03-2.75-.1-.26-.45-1.3.1-2.71 0 0 .84-.27 2.75 1.05a9.3 9.3 0 0 1 5 0c1.91-1.32 2.75-1.05 2.75-1.05.55 1.41.2 2.45.1 2.71.64.72 1.03 1.63 1.03 2.75 0 3.94-2.34 4.81-4.57 5.06.36.32.68.94.68 1.9 0 1.37-.01 2.47-.01 2.81 0 .27.18.59.69.49A10.02 10.02 0 0 0 22 12.26C22 6.58 17.52 2 12 2z"/>' }
        }),
        t('community.github')
    ]);

    const feedbackBtn = React.createElement('a', {
        key: 'fb',
        href: feedbackUrl,
        rel: 'noopener noreferrer',
        style: {
            display: 'inline-flex', alignItems: 'center', gap: '11px', padding: '15px 26px',
            borderRadius: '13px', background: 'rgba(var(--sb-ink), 0.03)', color: 'var(--sb-text-2)', textDecoration: 'none',
            fontSize: '15.5px', fontWeight: 700, letterSpacing: '-0.2px',
            border: '1px solid rgba(var(--sb-ink), 0.1)', whiteSpace: 'nowrap',
            transition: 'all .2s cubic-bezier(.2,.7,.3,1)'
        },
        onMouseEnter: (e) => { e.currentTarget.style.borderColor = 'rgba(var(--sb-ink), 0.24)'; e.currentTarget.style.background = 'rgba(var(--sb-ink), 0.06)'; },
        onMouseLeave: (e) => { e.currentTarget.style.borderColor = 'rgba(var(--sb-ink), 0.1)'; e.currentTarget.style.background = 'rgba(var(--sb-ink), 0.03)'; }
    }, [
        React.createElement('svg', {
            key: 'i', width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor',
            strokeWidth: 1.9, strokeLinecap: 'round', strokeLinejoin: 'round',
            dangerouslySetInnerHTML: { __html: '<path d="M21 11.5a8 8 0 0 1-11.6 7.1L4 20l1.4-5.3A8 8 0 1 1 21 11.5z"/><path d="M8.5 11h7M8.5 14h4.5"/>' }
        }),
        t('community.feedback')
    ]);

    const card = React.createElement('div', {
        key: 'card',
        style: {
            position: 'relative', overflow: 'hidden', maxWidth: '860px', width: '100%',
            borderRadius: '24px',
            background: 'radial-gradient(700px 360px at 50% 0%, rgba(var(--sb-orange-rgb), 0.1), transparent 65%), var(--sb-bg)',
            border: '1px solid rgba(var(--sb-ink), 0.07)',
            padding: isMobile ? '40px 24px 36px' : '56px 56px 48px',
            textAlign: 'center', boxShadow: '0 24px 60px rgba(var(--sb-shadow-rgb), calc(0.4 * var(--sb-shadow-k)))'
        }
    }, [
        // hairline accent
        React.createElement('div', {
            key: 'hairline',
            style: { position: 'absolute', top: 0, left: '50%', transform: 'translateX(-50%)', width: '180px', height: '1px', background: 'linear-gradient(90deg, transparent, rgba(var(--sb-orange-rgb), 0.7), transparent)' }
        }),
        // brand mark (same SVG as the header — no border or background)
        React.createElement('img', {
            key: 'icon',
            src: '/logo/securebit-mark.svg',
            alt: 'SecureBit',
            style: { display: 'inline-block', width: '64px', height: '64px', objectFit: 'contain', marginBottom: '22px', animation: 'ccUp .4s cubic-bezier(.2,.7,.3,1)' }
        }),
        // title
        React.createElement('h2', {
            key: 'title',
            style: { margin: '0 0 16px', fontSize: isMobile ? '28px' : '36px', fontWeight: 800, letterSpacing: '-1px', lineHeight: 1.05, color: 'var(--sb-text-1)' }
        }, t('community.title')),
        // description
        React.createElement('p', {
            key: 'desc',
            style: { margin: '0 auto 32px', maxWidth: '560px', fontSize: '16px', lineHeight: 1.65, color: 'var(--sb-text-6)' }
        }, t('community.description')),
        // buttons
        React.createElement('div', {
            key: 'btns',
            style: { display: 'flex', gap: '14px', justifyContent: 'center', flexWrap: 'wrap' }
        }, [githubBtn, feedbackBtn]),
        // Snap Store, bottom right.
        //
        // Served from this origin, not snapcraft.io. The site's CSP is
        // `img-src 'self' data:` and would block a hotlink anyway, but the
        // reason to keep it that way is the product's own claim: fetching a
        // badge from someone else's server hands them the address of every
        // visitor to a page that promises no servers are involved.
        React.createElement('div', {
            key: 'snap',
            style: {
                display: 'flex',
                justifyContent: isMobile ? 'center' : 'flex-end',
                marginTop: '28px'
            }
        }, React.createElement('a', {
            href: 'https://snapcraft.io/securebit-chat',
            target: '_blank',
            rel: 'noopener noreferrer',
            'aria-label': 'Get it from the Snap Store',
            style: { display: 'inline-flex', opacity: 0.9, transition: 'opacity .2s' },
            onMouseEnter: (e) => { e.currentTarget.style.opacity = 1; },
            onMouseLeave: (e) => { e.currentTarget.style.opacity = 0.9; }
        }, React.createElement('img', {
            src: '/assets/badges/snap-store.svg',
            alt: 'Get it from the Snap Store',
            width: 182,
            height: 56,
            loading: 'lazy',
            style: { display: 'block' }
        })))
    ]);

    return React.createElement('section', {
        style: {
            width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'var(--sb-bg)', fontFamily: SANS,
            padding: isMobile ? '48px 18px' : '64px 48px'
        }
    }, [
        React.createElement('style', { key: 'kf', dangerouslySetInnerHTML: { __html: '@keyframes ccUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}' } }),
        card
    ]);
};

window.CommunityCTA = CommunityCTA;
