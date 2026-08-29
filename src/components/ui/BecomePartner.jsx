import { t } from '../../i18n/index.js';

// "Trusted by our partners" — partner ecosystem section.
// Translated from the Claude Design component (Partners.dc.html) into the
// project's React.createElement style: a full-bleed dark band with partner
// cards plus a dashed "Become a partner" invite card.
const BecomePartner = () => {
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

    const ACCENT = '#f0892a';
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
    const SANS = "'Manrope', system-ui, -apple-system, sans-serif";

    const formUrl = 'https://docs.google.com/forms/d/e/1FAIpQLSc9ijV9PCoyXkus6vEx1OWwvwAsLq8fKS6-H5BmX-c-bvia6w/viewform?usp=dialog';

    const partners = [
        {
            id: 'aegis',
            name: 'Aegis Investment',
            logo: '/logo/aegis.png',
            logoHeight: '42px',
            url: 'https://aegis-investment.com/',
            desc: t('partners.aegis.desc'),
            role: t('partners.aegis.role'),
            delay: '.5s'
        },
        {
            id: 'furi',
            name: 'FuriLabs',
            logo: '/logo/furi.png',
            logoHeight: '54px',
            url: 'https://furilabs.com/',
            desc: t('partners.furilabs.desc'),
            role: t('partners.furilabs.role'),
            delay: '.56s'
        }
    ];

    const svg = (inner, size, stroke, sw, className) =>
        React.createElement('svg', {
            className, width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
            stroke, strokeWidth: sw, strokeLinecap: 'round', strokeLinejoin: 'round',
            dangerouslySetInnerHTML: { __html: inner }
        });

    const roleTag = (role) => React.createElement('span', {
        key: 'role',
        style: { fontFamily: MONO, fontSize: '10.5px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1.2px', padding: '6px 11px', borderRadius: '8px', border: '1px solid rgba(255,255,255,0.07)', background: 'rgba(255,255,255,0.025)', whiteSpace: 'nowrap' }
    }, role);

    const partnerCard = (p) => React.createElement('a', {
        key: p.id,
        href: p.url,
        target: '_blank',
        rel: 'noopener noreferrer',
        style: {
            flex: '1 1 320px', minWidth: isMobile ? 'auto' : '300px',
            borderRadius: '18px', background: '#141416', border: '1px solid rgba(255,255,255,0.06)',
            padding: '30px 30px 26px', display: 'flex', flexDirection: 'column',
            textDecoration: 'none', color: 'inherit',
            transition: 'transform .28s cubic-bezier(.2,.7,.3,1), border-color .28s cubic-bezier(.2,.7,.3,1)',
            animation: `ptUp ${p.delay} cubic-bezier(.2,.7,.3,1)`
        },
        onMouseEnter: (e) => { e.currentTarget.style.transform = 'translateY(-4px)'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.13)'; },
        onMouseLeave: (e) => { e.currentTarget.style.transform = 'none'; e.currentTarget.style.borderColor = 'rgba(255,255,255,0.06)'; }
    }, [
        React.createElement('div', { key: 'logo', style: { display: 'flex', alignItems: 'center', marginBottom: '30px', height: '54px' } },
            React.createElement('img', {
                src: p.logo, alt: p.name,
                style: { height: p.logoHeight, width: 'auto', maxWidth: '190px', objectFit: 'contain', display: 'block' }
            })
        ),
        React.createElement('h3', { key: 'name', style: { margin: '0 0 9px', fontSize: '21px', fontWeight: 800, letterSpacing: '-0.4px', color: '#f4f4f6' } }, p.name),
        React.createElement('p', { key: 'desc', style: { margin: '0 0 22px', fontSize: '14.5px', lineHeight: 1.6, color: '#9a9aa2' } }, p.desc),
        React.createElement('div', { key: 'foot', style: { marginTop: 'auto', paddingTop: '6px', display: 'flex', alignItems: 'center', gap: '12px' } }, [
            roleTag(p.role)
        ])
    ]);

    const inviteCard = React.createElement('a', {
        key: 'invite',
        href: formUrl,
        target: '_blank',
        rel: 'noopener noreferrer',
        style: {
            flex: '1 1 320px', minWidth: isMobile ? 'auto' : '300px',
            borderRadius: '18px', background: '#111113', border: '1px dashed rgba(255,255,255,0.12)',
            padding: '30px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
            textDecoration: 'none', color: 'inherit',
            transition: 'border-color .28s cubic-bezier(.2,.7,.3,1)',
            animation: 'ptUp .62s cubic-bezier(.2,.7,.3,1)'
        },
        onMouseEnter: (e) => { e.currentTarget.style.borderColor = 'rgba(240,137,42,0.4)'; },
        onMouseLeave: (e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.12)'; }
    }, [
        React.createElement('div', { key: 'top' }, [
            React.createElement('div', {
                key: 'icon',
                style: { width: '48px', height: '48px', borderRadius: '13px', display: 'grid', placeItems: 'center', background: 'rgba(240,137,42,0.12)', border: '1px solid rgba(240,137,42,0.28)', marginBottom: '24px' }
            }, svg('<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M19 8v6M22 11h-6"/>', 23, ACCENT, 1.9)),
            React.createElement('h3', { key: 'title', style: { margin: '0 0 8px', fontSize: '21px', fontWeight: 800, letterSpacing: '-0.4px', color: '#f4f4f6' } }, t('partners.inviteTitle')),
            React.createElement('p', { key: 'desc', style: { margin: 0, fontSize: '14.5px', lineHeight: 1.6, color: '#8a8a92' } }, t('partners.inviteDesc'))
        ]),
        React.createElement('span', {
            key: 'btn',
            style: {
                marginTop: '26px', width: '100%', display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '10px',
                padding: '15px 20px', borderRadius: '12px', border: 'none', background: ACCENT, color: '#1a0f04',
                fontFamily: SANS, fontSize: '15px', fontWeight: 700, cursor: 'pointer',
                boxShadow: '0 8px 24px rgba(240,137,42,0.28)', boxSizing: 'border-box',
                transition: 'background .2s cubic-bezier(.2,.7,.3,1), transform .2s cubic-bezier(.2,.7,.3,1)'
            }
        }, [
            t('partners.inviteCta'),
            svg('<path d="M5 12h14M13 6l6 6-6 6"/>', 17, 'currentColor', 2.2, 'sb-mirror-rtl')
        ])
    ]);

    const inner = React.createElement('div', {
        key: 'inner',
        style: { maxWidth: '1240px', margin: '0 auto', padding: isMobile ? '0 18px' : '0 40px' }
    }, [
        // Header
        React.createElement('div', { key: 'head', style: { marginBottom: '44px' } }, [
            React.createElement('div', {
                key: 'eyebrow',
                style: { fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1.6px', marginBottom: '14px' }
            }, t('partners.eyebrow')),
            // The heading used to share a flex row with a strapline; with that gone the
            // row had one child and nothing left to arrange.
            React.createElement('h2', {
                key: 'h2',
                style: { margin: 0, fontSize: isMobile ? '30px' : '40px', fontWeight: 800, letterSpacing: '-1.1px', lineHeight: 1.04, color: '#f4f4f6' }
            }, t('partners.heading'))
        ]),

        // Cards
        React.createElement('div', {
            key: 'cards',
            style: { display: 'flex', gap: '18px', alignItems: 'stretch', flexWrap: 'wrap' }
        }, [
            ...partners.map(partnerCard),
            inviteCard
        ])
    ]);

    return React.createElement('section', {
        style: {
            width: '100%', color: '#e8e8eb', fontFamily: SANS,
            padding: isMobile ? '48px 0' : '72px 0',
            background: 'radial-gradient(1100px 640px at 50% -6%, rgba(240,137,42,0.055), transparent 62%), #0f0f11'
        }
    }, [
        React.createElement('style', { key: 'kf', dangerouslySetInnerHTML: { __html: '@keyframes ptUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:translateY(0)}}' } }),
        inner
    ]);
};

window.BecomePartner = BecomePartner;
