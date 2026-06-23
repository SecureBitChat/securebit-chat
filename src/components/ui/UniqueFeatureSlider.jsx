// "Why SecureBit is unique" — interactive accordion section.
// Translated from the Claude Design component (Why Unique.dc.html) into the
// project's React.createElement style. Five horizontal panels; the active one
// expands to reveal full content, the rest collapse to a vertical spine label.
const UniqueFeatureSlider = () => {
  const [active, setActive] = React.useState(0);
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
  const ACTIVE_BG = 'radial-gradient(130% 90% at 28% 0%, rgba(240,137,42,0.11), transparent 60%), #141416';
  const ACTIVE_BD = 'rgba(240,137,42,0.3)';
  const IDLE_BG = '#111113';
  const IDLE_BD = 'rgba(255,255,255,0.06)';
  const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
  const SANS = "'Manrope', system-ui, -apple-system, sans-serif";

  const slides = [
    {
      num: '01',
      title: ['Layered', 'encryption core'],
      collapsed: 'Encryption core',
      desc: 'ECDH P-384 key exchange, AES-256-GCM payloads, ECDSA signatures and full ASN.1 validation — composed into one hardened pipeline.',
      tags: ['ECDH P-384', 'AES-256-GCM', 'ECDSA', 'ASN.1'],
      icon: '<path d="M12 3l8 4v5c0 4.5-3.2 7.8-8 9-4.8-1.2-8-4.5-8-9V7l8-4z"/><path d="M9.2 12.2l2 2 3.6-3.8"/>'
    },
    {
      num: '02',
      title: ['Pure P2P', 'WebRTC'],
      collapsed: 'Pure P2P WebRTC',
      desc: 'Messages travel directly between devices over WebRTC. No relay holds your data — the server only helps two peers find each other.',
      tags: ['DTLS 1.3', 'No relay'],
      icon: '<circle cx="5.5" cy="12" r="2.5"/><circle cx="18.5" cy="6" r="2.5"/><circle cx="18.5" cy="18" r="2.5"/><path d="M7.8 10.8l8.4-3.6M7.8 13.2l8.4 3.6"/>'
    },
    {
      num: '03',
      title: ['Perfect', 'forward secrecy'],
      collapsed: 'Forward secrecy',
      desc: 'Session keys rotate continuously and are discarded after use, so a single compromised key can never unlock past conversations.',
      tags: ['Ephemeral keys', 'Auto-rotate'],
      icon: '<path d="M21 8a8.5 8.5 0 0 0-15.6-2.5M3 4v4h4"/><path d="M3 16a8.5 8.5 0 0 0 15.6 2.5M21 20v-4h-4"/>'
    },
    {
      num: '04',
      title: ['Traffic', 'obfuscation'],
      collapsed: 'Traffic obfuscation',
      desc: 'Packet sizes and timing are padded and randomized, hiding metadata patterns from anyone watching the wire.',
      tags: ['Packet padding', 'Timing jitter'],
      icon: '<path d="M3 7h4l3 10h4M14 7h3l3 0"/><path d="M17 4l3 3-3 3"/><path d="M3 17h4l2-6"/>'
    },
    {
      num: '05',
      title: ['Zero data', 'collection'],
      collapsed: 'Zero data collection',
      desc: 'No accounts, no logs, no message storage. There is nothing on a server to leak, subpoena, or sell.',
      tags: ['No accounts', 'No logs'],
      icon: '<path d="M9.9 5.1A9.6 9.6 0 0 1 12 5c5.5 0 9 5 9 7a11 11 0 0 1-2.2 3M6.3 7.3C3.6 8.9 2 11.2 2 12c0 1.4 3.5 7 10 7 1.6 0 3-.3 4.2-.8"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2M3 3l18 18"/>'
    }
  ];

  const svg = (inner, size, stroke, sw) =>
    React.createElement('svg', {
      width: size, height: size, viewBox: '0 0 24 24', fill: 'none',
      stroke, strokeWidth: sw, strokeLinecap: 'round', strokeLinejoin: 'round',
      dangerouslySetInnerHTML: { __html: inner }
    });

  const go = (step) =>
    setActive((a) => (a + step + slides.length) % slides.length);

  const navBtn = (key, onClick, path) =>
    React.createElement('button', {
      key, onClick, 'aria-label': key,
      style: {
        width: '46px', height: '46px', display: 'grid', placeItems: 'center',
        borderRadius: '50%', border: '1px solid rgba(255,255,255,0.1)',
        background: 'rgba(255,255,255,0.025)', color: '#cfcfd4', cursor: 'pointer',
        transition: 'all .2s cubic-bezier(.2,.7,.3,1)'
      },
      onMouseEnter: (e) => { e.currentTarget.style.borderColor = ACTIVE_BD; e.currentTarget.style.color = ACCENT; },
      onMouseLeave: (e) => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.1)'; e.currentTarget.style.color = '#cfcfd4'; }
    }, svg(path, 18, 'currentColor', 2.1));

  const tag = (label) =>
    React.createElement('span', {
      key: label,
      style: {
        display: 'inline-flex', alignItems: 'center', gap: '7px', padding: '7px 12px',
        borderRadius: '9px', border: '1px solid rgba(255,255,255,0.07)',
        background: 'rgba(255,255,255,0.025)', fontFamily: MONO,
        fontSize: '11.5px', fontWeight: 500, color: '#9a9aa2'
      }
    }, [
      React.createElement('span', { key: 'dot', style: { width: '5px', height: '5px', borderRadius: '50%', background: '#3ecf8e' } }),
      label
    ]);

  const expandedContent = (s) =>
    React.createElement('div', {
      key: 'exp',
      style: {
        height: '100%', display: 'flex', flexDirection: 'column',
        justifyContent: isMobile ? 'flex-start' : 'space-between',
        gap: isMobile ? '18px' : 0,
        padding: isMobile ? '24px 22px' : '32px 34px',
        minWidth: isMobile ? 'auto' : '320px',
        animation: 'wuUp .42s cubic-bezier(.2,.7,.3,1)'
      }
    }, [
      React.createElement('div', { key: 'top', style: { display: 'flex', alignItems: 'center', justifyContent: 'space-between' } }, [
        React.createElement('div', {
          key: 'ic',
          style: {
            width: '54px', height: '54px', borderRadius: '15px', display: 'grid', placeItems: 'center',
            background: 'rgba(240,137,42,0.13)', border: '1px solid rgba(240,137,42,0.3)'
          }
        }, svg(s.icon, 26, ACCENT, 1.9)),
        React.createElement('span', { key: 'n', style: { fontFamily: MONO, fontSize: '13px', fontWeight: 600, color: '#6b6b73' } }, s.num)
      ]),
      React.createElement('div', { key: 'mid' }, [
        React.createElement('h3', {
          key: 'h', style: { margin: '0 0 12px', fontSize: isMobile ? '24px' : '30px', fontWeight: 800, letterSpacing: '-0.7px', lineHeight: 1.08, color: '#f4f4f6' }
        }, [s.title[0], React.createElement('br', { key: 'br' }), s.title[1]]),
        React.createElement('p', {
          key: 'p', style: { margin: 0, fontSize: '15px', lineHeight: 1.6, color: '#9a9aa2', maxWidth: '380px' }
        }, s.desc)
      ]),
      React.createElement('div', { key: 'tags', style: { display: 'flex', flexWrap: 'wrap', gap: '8px' } }, s.tags.map(tag))
    ]);

  const collapsedContent = (s) => isMobile
    ? React.createElement('div', {
        key: 'col',
        style: { display: 'flex', alignItems: 'center', gap: '16px', padding: '20px 22px' }
      }, [
        React.createElement('span', { key: 'n', style: { fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: '#56565e' } }, s.num),
        React.createElement('span', { key: 'l', style: { fontSize: '16px', fontWeight: 800, letterSpacing: '-0.2px', color: '#cfcfd4' } }, s.collapsed)
      ])
    : React.createElement('div', {
        key: 'col',
        style: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between', padding: '24px 0' }
      }, [
        React.createElement('span', { key: 'n', style: { fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: '#56565e' } }, s.num),
        React.createElement('span', {
          key: 'l',
          style: { writingMode: 'vertical-rl', transform: 'rotate(180deg)', fontSize: '17px', fontWeight: 800, letterSpacing: '-0.2px', color: '#cfcfd4', whiteSpace: 'nowrap' }
        }, s.collapsed),
        svg(s.icon, 22, '#56565e', 1.8)
      ]);

  const panels = slides.map((s, i) => {
    const isActive = active === i;
    return React.createElement('div', {
      key: i,
      onClick: () => setActive(i),
      // Selection is click-only (like the design); hover just brightens the panel
      // a touch so the orange glow never jumps around chasing the cursor.
      onMouseEnter: (e) => { if (!isActive) e.currentTarget.style.filter = 'brightness(1.18)'; },
      onMouseLeave: (e) => { e.currentTarget.style.filter = 'none'; },
      style: {
        flex: isMobile ? 'none' : (isActive ? 6.2 : 1),
        minWidth: isMobile ? 'auto' : '72px',
        position: 'relative',
        borderRadius: '18px',
        overflow: 'hidden',
        cursor: 'pointer',
        background: isActive ? ACTIVE_BG : IDLE_BG,
        border: '1px solid ' + (isActive ? ACTIVE_BD : IDLE_BD),
        color: '#8a8a92',
        transition: 'flex .46s cubic-bezier(.2,.7,.3,1), background .3s ease, border-color .3s ease, filter .2s ease'
      }
    }, isActive ? expandedContent(s) : collapsedContent(s));
  });

  const inner = React.createElement('div', {
    key: 'inner',
    style: {
      maxWidth: '1180px', margin: '0 auto',
      padding: isMobile ? '0 18px' : '0 40px'
    }
  }, [
    // Header
    React.createElement('div', {
      key: 'head',
      style: { display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between', gap: '24px', marginBottom: '28px' }
    }, [
      React.createElement('div', { key: 'titles' }, [
        React.createElement('div', {
          key: 'eyebrow',
          style: { fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1.4px', marginBottom: '12px' }
        }, 'What sets us apart'),
        React.createElement('h2', {
          key: 'h2',
          style: { margin: 0, fontSize: isMobile ? '28px' : '38px', fontWeight: 800, letterSpacing: '-1.1px', lineHeight: 1.05, color: '#f4f4f6' }
        }, 'Why SecureBit is unique')
      ]),
      React.createElement('div', { key: 'nav', style: { display: 'flex', alignItems: 'center', gap: '10px', flex: 'none' } }, [
        navBtn('prev', () => go(-1), '<path d="M15 6l-6 6 6 6"/>'),
        navBtn('next', () => go(1), '<path d="M9 6l6 6-6 6"/>')
      ])
    ]),

    // Accordion
    React.createElement('div', {
      key: 'accordion',
      style: {
        display: 'flex',
        flexDirection: isMobile ? 'column' : 'row',
        gap: isMobile ? '12px' : '14px',
        height: isMobile ? 'auto' : '440px'
      }
    }, panels)
  ]);

  // Full-bleed dark band with the radial accent glow — matches the design mockup.
  return React.createElement('section', {
    style: {
      width: '100%', color: '#e8e8eb', fontFamily: SANS,
      padding: isMobile ? '44px 0' : '64px 0',
      background: 'radial-gradient(1100px 700px at 18% 8%, rgba(240,137,42,0.05), transparent 60%), #0f0f11'
    }
  }, [
    React.createElement('style', { key: 'kf', dangerouslySetInnerHTML: { __html: '@keyframes wuUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}' } }),
    inner
  ]);
};

// Export for use in your app
window.UniqueFeatureSlider = UniqueFeatureSlider;
