import { t, tList } from '../../i18n/index.js';

// "Development Roadmap" — milestone timeline section.
// Translated from the Claude Design component (Roadmap.dc.html): a full-bleed
// dark band with a shipped-progress bar and an expandable, status-coded timeline.
function Roadmap() {
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

    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";
    const SANS = "'Manrope', system-ui, -apple-system, sans-serif";

    const DATA = [
        { v: "v1.0", k: 'r1', status: "released" },
        { v: "v1.5", k: 'r2', status: "released" },
        { v: "v2.0", k: 'r3', status: "released" },
        { v: "v3.0", k: 'r4', status: "released" },
        { v: "v3.5", k: 'r5', status: "released" },
        { v: "v4.5", k: 'r6', status: "released" },
        { v: "v5.0", k: 'r7', status: "released" },
        { v: "v5.5", k: 'r8', status: "released" },
        { v: "v6.0", k: 'r9', status: "current" },
        { v: "v6.5", k: 'r10', status: "dev" },
        { v: "v7.0", k: 'r11', status: "planned" },
        { v: "v7.5", k: 'r12', status: "research" },
        { v: "v8.0", k: 'r13', status: "research" }
    ].map((d) => ({
        ...d,
        // Version tag and status are identifiers, not copy; everything a reader
        // actually reads comes from the locale file.
        title: t(`roadmap.${d.k}.title`),
        sub: t(`roadmap.${d.k}.sub`),
        date: t(`roadmap.${d.k}.date`),
        features: tList(`roadmap.${d.k}.features`)
    }));

    const META = {
        released: { word: t('roadmap.status.released'), color: "#3ecf8e", line: "rgba(62,207,142,0.32)" },
        current: { word: t('roadmap.status.current'), color: "#f0892a", line: "rgba(240,137,42,0.32)" },
        dev: { word: t('roadmap.status.dev'), color: "#e3b341", line: "rgba(255,255,255,0.08)" },
        planned: { word: t('roadmap.status.planned'), color: "#8a8a92", line: "rgba(255,255,255,0.08)" },
        research: { word: t('roadmap.status.research'), color: "#6b6b73", line: "rgba(255,255,255,0.08)" }
    };

    const [open, setOpen] = React.useState({});
    const isOpen = (i) => (open[i] === undefined ? DATA[i].status === 'current' : open[i]);
    const toggle = (i) => setOpen((s) => ({ ...s, [i]: !isOpen(i) }));

    const hexA = (hex, a) => {
        const n = parseInt(hex.slice(1), 16);
        return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
    };

    const total = DATA.length;
    const shipped = DATA.filter((d) => d.status === 'released' || d.status === 'current').length;
    const upcoming = total - shipped;
    const shippedPct = (shipped / total * 100).toFixed(1) + '%';

    // The shipped count is highlighted, so the sentence is split around it rather than
    // interpolated whole. Passing only `total` leaves the {shipped} placeholder in the
    // string, which is where the highlighted number goes — a translation is free to put
    // it anywhere in the sentence, and the highlight follows it there.
    const [progressBefore, progressAfter] = t('roadmap.progress', { total }).split('{shipped}');

    const renderNode = (status) => {
        if (status === 'released') {
            return (
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(62,207,142,0.16),rgba(62,207,142,0.16)), #0f0f11', border: '1px solid rgba(62,207,142,0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4 10-11" /></svg>
                </div>
            );
        }
        if (status === 'current') {
            return (
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(240,137,42,0.2),rgba(240,137,42,0.2)), #0f0f11', border: '1px solid #f0892a', zIndex: 2, animation: 'rmPulse 2.4s ease-out infinite' }}>
                    <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: '#f0892a' }} />
                </div>
            );
        }
        if (status === 'dev') {
            return (
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(227,179,65,0.15),rgba(227,179,65,0.15)), #0f0f11', border: '1px solid rgba(227,179,65,0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9" /></svg>
                </div>
            );
        }
        // planned / research
        return (
            <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: '#0f0f11', border: `1px ${status === 'research' ? 'dashed' : 'solid'} rgba(255,255,255,0.18)`, zIndex: 2 }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: META[status].color }} />
            </div>
        );
    };

    return (
        <section style={{ width: '100%', color: '#e8e8eb', fontFamily: SANS, padding: isMobile ? '48px 0' : '64px 0', background: 'radial-gradient(1200px 720px at 50% -8%, rgba(240,137,42,0.05), transparent 60%), #0f0f11' }}>
            <style dangerouslySetInnerHTML={{ __html: '@keyframes rmExp{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}@keyframes rmPulse{0%,100%{box-shadow:0 0 0 0 rgba(240,137,42,0.18)}60%{box-shadow:0 0 0 9px rgba(240,137,42,0)}}' }} />

            <div style={{ maxWidth: '1040px', margin: '0 auto', padding: isMobile ? '0 18px' : '0 40px' }}>

                {/* header */}
                <div style={{ marginBottom: '30px' }}>
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1.6px', marginBottom: '13px' }}>{t('roadmap.eyebrow')}</div>
                    <h2 style={{ margin: '0 0 14px', fontSize: isMobile ? '27px' : '34px', fontWeight: 800, letterSpacing: '-1px', lineHeight: 1.08, color: '#f4f4f6' }}>{t('roadmap.heading')}</h2>
                    <p style={{ margin: 0, fontSize: '15.5px', lineHeight: 1.6, color: '#8a8a92', maxWidth: '660px' }}>{t('roadmap.subheading')}</p>
                </div>

                {/* progress */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '18px', flexWrap: 'wrap', padding: '18px 22px', borderRadius: '14px', background: '#141416', border: '1px solid rgba(255,255,255,0.06)', marginBottom: '36px' }}>
                    <div style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: '#e8e8eb', whiteSpace: 'nowrap' }}>{progressBefore}<span style={{ color: '#3ecf8e' }}>{shipped}</span>{progressAfter}</div>
                    <div style={{ flex: '1 1 240px', minWidth: '200px', height: '8px', borderRadius: '99px', background: '#0c0c0e', border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: shippedPct, background: 'linear-gradient(90deg, #3ecf8e, #f0892a)' }} />
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '0.8px', whiteSpace: 'nowrap' }}>{t('roadmap.upcoming', { upcoming })}</div>
                </div>

                {/* timeline */}
                {DATA.map((d, i) => {
                    const meta = META[d.status];
                    const opened = isOpen(i);
                    const notLast = i < total - 1;
                    return (
                        <div key={i} style={{ position: 'relative', display: 'grid', gridTemplateColumns: '54px 1fr', marginBottom: '16px' }}>

                            {/* spine */}
                            <div style={{ position: 'relative' }}>
                                {notLast && <div style={{ position: 'absolute', insetInlineStart: '26px', top: '30px', height: 'calc(100% + 16px)', width: '2px', background: meta.line }} />}
                                {renderNode(d.status)}
                            </div>

                            {/* card */}
                            <div style={{ borderRadius: '16px', background: '#141416', border: `1px solid ${d.status === 'current' ? 'rgba(240,137,42,0.28)' : 'rgba(255,255,255,0.06)'}`, overflow: 'hidden' }}>
                                <div
                                    onClick={() => toggle(i)}
                                    style={{ display: 'flex', alignItems: 'center', gap: isMobile ? '11px' : '16px', padding: isMobile ? '16px 16px' : '18px 22px', cursor: 'pointer', transition: 'background .18s ease' }}
                                    onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(255,255,255,0.018)'; }}
                                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                                >
                                    <div style={{ flex: 'none', minWidth: '52px', textAlign: 'center', padding: '7px 10px', borderRadius: '9px', background: '#0c0c0e', border: '1px solid rgba(255,255,255,0.07)', fontFamily: MONO, fontSize: '13px', fontWeight: 700, color: d.status === 'current' ? '#f0892a' : '#cfcfd4' }}>{d.v}</div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ fontSize: isMobile ? '15.5px' : '17px', fontWeight: 800, letterSpacing: '-0.4px', color: '#f4f4f6' }}>{d.title}</div>
                                        {!isMobile && <div style={{ marginTop: '3px', fontSize: '13.5px', color: '#9a9aa2' }}>{d.sub}</div>}
                                    </div>
                                    <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: isMobile ? '8px' : '14px' }}>
                                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: '7px', padding: '6px 11px', borderRadius: '8px', background: hexA(meta.color, 0.1), border: `1px solid ${hexA(meta.color, 0.22)}`, fontFamily: MONO, fontSize: '10.5px', fontWeight: 600, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.8px', whiteSpace: 'nowrap' }}>
                                            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: meta.color }} />
                                            {!isMobile && meta.word}
                                        </span>
                                        {!isMobile && <span style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 500, color: '#8a8a92', whiteSpace: 'nowrap', minWidth: '74px', textAlign: 'end' }}>{d.date}</span>}
                                        <span style={{ color: '#6b6b73', display: 'inline-flex', transition: 'transform .22s cubic-bezier(.2,.7,.3,1)', transform: opened ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                                            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6" /></svg>
                                        </span>
                                    </div>
                                </div>
                                {opened && (
                                    <div style={{ padding: '4px 22px 22px 22px', animation: 'rmExp .24s cubic-bezier(.2,.7,.3,1)' }}>
                                        <div style={{ fontFamily: MONO, fontSize: '10px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '14px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>{t('roadmap.keyFeatures')}</div>
                                        <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '11px 28px' }}>
                                            {d.features.map((f, fi) => (
                                                <div key={fi} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                                                    <span style={{ flex: 'none', marginTop: '7px', width: '5px', height: '5px', borderRadius: '50%', background: meta.color }} />
                                                    <span style={{ fontSize: '13.5px', lineHeight: 1.5, color: '#cfcfd4' }}>{f}</span>
                                                </div>
                                            ))}
                                        </div>
                                    </div>
                                )}
                            </div>
                        </div>
                    );
                })}

            </div>
        </section>
    );
}

window.Roadmap = Roadmap;
