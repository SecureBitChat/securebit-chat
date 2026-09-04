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

    // `rgb` is the same colour as `color`, published as bare channels. The pill draws
    // its fill and border from it at low alpha, and there is no way to add an alpha to
    // a colour that a custom property has already resolved — hence the pair, which has
    // to be kept in step.
    // Three forms of the same status colour, because they are used three ways and only
    // one of them is text. `color` is the word — it darkens in the light theme so it can
    // be read on white. `solid` is the dot, which is a mark rather than a label and
    // stays the brand colour in both themes. `rgb` is the channels, for the pill's fill
    // and border at low alpha. The three have to be kept in step.
    const META = {
        released: { word: t('roadmap.status.released'), color: "var(--sb-green)", solid: "var(--sb-green-solid)", rgb: "var(--sb-green-rgb)", line: "rgba(var(--sb-green-rgb), 0.32)" },
        current: { word: t('roadmap.status.current'), color: "var(--sb-orange)", solid: "var(--sb-orange-solid)", rgb: "var(--sb-orange-rgb)", line: "rgba(var(--sb-orange-rgb), 0.32)" },
        dev: { word: t('roadmap.status.dev'), color: "var(--sb-yellow-2)", solid: "var(--sb-yellow-2-solid)", rgb: "var(--sb-yellow-2-rgb)", line: "rgba(var(--sb-ink), 0.08)" },
        planned: { word: t('roadmap.status.planned'), color: "var(--sb-text-7)", solid: "var(--sb-text-7)", rgb: "var(--sb-text-7-rgb)", line: "rgba(var(--sb-ink), 0.08)" },
        research: { word: t('roadmap.status.research'), color: "var(--sb-text-9)", solid: "var(--sb-text-9)", rgb: "var(--sb-text-9-rgb)", line: "rgba(var(--sb-ink), 0.08)" }
    };

    const [open, setOpen] = React.useState({});
    const isOpen = (i) => (open[i] === undefined ? DATA[i].status === 'current' : open[i]);
    const toggle = (i) => setOpen((s) => ({ ...s, [i]: !isOpen(i) }));

    // Was hexA(), which took the literal hex out of META and split it into channels by
    // hand. Those literals are custom properties now, so there is nothing to parse at
    // runtime — the browser does the substitution instead, and it does it again when
    // the theme changes, which the old version could not.
    const tint = (channels, a) => `rgba(${channels}, ${a})`;

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
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(var(--sb-green-rgb), 0.16),rgba(var(--sb-green-rgb), 0.16)), var(--sb-bg)', border: '1px solid rgba(var(--sb-green-rgb), 0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--sb-green-solid)" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4 10-11" /></svg>
                </div>
            );
        }
        if (status === 'current') {
            return (
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(var(--sb-orange-rgb), 0.2),rgba(var(--sb-orange-rgb), 0.2)), var(--sb-bg)', border: '1px solid var(--sb-orange-solid)', zIndex: 2, animation: 'rmPulse 2.4s ease-out infinite' }}>
                    <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: 'var(--sb-orange-solid)' }} />
                </div>
            );
        }
        if (status === 'dev') {
            return (
                <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(var(--sb-yellow-2-rgb), 0.15),rgba(var(--sb-yellow-2-rgb), 0.15)), var(--sb-bg)', border: '1px solid rgba(var(--sb-yellow-2-rgb), 0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--sb-yellow-2-solid)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9" /></svg>
                </div>
            );
        }
        // planned / research
        return (
            <div style={{ position: 'absolute', insetInlineStart: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'var(--sb-bg)', border: `1px ${status === 'research' ? 'dashed' : 'solid'} rgba(var(--sb-ink), 0.18)`, zIndex: 2 }}>
                <span style={{ width: '7px', height: '7px', borderRadius: '50%', background: META[status].solid }} />
            </div>
        );
    };

    return (
        <section style={{ width: '100%', color: 'var(--sb-text-2)', fontFamily: SANS, padding: isMobile ? '48px 0' : '64px 0', background: 'radial-gradient(1200px 720px at 50% -8%, rgba(var(--sb-orange-rgb), 0.05), transparent 60%), var(--sb-bg)' }}>
            <style dangerouslySetInnerHTML={{ __html: '@keyframes rmExp{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}@keyframes rmPulse{0%,100%{box-shadow:0 0 0 0 rgba(var(--sb-orange-rgb), 0.18)}60%{box-shadow:0 0 0 9px rgba(var(--sb-orange-rgb), 0)}}' }} />

            <div style={{ maxWidth: '1040px', margin: '0 auto', padding: isMobile ? '0 18px' : '0 40px' }}>

                {/* header */}
                <div style={{ marginBottom: '30px' }}>
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: 'var(--sb-text-9)', textTransform: 'uppercase', letterSpacing: '1.6px', marginBottom: '13px' }}>{t('roadmap.eyebrow')}</div>
                    <h2 style={{ margin: '0 0 14px', fontSize: isMobile ? '27px' : '34px', fontWeight: 800, letterSpacing: '-1px', lineHeight: 1.08, color: 'var(--sb-text-1)' }}>{t('roadmap.heading')}</h2>
                    <p style={{ margin: 0, fontSize: '15.5px', lineHeight: 1.6, color: 'var(--sb-text-7)', maxWidth: '660px' }}>{t('roadmap.subheading')}</p>
                </div>

                {/* progress */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '18px', flexWrap: 'wrap', padding: '18px 22px', borderRadius: '14px', background: 'var(--sb-surface)', border: '1px solid rgba(var(--sb-ink), 0.06)', marginBottom: '36px' }}>
                    <div style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: 'var(--sb-text-2)', whiteSpace: 'nowrap' }}>{progressBefore}<span style={{ color: 'var(--sb-green)' }}>{shipped}</span>{progressAfter}</div>
                    <div style={{ flex: '1 1 240px', minWidth: '200px', height: '8px', borderRadius: '99px', background: 'var(--sb-bg-deep)', border: '1px solid rgba(var(--sb-ink), 0.06)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: shippedPct, background: 'linear-gradient(90deg, var(--sb-green), var(--sb-orange))' }} />
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: 'var(--sb-text-9)', textTransform: 'uppercase', letterSpacing: '0.8px', whiteSpace: 'nowrap' }}>{t('roadmap.upcoming', { upcoming })}</div>
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
                            <div style={{ borderRadius: '16px', background: 'var(--sb-surface)', border: `1px solid ${d.status === 'current' ? 'rgba(var(--sb-orange-rgb), 0.28)' : 'rgba(var(--sb-ink), 0.06)'}`, overflow: 'hidden' }}>
                                <div
                                    onClick={() => toggle(i)}
                                    style={{ display: 'flex', alignItems: 'center', gap: isMobile ? '11px' : '16px', padding: isMobile ? '16px 16px' : '18px 22px', cursor: 'pointer', transition: 'background .18s ease' }}
                                    onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(var(--sb-ink), 0.018)'; }}
                                    onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; }}
                                >
                                    <div style={{ flex: 'none', minWidth: '52px', textAlign: 'center', padding: '7px 10px', borderRadius: '9px', background: 'var(--sb-bg-deep)', border: '1px solid rgba(var(--sb-ink), 0.07)', fontFamily: MONO, fontSize: '13px', fontWeight: 700, color: d.status === 'current' ? 'var(--sb-orange)' : 'var(--sb-text-4)' }}>{d.v}</div>
                                    <div style={{ flex: 1, minWidth: 0 }}>
                                        <div style={{ fontSize: isMobile ? '15.5px' : '17px', fontWeight: 800, letterSpacing: '-0.4px', color: 'var(--sb-text-1)' }}>{d.title}</div>
                                        {!isMobile && <div style={{ marginTop: '3px', fontSize: '13.5px', color: 'var(--sb-text-6)' }}>{d.sub}</div>}
                                    </div>
                                    <div style={{ flex: 'none', display: 'flex', alignItems: 'center', gap: isMobile ? '8px' : '14px' }}>
                                        {/* The status pill is desktop-only. On a phone its
                                            word does not fit, and what was left — a bordered
                                            box around a single coloured dot — said nothing the
                                            marker on the timeline was not already saying in
                                            the same colour, while taking room from the title.
                                            So the whole pill goes, not just its label. */}
                                        {!isMobile && (
                                            <span style={{ display: 'inline-flex', alignItems: 'center', gap: '7px', padding: '6px 11px', borderRadius: '8px', background: tint(meta.rgb, 0.1), border: `1px solid ${tint(meta.rgb, 0.22)}`, fontFamily: MONO, fontSize: '10.5px', fontWeight: 600, color: meta.color, textTransform: 'uppercase', letterSpacing: '0.8px', whiteSpace: 'nowrap' }}>
                                                <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: meta.solid }} />
                                                {meta.word}
                                            </span>
                                        )}
                                        {!isMobile && <span style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 500, color: 'var(--sb-text-7)', whiteSpace: 'nowrap', minWidth: '74px', textAlign: 'end' }}>{d.date}</span>}
                                        <span style={{ color: 'var(--sb-text-9)', display: 'inline-flex', transition: 'transform .22s cubic-bezier(.2,.7,.3,1)', transform: opened ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                                            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6" /></svg>
                                        </span>
                                    </div>
                                </div>
                                {opened && (
                                    <div style={{ padding: '4px 22px 22px 22px', animation: 'rmExp .24s cubic-bezier(.2,.7,.3,1)' }}>
                                        <div style={{ fontFamily: MONO, fontSize: '10px', fontWeight: 600, color: 'var(--sb-text-faint)', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '14px', paddingTop: '14px', borderTop: '1px solid rgba(var(--sb-ink), 0.05)' }}>{t('roadmap.keyFeatures')}</div>
                                        <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : '1fr 1fr', gap: '11px 28px' }}>
                                            {d.features.map((f, fi) => (
                                                <div key={fi} style={{ display: 'flex', alignItems: 'flex-start', gap: '10px' }}>
                                                    <span style={{ flex: 'none', marginTop: '7px', width: '5px', height: '5px', borderRadius: '50%', background: meta.solid }} />
                                                    <span style={{ fontSize: '13.5px', lineHeight: 1.5, color: 'var(--sb-text-4)' }}>{f}</span>
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
