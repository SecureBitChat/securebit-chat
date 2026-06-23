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
        { v: "v1.0", title: "Start of Development", sub: "Idea, prototype, and infrastructure setup", status: "released", date: "Early 2025",
          features: ["Concept and requirements formation", "Stack selection: WebRTC, P2P, cryptography", "First messaging prototypes", "Repository creation and CI", "Basic encryption architecture", "UX/UI design"] },
        { v: "v1.5", title: "Alpha Release", sub: "First public alpha: basic chat and key exchange", status: "released", date: "Spring 2025",
          features: ["Basic P2P messaging via WebRTC", "Simple E2E encryption (demo scheme)", "Stable signaling and reconnection", "Minimal UX for testing", "Feedback collection from early testers"] },
        { v: "v2.0", title: "Security Hardened", sub: "Security strengthening and stable branch release", status: "released", date: "Summer 2025",
          features: ["ECDH/ECDSA implementation in production", "Perfect Forward Secrecy and key rotation", "Improved authentication checks", "File encryption and large payload transfers", "Audit of basic cryptoprocesses"] },
        { v: "v3.0", title: "Scaling & Stability", sub: "Network scaling and stability improvements", status: "released", date: "Fall 2025",
          features: ["Optimization of P2P connections and NAT traversal", "Reconnection mechanisms and message queues", "Reduced battery consumption on mobile", "Multi-device synchronization support", "Monitoring and logging tools for developers"] },
        { v: "v3.5", title: "Privacy-first Release", sub: "Focus on privacy: minimizing metadata", status: "released", date: "Winter 2025",
          features: ["Metadata protection and fingerprint reduction", "Experiments with onion routing and DHT", "Options for anonymous connections", "Preparation for open code audit", "Improved user verification processes"] },
        { v: "v4.5", title: "Enhanced Security Edition", sub: "18-layer military-grade cryptography with complete ASN.1 validation", status: "released", date: "Late 2025",
          features: ["ECDH + DTLS + SAS triple-layer security", "ECDH P-384 + AES-GCM 256-bit encryption", "DTLS fingerprint verification", "SAS (Short Authentication String) verification", "Perfect Forward Secrecy with key rotation", "Enhanced MITM attack prevention", "Complete ASN.1 DER validation", "OID and EC point verification", "SPKI structure validation", "P2P WebRTC architecture", "Metadata protection", "100% open source code"] },
        { v: "v4.7", title: "Desktop Edition", sub: "Native desktop apps for Windows, macOS, and Linux", status: "current", date: "Now",
          features: ["Windows desktop app (Tauri v2)", "macOS desktop app (Tauri v2)", "Linux AppImage support (Tauri v2)", "Real-time notifications", "Automatic reconnection", "Cross-device synchronization", "Improved UX/UI", "Support for files up to 100MB"] },
        { v: "v5.0", title: "Mobile Edition", sub: "Native mobile apps for iOS and Android", status: "dev", date: "Q1 2026",
          features: ["iOS native app (Swift/SwiftUI)", "Android native app (Kotlin/Jetpack Compose)", "PWA support for mobile browsers", "Real-time push notifications", "Battery optimization", "Mobile-optimized UX/UI", "Offline message queuing", "Biometric authentication"] },
        { v: "v5.5", title: "Quantum-Resistant Edition", sub: "Protection against quantum computers", status: "planned", date: "Q2 2026",
          features: ["Post-quantum cryptography CRYSTALS-Kyber", "SPHINCS+ digital signatures", "Hybrid scheme: classic + PQ", "Quantum-safe key exchange", "Updated hashing algorithms", "Migration of existing sessions", "Compatibility with v4.x", "Quantum-resistant protocols"] },
        { v: "v6.0", title: "Group Communications", sub: "Group chats with preserved privacy", status: "planned", date: "Q4 2026",
          features: ["P2P group connections up to 8 participants", "Mesh networking for groups", "Signal Double Ratchet for groups", "Anonymous groups without metadata", "Ephemeral groups (disappear after session)", "Cryptographic group administration", "Group member auditing"] },
        { v: "v6.5", title: "Decentralized Network", sub: "Fully decentralized network", status: "research", date: "2027",
          features: ["Node mesh network", "DHT for peer discovery", "Built-in onion routing", "Tokenomics and node incentives", "Governance via DAO", "Interoperability with other networks", "Cross-platform compatibility", "Self-healing network"] },
        { v: "v7.0", title: "AI Privacy Assistant", sub: "AI for privacy and security", status: "research", date: "2028+",
          features: ["Local AI threat analysis", "Automatic MITM detection", "Adaptive cryptography", "Personalized security recommendations", "Zero-knowledge machine learning", "Private AI assistant", "Predictive security", "Autonomous attack protection"] }
    ];

    const META = {
        released: { word: "Released", color: "#3ecf8e", line: "rgba(62,207,142,0.32)" },
        current: { word: "Current", color: "#f0892a", line: "rgba(240,137,42,0.32)" },
        dev: { word: "In development", color: "#e3b341", line: "rgba(255,255,255,0.08)" },
        planned: { word: "Planned", color: "#8a8a92", line: "rgba(255,255,255,0.08)" },
        research: { word: "Research", color: "#6b6b73", line: "rgba(255,255,255,0.08)" }
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

    const renderNode = (status) => {
        if (status === 'released') {
            return (
                <div style={{ position: 'absolute', left: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(62,207,142,0.16),rgba(62,207,142,0.16)), #0f0f11', border: '1px solid rgba(62,207,142,0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#3ecf8e" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round"><path d="M5 13l4 4 10-11" /></svg>
                </div>
            );
        }
        if (status === 'current') {
            return (
                <div style={{ position: 'absolute', left: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(240,137,42,0.2),rgba(240,137,42,0.2)), #0f0f11', border: '1px solid #f0892a', zIndex: 2, animation: 'rmPulse 2.4s ease-out infinite' }}>
                    <span style={{ width: '9px', height: '9px', borderRadius: '50%', background: '#f0892a' }} />
                </div>
            );
        }
        if (status === 'dev') {
            return (
                <div style={{ position: 'absolute', left: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'linear-gradient(rgba(227,179,65,0.15),rgba(227,179,65,0.15)), #0f0f11', border: '1px solid rgba(227,179,65,0.4)', zIndex: 2 }}>
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="#e3b341" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3a9 9 0 1 0 9 9" /></svg>
                </div>
            );
        }
        // planned / research
        return (
            <div style={{ position: 'absolute', left: '13px', top: '16px', width: '28px', height: '28px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: '#0f0f11', border: `1px ${status === 'research' ? 'dashed' : 'solid'} rgba(255,255,255,0.18)`, zIndex: 2 }}>
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
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '1.6px', marginBottom: '13px' }}>Development Roadmap</div>
                    <h2 style={{ margin: '0 0 14px', fontSize: isMobile ? '27px' : '34px', fontWeight: 800, letterSpacing: '-1px', lineHeight: 1.08, color: '#f4f4f6' }}>The evolution of SecureBit</h2>
                    <p style={{ margin: 0, fontSize: '15.5px', lineHeight: 1.6, color: '#8a8a92', maxWidth: '660px' }}>From the first prototype to a quantum-resistant, decentralized network — with complete ASN.1 validation at every layer.</p>
                </div>

                {/* progress */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '18px', flexWrap: 'wrap', padding: '18px 22px', borderRadius: '14px', background: '#141416', border: '1px solid rgba(255,255,255,0.06)', marginBottom: '36px' }}>
                    <div style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 600, color: '#e8e8eb', whiteSpace: 'nowrap' }}><span style={{ color: '#3ecf8e' }}>{shipped}</span> of {total} milestones shipped</div>
                    <div style={{ flex: '1 1 240px', minWidth: '200px', height: '8px', borderRadius: '99px', background: '#0c0c0e', border: '1px solid rgba(255,255,255,0.06)', overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: shippedPct, background: 'linear-gradient(90deg, #3ecf8e, #f0892a)' }} />
                    </div>
                    <div style={{ fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#6b6b73', textTransform: 'uppercase', letterSpacing: '0.8px', whiteSpace: 'nowrap' }}>{upcoming} on the way</div>
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
                                {notLast && <div style={{ position: 'absolute', left: '26px', top: '30px', height: 'calc(100% + 16px)', width: '2px', background: meta.line }} />}
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
                                        {!isMobile && <span style={{ fontFamily: MONO, fontSize: '12px', fontWeight: 500, color: '#8a8a92', whiteSpace: 'nowrap', minWidth: '74px', textAlign: 'right' }}>{d.date}</span>}
                                        <span style={{ color: '#6b6b73', display: 'inline-flex', transition: 'transform .22s cubic-bezier(.2,.7,.3,1)', transform: opened ? 'rotate(180deg)' : 'rotate(0deg)' }}>
                                            <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.1" strokeLinecap="round" strokeLinejoin="round"><path d="M6 9l6 6 6-6" /></svg>
                                        </span>
                                    </div>
                                </div>
                                {opened && (
                                    <div style={{ padding: '4px 22px 22px 22px', animation: 'rmExp .24s cubic-bezier(.2,.7,.3,1)' }}>
                                        <div style={{ fontFamily: MONO, fontSize: '10px', fontWeight: 600, color: '#56565e', textTransform: 'uppercase', letterSpacing: '1.2px', marginBottom: '14px', paddingTop: '14px', borderTop: '1px solid rgba(255,255,255,0.05)' }}>Key features</div>
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
