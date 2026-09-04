import { t, direction } from '../../i18n/index.js';
// Advanced network settings: lets a user supply their own STUN/TURN servers
// instead of the bundled public defaults, and toggle relay-only privacy mode.
// Free / power-user feature, hidden behind an explicit "Advanced" entry point.
//
// All input is validated through src/network/iceServers.js before it can reach
// RTCPeerConnection. Persistence is opt-in and encrypted at rest (see
// src/network/iceSettingsStore.js).
import {
    parseIceServersInput,
    listHasTurn,
    ICE_LIMITS
} from '../../network/iceServers.js';

const React = window.React;

const PLACEHOLDER = [
    '# One URL per line, e.g.:',
    'stun:stun.example.com:3478',
    'turn:turn.example.com:3478?transport=udp',
    '',
    '# Or paste JSON for servers with credentials:',
    '[{"urls":"turns:turn.example.com:5349","username":"user","credential":"secret"}]'
].join('\n');

async function testIceServers(servers, timeoutMs = 6000) {
    const found = { host: 0, srflx: 0, relay: 0 };
    if (typeof RTCPeerConnection === 'undefined') {
        return { ...found, error: t('ice.errUnavailable') };
    }
    let pc;
    try {
        pc = new RTCPeerConnection({ iceServers: servers });
    } catch (error) {
        return { ...found, error: error.message || t('ice.errInvalid') };
    }

    return new Promise((resolve) => {
        let settled = false;
        const finish = () => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            try { pc.close(); } catch { /* noop */ }
            resolve(found);
        };
        const timer = setTimeout(finish, timeoutMs);

        pc.onicecandidate = (event) => {
            if (!event.candidate) { finish(); return; }
            const c = event.candidate.candidate || '';
            if (/ typ host/.test(c)) found.host++;
            else if (/ typ srflx/.test(c)) found.srflx++;
            else if (/ typ relay/.test(c)) found.relay++;
        };

        try {
            pc.createDataChannel('securebit-ice-test');
            pc.createOffer()
                .then((offer) => pc.setLocalDescription(offer))
                .catch(() => finish());
        } catch {
            finish();
        }
    });
}

const IceServerSettings = ({ isOpen, onClose, initial, hasSaved, onApply, onForget, embedded }) => {
    if (!isOpen) return null;

    const [useCustom, setUseCustom] = React.useState(initial?.useCustom || false);
    const [serversText, setServersText] = React.useState(initial?.serversText || '');
    const [relayOnly, setRelayOnly] = React.useState(initial?.privacyMode === 'relay-only');
    const [persist, setPersist] = React.useState(initial?.persisted || false);
    const [testState, setTestState] = React.useState('idle'); // idle | running | done
    const [testResult, setTestResult] = React.useState(null);

    const parsed = useCustom ? parseIceServersInput(serversText) : { servers: [], errors: [], warnings: [] };
    const hasTurn = listHasTurn(parsed.servers);
    const canApply = !useCustom || (parsed.servers.length > 0 && parsed.errors.length === 0);

    const handleTest = async () => {
        setTestState('running');
        setTestResult(null);
        const result = await testIceServers(parsed.servers);
        setTestResult(result);
        setTestState('done');
    };

    const handleApply = () => {
        if (!canApply) return;
        onApply(
            {
                useCustom,
                servers: useCustom ? parsed.servers : [],
                privacyMode: relayOnly ? 'relay-only' : 'standard',
                serversText
            },
            persist
        );
    };

    const handleForget = async () => {
        if (onForget) await onForget();
        setPersist(false);
    };

    // ── Design import: dark slide-up overlay (orange/green accents) ──────────
    const h = React.createElement;
    const C_ORANGE = 'var(--sb-orange)';
    const C_GREEN = 'var(--sb-green)';
    // Fill forms of the two: brand colour in both themes. See app.jsx.
    const C_ORANGE_SOLID = 'var(--sb-orange-solid)';
    const C_GREEN_SOLID = 'var(--sb-green-solid)';
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

    // radio card (public / own servers)
    const radioCard = (selected, onClick, title, desc, extraStyle) => h('button', {
        type: 'button', onClick,
        style: Object.assign({
            width: '100%', textAlign: 'start', display: 'flex', alignItems: 'flex-start', gap: '12px',
            padding: '14px 15px', borderRadius: '13px',
            border: `1px solid ${selected ? 'rgba(var(--sb-orange-rgb), 0.45)' : 'rgba(var(--sb-ink), 0.07)'}`,
            background: selected ? 'rgba(var(--sb-orange-rgb), 0.06)' : 'var(--sb-surface)',
            color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', transition: 'all .15s', marginBottom: '10px'
        }, extraStyle || {})
    }, [
        h('span', { key: 'ring', style: { flex: 'none', width: '18px', height: '18px', marginTop: '1px', borderRadius: '50%', border: `1.5px solid ${selected ? C_ORANGE : 'rgba(var(--sb-ink), 0.22)'}`, display: 'grid', placeItems: 'center' } },
            h('span', { style: { width: '8px', height: '8px', borderRadius: '50%', background: selected ? C_ORANGE_SOLID : 'transparent' } })),
        h('span', { key: 'tx', style: { flex: 1 } }, [
            h('span', { key: 't', style: { display: 'block', fontSize: '14px', fontWeight: 700, color: 'var(--sb-text-1)' } }, title),
            h('span', { key: 'd', style: { display: 'block', fontSize: '12.5px', color: 'var(--sb-text-7)', marginTop: '2px' } }, desc)
        ])
    ]);

    // pill toggle row (relay / save)
    const toggleRow = (on, onClick, title, desc, accent, badge) => h('button', {
        type: 'button', onClick,
        style: {
            width: '100%', textAlign: 'start', display: 'flex', alignItems: 'flex-start', gap: '12px',
            padding: '14px 15px', borderRadius: '13px',
            border: `1px solid ${on ? 'rgba(var(--sb-green-rgb), 0.3)' : 'rgba(var(--sb-ink), 0.07)'}`,
            background: on ? 'rgba(var(--sb-green-rgb), 0.05)' : 'var(--sb-surface)',
            color: 'inherit', fontFamily: 'inherit', cursor: 'pointer', transition: 'all .15s', marginBottom: '10px'
        }
    }, [
        h('span', { key: 'tx', style: { flex: 1 } }, [
            h('span', { key: 'r1', style: { display: 'flex', alignItems: 'center', gap: '8px' } }, [
                h('span', { key: 't', style: { fontSize: '14px', fontWeight: 700, color: 'var(--sb-text-1)' } }, title),
                badge && h('span', { key: 'b', style: { fontSize: '10px', fontWeight: 700, color: C_GREEN, padding: '2px 7px', borderRadius: '5px', background: 'rgba(var(--sb-green-rgb), 0.1)', border: '1px solid rgba(var(--sb-green-rgb), 0.22)' } }, badge)
            ]),
            h('span', { key: 'd', style: { display: 'block', fontSize: '12.5px', lineHeight: 1.5, color: 'var(--sb-text-7)', marginTop: '3px' } }, desc)
        ]),
        h('span', { key: 'tr', style: { flex: 'none', width: '42px', height: '24px', borderRadius: '99px', background: on ? (accent || C_GREEN_SOLID) : 'rgba(var(--sb-ink), 0.08)', border: `1px solid ${on ? (accent || C_GREEN) : 'rgba(var(--sb-ink), 0.12)'}`, position: 'relative', transition: 'all .18s', marginTop: '1px' } },
            h('span', { style: { position: 'absolute', top: '2px', insetInlineStart: '2px', width: '18px', height: '18px', borderRadius: '50%', background: '#fff', transform: on ? `translateX(${18 * direction()}px)` : 'translateX(0)', transition: 'transform .18s' } }))
    ]);

    // ── scrollable body ──
    const body = [];
    body.push(h('p', { key: 'intro', style: { margin: '0 0 18px', fontSize: '13.5px', lineHeight: 1.6, color: 'var(--sb-text-6)' } },
        t('ice.intro')));
    body.push(radioCard(!useCustom, () => setUseCustom(false), t('ice.publicTitle'), t('ice.publicDesc')));
    body.push(radioCard(useCustom, () => setUseCustom(true), t('ice.customTitle'), t('ice.customDesc', { max: ICE_LIMITS.MAX_SERVERS }), useCustom ? { marginBottom: '14px' } : null));

    if (useCustom) {
        const custom = [];
        custom.push(h('div', { key: 'ta', style: { borderRadius: '13px', border: '1px solid rgba(var(--sb-ink), 0.08)', background: 'var(--sb-bg-deep)', overflow: 'hidden', marginBottom: '12px' } },
            h('textarea', {
                dir: 'ltr',
                value: serversText, onChange: (e) => setServersText(e.target.value), rows: 5, spellCheck: false, autoComplete: 'off',
                placeholder: PLACEHOLDER,
                style: { width: '100%', resize: 'vertical', border: 'none', outline: 'none', background: 'transparent', color: 'var(--sb-text-code)', fontFamily: MONO, fontSize: '12px', lineHeight: 1.65, padding: '13px 14px', minHeight: '104px' }
            })));
        if (parsed.errors.length > 0) {
            custom.push(h('ul', { key: 'err', style: { margin: '0 0 10px', paddingInlineStart: '18px', color: 'var(--sb-red)', fontSize: '12.5px' } },
                parsed.errors.slice(0, 6).map((err, i) => h('li', { key: i }, err))));
        }
        if (parsed.warnings.length > 0) {
            custom.push(h('ul', { key: 'warn', style: { margin: '0 0 10px', paddingInlineStart: '18px', color: 'var(--sb-yellow)', fontSize: '12.5px' } },
                parsed.warnings.slice(0, 6).map((w, i) => h('li', { key: i }, w))));
        }
        if (parsed.servers.length > 0 && parsed.errors.length === 0) {
            custom.push(h('p', { key: 'ok', style: { margin: '0 0 10px', fontSize: '12.5px', color: C_GREEN } },
                `${parsed.servers.length} server(s) parsed${hasTurn ? ' (TURN present)' : ' (STUN only — does not hide IP)'}.`));
        }
        custom.push(h('div', { key: 'note', style: { display: 'flex', alignItems: 'flex-start', gap: '9px', padding: '12px 13px', borderRadius: '11px', border: '1px solid rgba(var(--sb-green-rgb), 0.18)', background: 'rgba(var(--sb-green-rgb), 0.05)', marginBottom: '12px' } }, [
            h('i', { key: 'i', className: 'fas fa-info-circle', style: { color: C_GREEN, fontSize: '13px', marginTop: '2px', flex: 'none' } }),
            h('span', { key: 't', style: { fontSize: '12px', lineHeight: 1.55, color: 'var(--sb-green-muted)' } }, [
                t('ice.turnNote'),
                h('span', { key: 'm', style: { fontFamily: MONO, color: C_GREEN } }, 'turns:'), t('ice.turnNoteTls')
            ])
        ]));
        const testColor = testState === 'done' && testResult && !testResult.error ? C_GREEN : 'var(--sb-text-4)';
        custom.push(h('div', { key: 'test', style: { display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap', marginBottom: '4px' } }, [
            h('button', {
                key: 'btn', type: 'button', disabled: !canApply || testState === 'running', onClick: handleTest,
                style: { display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '10px 15px', borderRadius: '10px', border: `1px solid ${testState === 'done' && testResult && !testResult.error ? 'rgba(var(--sb-green-rgb), 0.4)' : 'rgba(var(--sb-ink), 0.1)'}`, background: testState === 'done' && testResult && !testResult.error ? 'rgba(var(--sb-green-rgb), 0.08)' : 'rgba(var(--sb-ink), 0.04)', color: testColor, fontFamily: 'inherit', fontSize: '13px', fontWeight: 600, cursor: (!canApply || testState === 'running') ? 'not-allowed' : 'pointer', opacity: (!canApply || testState === 'running') ? 0.6 : 1 }
            }, [
                h('i', { key: 'i', className: testState === 'running' ? 'fas fa-circle-notch' : 'fas fa-play-circle', style: testState === 'running' ? { animation: 'sbSpin 1s linear infinite' } : null }),
                testState === 'running' ? t('ice.testing') : t('ice.test')
            ]),
            (testState === 'done' && testResult) ? h('span', { key: 'res', style: { fontSize: '12px', color: testResult.error ? 'var(--sb-red)' : 'var(--sb-text-7)' } },
                testResult.error
                    ? `Test failed: ${testResult.error}`
                    : (testResult.srflx > 0 || testResult.relay > 0)
                        ? `STUN ${testResult.srflx > 0 ? 'OK' : 'none'} · TURN ${testResult.relay > 0 ? 'OK' : 'none'} · host ${testResult.host}`
                        : `host ${testResult.host} · this browser hides STUN/TURN candidates from the test — your servers still apply to real connections`
            ) : null
        ]));
        body.push(h('div', { key: 'custom', style: { marginBottom: '16px' } }, custom));
    }

    body.push(toggleRow(relayOnly, () => setRelayOnly(!relayOnly), t('ice.relayTitle'),
        t('ice.relayDesc'), C_GREEN, t('ice.relayBadge')));
    if (relayOnly && useCustom && !hasTurn) {
        body.push(h('p', { key: 'relaywarn', style: { margin: '-4px 0 10px', fontSize: '12.5px', color: 'var(--sb-yellow)' } },
            t('ice.relayWarning')));
    }
    body.push(toggleRow(persist, () => setPersist(!persist), t('ice.persist'),
        t('ice.persistDesc'), C_ORANGE));

    // ── footer actions ──
    const footerBtns = [];
    if (hasSaved) {
        footerBtns.push(h('button', { key: 'forget', type: 'button', onClick: handleForget,
            style: { marginInlineEnd: 'auto', padding: '11px 18px', borderRadius: '11px', border: '1px solid rgba(var(--sb-red-rgb), 0.3)', background: 'transparent', color: 'var(--sb-red)', fontFamily: 'inherit', fontSize: '13.5px', fontWeight: 600, cursor: 'pointer' } }, t('ice.forget')));
    }
    footerBtns.push(h('button', { key: 'cancel', type: 'button', onClick: onClose,
        style: { padding: '11px 18px', borderRadius: '11px', border: '1px solid rgba(var(--sb-ink), 0.1)', background: 'transparent', color: 'var(--sb-text-5)', fontFamily: 'inherit', fontSize: '13.5px', fontWeight: 600, cursor: 'pointer' } }, t('ice.cancel')));
    footerBtns.push(h('button', { key: 'apply', type: 'button', onClick: handleApply, disabled: !canApply,
        style: { display: 'inline-flex', alignItems: 'center', gap: '8px', padding: '11px 20px', borderRadius: '11px', border: 'none', background: C_ORANGE_SOLID, color: 'var(--sb-on-accent)', fontFamily: 'inherit', fontSize: '13.5px', fontWeight: 700, cursor: canApply ? 'pointer' : 'not-allowed', opacity: canApply ? 1 : 0.5, boxShadow: '0 6px 18px rgba(var(--sb-orange-rgb), 0.28)' } }, [
        h('i', { key: 'i', className: 'fas fa-check' }), t('ice.apply')
    ]));

    // Embedded mode (default for the new design): fill the connection screen's
    // right column and slide up over it. Fallback: a fixed right-side drawer.
    const wrapperStyle = embedded
        ? { position: 'absolute', inset: 0, zIndex: 60, display: 'flex', flexDirection: 'column', background: 'var(--sb-bg)', animation: 'sbSlideUp .32s cubic-bezier(.2,.7,.3,1)' }
        : { position: 'fixed', inset: 0, zIndex: 60, display: 'flex', flexDirection: 'column', alignItems: 'stretch', background: 'var(--sb-bg)', animation: 'sbSlideUp .32s cubic-bezier(.2,.7,.3,1)' };

    return h('div', { className: 'sb-ice-overlay', style: wrapperStyle }, [
        h(React.Fragment, { key: 'panel' }, [
            // header
            h('div', { key: 'head', style: { display: 'flex', alignItems: 'center', gap: '12px', padding: '20px 24px', borderBottom: '1px solid rgba(var(--sb-ink), 0.06)' } }, [
                h('div', { key: 'ic', style: { width: '38px', height: '38px', flex: 'none', display: 'grid', placeItems: 'center', borderRadius: '10px', background: 'rgba(var(--sb-ink), 0.03)', border: '1px solid rgba(var(--sb-ink), 0.06)' } },
                    h('i', { className: 'fas fa-sliders-h', style: { color: 'var(--sb-text-4)', fontSize: '15px' } })),
                h('div', { key: 'tx', style: { flex: 1, lineHeight: 1.25 } }, [
                    h('div', { key: 't', style: { fontSize: '16.5px', fontWeight: 800, letterSpacing: '-0.3px', color: 'var(--sb-text-1)' } }, t('ice.title')),
                    h('div', { key: 's', style: { fontSize: '12px', color: 'var(--sb-text-8)' } }, t('ice.subtitle'))
                ]),
                h('button', { key: 'x', type: 'button', onClick: onClose, style: { width: '32px', height: '32px', flex: 'none', display: 'grid', placeItems: 'center', borderRadius: '9px', border: 'none', background: 'rgba(var(--sb-ink), 0.04)', color: 'var(--sb-text-7)', cursor: 'pointer' } },
                    h('i', { className: 'fas fa-times' }))
            ]),
            // scroll body
            h('div', { key: 'body', className: 'custom-scrollbar', style: { flex: 1, overflowY: 'auto', padding: '20px 24px' } }, body),
            // footer
            h('div', { key: 'foot', style: { display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '10px', padding: '16px 24px', borderTop: '1px solid rgba(var(--sb-ink), 0.06)', background: 'var(--sb-bg-deep)', borderRadius: '0' } }, footerBtns)
        ])
    ]);
};

window.IceServerSettings = IceServerSettings;

export { IceServerSettings, testIceServers };
