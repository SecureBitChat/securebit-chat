import { t } from '../../i18n/index.js';
// Encrypted voice / video call UI for SecureBit.chat.
//
// Faithful implementation of the "SecureBit Chat.dc.html" design: the voice-call
// (expanded), video-call (expanded) and minimized-widget states use the exact
// icons, sizes, colours and layout from that mockup. This component is a thin
// presentational shell over the call subsystem in EnhancedSecureWebRTCManager —
// all media and crypto live there. Media is DTLS-SRTP encrypted on the same
// SAS-verified transport as the chat (see the manager's call section).
//
// Loaded as a native ES module (no JSX compilation), so this file uses
// React.createElement directly, mirroring the other components/ui modules.

const CallUIComponent = ({ webrtcManager, peerTitle }) => {
    const h = React.createElement;
    const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

    // Exact SVG icons lifted from the design. Rendered via innerHTML (CSP-safe —
    // markup, not script); `stroke="currentColor"` inherits the button's colour.
    const ICON = {
        lock: '<path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="4.5" y="11" width="15" height="9" rx="2.2"/>',
        minimize: '<path d="M9 4v4a1 1 0 0 1-1 1H4M15 4v4a1 1 0 0 0 1 1h4M9 20v-4a1 1 0 0 0-1-1H4M15 20v-4a1 1 0 0 1 1-1h4"/>',
        expand: '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>',
        user: '<circle cx="12" cy="8" r="3.6"/><path d="M5 20c0-3.5 3-5.5 7-5.5s7 2 7 5.5"/>',
        micOn: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><path d="M12 18v3"/>',
        micOff: '<path d="M9 9v-1a3 3 0 0 1 5.1-2.1M15 11v3a3 3 0 0 1-4.6 2.5"/><path d="M5 11a7 7 0 0 0 10.3 6.2M19 11a7 7 0 0 1-.4 2.3"/><path d="M12 18v3"/><path d="M3 3l18 18"/>',
        camOn: '<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2.5"/>',
        camOff: '<path d="M16 16H3a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h2l2-2M11 6h2l7-3v14M2 2l20 20"/>',
        flip: '<path d="M3 7h3l2-2h8l2 2h3v12H3z"/><path d="M9.5 13a2.5 2.5 0 0 1 5 0M14.5 13l-1.3-1.3M14.5 13l1.3-1.3"/>',
        phone: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z"/>',
        phoneHangup: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>'
    };
    const svg = (inner, size, sw) => h('span', {
        style: { display: 'grid', placeItems: 'center', width: size + 'px', height: size + 'px' },
        dangerouslySetInnerHTML: { __html: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>` }
    });

    const [call, setCall] = React.useState(() => (webrtcManager?.getCallState?.() || { phase: 'idle', active: false }));
    const [minimized, setMinimized] = React.useState(false);
    const [seconds, setSeconds] = React.useState(0);

    const remoteVideoRef = React.useRef(null);
    const remoteAudioRef = React.useRef(null);
    const selfVideoRef = React.useRef(null);

    // Subscribe to call-state changes from the active session's manager.
    React.useEffect(() => {
        if (!webrtcManager) return;
        const onState = (state) => setCall(state);
        const prev = webrtcManager.onCallStateChanged;
        webrtcManager.onCallStateChanged = onState;
        setCall(webrtcManager.getCallState ? webrtcManager.getCallState() : { phase: 'idle', active: false });
        return () => { if (webrtcManager.onCallStateChanged === onState) webrtcManager.onCallStateChanged = prev || null; };
    }, [webrtcManager]);

    const phase = call.phase || 'idle';
    const active = !!call.active;
    const isVideo = !!call.withVideo || !!call.remoteHasVideo;

    // Attach media streams to the <video>/<audio> elements AND explicitly play():
    // just setting srcObject does not reliably start playback (esp. when the
    // element mounts before the stream exists), so the peer's audio stayed silent.
    React.useEffect(() => {
        const remoteStream = webrtcManager?.getRemoteMediaStream?.();
        const localStream = webrtcManager?.getLocalMediaStream?.();
        const attach = (el, stream, muted) => {
            if (!el || !stream) return;
            if (el.srcObject !== stream) { el.muted = muted; el.srcObject = stream; }
            const p = el.play && el.play();
            if (p && p.catch) p.catch(() => {});
        };
        // Remote audio via the dedicated <audio>; remote <video> stays muted so the
        // peer's audio isn't played twice.
        attach(remoteAudioRef.current, remoteStream, false, 'remoteAudio');
        attach(remoteVideoRef.current, remoteStream, true, 'remoteVideo');
        attach(selfVideoRef.current, localStream, true, 'selfVideo');
    });

    // Call duration timer (starts when the call goes active).
    React.useEffect(() => {
        if (phase !== 'active') { setSeconds(0); return; }
        const started = Date.now();
        const iv = setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 1000);
        return () => clearInterval(iv);
    }, [phase]);

    React.useEffect(() => { if (phase === 'idle') setMinimized(false); }, [phase]);

    if (!active || phase === 'idle' || phase === 'ended') return null;
    // One leg of a group call runs on this same session. The group's own surface
    // renders it as a tile alongside the others; a second full-screen 1:1 overlay
    // on top of that would be the same audio shown twice, with two hang-up
    // buttons that mean different things.
    if (call.groupCallId) return null;

    const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;
    const ringing = phase === 'outgoing' || phase === 'connecting';
    const callStatus = phase === 'outgoing' ? t('call.ringing')
        : phase === 'connecting' ? t('call.connecting')
            : phase === 'active' ? fmt(seconds) : t('call.ringing');
    const name = peerTitle || t('call.peer');

    // ── shared styles (from the design) ──────────────────────────────────────
    const ctrlBase = {
        width: '56px', height: '56px', borderRadius: '50%', display: 'grid', placeItems: 'center',
        border: '1px solid rgba(255,255,255,0.1)', background: 'rgba(255,255,255,0.05)',
        color: '#cfcfd4', cursor: 'pointer', transition: 'all .15s'
    };
    const dangerCtrl = { ...ctrlBase, background: '#e5484d', color: '#fff', border: '1px solid transparent' };
    const endBtn = {
        width: '56px', height: '56px', borderRadius: '50%', display: 'grid', placeItems: 'center',
        border: 'none', background: '#e5484d', color: '#fff', cursor: 'pointer',
        boxShadow: '0 8px 24px rgba(229,72,77,0.35)', transition: 'transform .15s'
    };
    const minimizeBtn = (light) => ({
        width: '36px', height: '36px', borderRadius: '9px', display: 'grid', placeItems: 'center',
        border: '1px solid rgba(255,255,255,' + (light ? '0.15' : '0.1') + ')',
        background: light ? 'rgba(0,0,0,0.35)' : 'rgba(255,255,255,0.04)',
        color: light ? '#fff' : '#cfcfd4', cursor: 'pointer', transition: 'all .15s'
    });

    const encBadge = h('span', { key: 'enc', style: { display: 'inline-flex', alignItems: 'center', gap: '4px', fontSize: '11px', fontWeight: 600, color: '#3ecf8e' } },
        [svg(ICON.lock, 11, 2), t('call.encryptedShort')]);

    // Connection-quality indicator — driven by the adaptation controller's
    // getStats (loss + RTT). Signal bars + label; hidden until there's data.
    const QUALITY = {
        excellent: { bars: 4, color: '#3ecf8e', label: t('call.qualityExcellent') },
        good: { bars: 3, color: '#3ecf8e', label: t('call.qualityGood') },
        fair: { bars: 2, color: '#e3c84e', label: t('call.qualityFair') },
        poor: { bars: 1, color: '#e5727a', label: t('call.qualityWeak') },
    };
    const qualityIndicator = (compact) => {
        const q = QUALITY[call.quality];
        if (!q) return null;
        const bars = h('span', { key: 'bars', style: { display: 'inline-flex', alignItems: 'flex-end', gap: '2px', height: '14px' } },
            [0, 1, 2, 3].map(i => h('span', {
                key: i, style: { width: '3px', height: (5 + i * 3) + 'px', borderRadius: '1px', background: i < q.bars ? q.color : 'rgba(255,255,255,0.18)' }
            })));
        if (compact) return bars;
        return h('span', { key: 'q', title: t('call.quality'), style: { display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '11.5px', fontWeight: 600, color: q.color } }, [bars, q.label]);
    };

    // ── actions ──────────────────────────────────────────────────────────────
    const doAccept = () => webrtcManager?.acceptCall?.();
    const doDecline = () => webrtcManager?.declineCall?.();
    const doEnd = () => { setMinimized(false); webrtcManager?.endCall?.(); };
    const doMute = () => webrtcManager?.toggleMic?.();
    const doCamera = () => webrtcManager?.toggleCamera?.();
    const doFlip = () => webrtcManager?.switchCamera?.();
    const doUpgrade = () => webrtcManager?.upgradeToVideo?.();

    const hiddenAudio = h('audio', { key: 'ra', ref: remoteAudioRef, autoPlay: true, playsInline: true, style: { display: 'none' } });

    const labeled = (key, btn, label) => h('div', { key, style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' } },
        [btn, h('span', { key: 'l', style: { fontFamily: MONO, fontSize: '10.5px', color: '#8a8a92' } }, label)]);

    // Avatar disc with optional ringing pulse (voice + incoming).
    const avatarDisc = (size, ring) => h('div', { key: 'av', style: { position: 'relative', width: '120px', height: '120px', marginBottom: '28px', display: 'grid', placeItems: 'center' } }, [
        ring && h('span', { key: 'p1', style: { position: 'absolute', inset: 0, borderRadius: '50%', border: '1.5px solid rgba(240,137,42,0.5)', animation: 'sbCallPulse 2s ease-out infinite' } }),
        ring && h('span', { key: 'p2', style: { position: 'absolute', inset: 0, borderRadius: '50%', border: '1.5px solid rgba(240,137,42,0.4)', animation: 'sbCallPulse 2s ease-out infinite', animationDelay: '1s' } }),
        h('div', { key: 'c', style: { width: '104px', height: '104px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'radial-gradient(circle at 35% 30%, #2a2a30, #161618)', border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 12px 30px rgba(0,0,0,0.4)', color: '#8a8a92' } }, svg(ICON.user, size, 1.6))
    ]);

    // ── INCOMING (ringing) prompt ────────────────────────────────────────────
    if (phase === 'incoming') {
        return h('div', { style: { position: 'absolute', inset: 0, zIndex: 40, display: 'flex', flexDirection: 'column', background: 'radial-gradient(680px 460px at 50% 36%, rgba(240,137,42,0.08), transparent 70%), #0d0d0f', animation: 'sbExpand .2s ease' } }, [
            hiddenAudio,
            h('div', { key: 'top', style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'flex-start', padding: '16px 18px' } },
                h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '7px', fontSize: '12px', fontWeight: 600, color: '#3ecf8e' } }, [svg(ICON.lock, 13, 2), t('call.encrypted')])),
            h('div', { key: 'mid', style: { flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' } }, [
                avatarDisc(46, true),
                h('div', { key: 'nm', style: { fontSize: '24px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f4f4f6' } }, name),
                h('div', { key: 'st', style: { fontFamily: MONO, fontSize: '14px', fontWeight: 500, color: '#9a9aa2', marginTop: '8px' } }, call.withVideo ? t('call.incomingVideo') : t('call.incoming'))
            ]),
            h('div', { key: 'ctrls', style: { flex: 'none', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', gap: '48px', padding: '28px 24px 40px' } }, [
                labeled('dec', h('button', { onClick: doDecline, title: t('call.decline'), style: { ...endBtn, width: '62px', height: '62px' } }, svg(ICON.phoneHangup, 24, 1.9)), t('call.decline')),
                labeled('acc', h('button', { onClick: doAccept, title: t('call.accept'), style: { width: '62px', height: '62px', borderRadius: '50%', display: 'grid', placeItems: 'center', border: 'none', background: '#3ecf8e', color: '#06231a', cursor: 'pointer', boxShadow: '0 8px 24px rgba(62,207,142,0.35)' } }, svg(ICON.phone, 24, 1.9)), t('call.accept'))
            ])
        ]);
    }

    // ── MINIMIZED widget ─────────────────────────────────────────────────────
    if (minimized) {
        return h('div', { style: { position: 'absolute', bottom: '18px', insetInlineEnd: '18px', zIndex: 40, width: '236px', borderRadius: '14px', overflow: 'hidden', background: '#161618', border: '1px solid rgba(255,255,255,0.1)', boxShadow: '0 18px 44px rgba(0,0,0,0.55)', animation: 'sbExpand .18s ease' } }, [
            hiddenAudio,
            isVideo && h('div', { key: 'v', style: { position: 'relative', height: '132px', background: '#111' } }, [
                h('video', { key: 'rv', ref: remoteVideoRef, autoPlay: true, muted: true, playsInline: true, style: { width: '100%', height: '100%', objectFit: 'cover', display: 'block' } }),
                !call.remoteHasVideo && h('div', { key: 'off', style: { position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', background: 'linear-gradient(120deg,#15151b,#1d1a24)', color: '#6b6b73' } }, svg(ICON.camOff, 22, 1.8)),
                h('span', { key: 's', style: { position: 'absolute', top: '8px', insetInlineStart: '9px', fontFamily: MONO, fontSize: '11px', fontWeight: 600, color: '#fff', padding: '3px 7px', borderRadius: '6px', background: 'rgba(0,0,0,0.5)' } }, callStatus)
            ]),
            h('div', { key: 'bar', style: { display: 'flex', alignItems: 'center', gap: '11px', padding: '11px 12px' } }, [
                h('span', { key: 'ic', style: { position: 'relative', flex: 'none', width: '34px', height: '34px', borderRadius: '9px', display: 'grid', placeItems: 'center', background: 'rgba(62,207,142,0.1)', border: '1px solid rgba(62,207,142,0.25)', color: '#3ecf8e' } }, svg(ICON.user, 16, 1.9)),
                h('div', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
                    h('div', { key: 'n', style: { fontSize: '13px', fontWeight: 700, color: '#f4f4f6', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, name),
                    h('div', { key: 's', style: { display: 'flex', alignItems: 'center', gap: '7px', fontFamily: MONO, fontSize: '11px', color: '#9a9aa2' } }, [
                        (isVideo ? t('call.videoPrefix') : t('call.voicePrefix')) + callStatus,
                        phase === 'active' && qualityIndicator(true)
                    ])
                ]),
                h('button', { key: 'exp', onClick: () => setMinimized(false), title: t('call.expand'), style: { flex: 'none', width: '32px', height: '32px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: 'none', background: 'rgba(255,255,255,0.05)', color: '#cfcfd4', cursor: 'pointer', transition: 'all .15s' } }, svg(ICON.expand, 15, 2)),
                h('button', { key: 'end', onClick: doEnd, title: t('call.end'), style: { flex: 'none', width: '32px', height: '32px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: 'none', background: '#e5484d', color: '#fff', cursor: 'pointer', transition: 'transform .15s' } }, svg(ICON.phoneHangup, 15, 2))
            ])
        ]);
    }

    // ── VIDEO call (expanded) ────────────────────────────────────────────────
    if (isVideo) {
        return h('div', { style: { position: 'absolute', inset: 0, zIndex: 40, overflow: 'hidden', background: '#0a0a0c', animation: 'sbExpand .2s ease' } }, [
            hiddenAudio,
            call.remoteHasVideo
                ? h('video', { key: 'rv', ref: remoteVideoRef, autoPlay: true, muted: true, playsInline: true, style: { position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover', background: '#0a0a0c' } })
                : h('div', { key: 'ph', style: { position: 'absolute', inset: 0, background: 'linear-gradient(120deg, #15151b, #1d1a24, #161620)', backgroundSize: '200% 200%', animation: 'sbLiveBg 9s ease-in-out infinite', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '18px' } }, [
                    h('div', { key: 'a', style: { width: '120px', height: '120px', borderRadius: '50%', display: 'grid', placeItems: 'center', background: 'radial-gradient(circle at 35% 30%, #2a2a30, #161618)', border: '1px solid rgba(255,255,255,0.1)', color: '#9a9aa2' } }, svg(ICON.user, 54, 1.5)),
                    h('div', { key: 't', style: { fontSize: '15px', fontWeight: 600, color: '#8a8a92' } }, t('call.peerCameraOff'))
                ]),
            // Top bar
            h('div', { key: 'top', style: { position: 'absolute', top: 0, left: 0, right: 0, display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: '14px', padding: '18px 20px', background: 'linear-gradient(180deg, rgba(0,0,0,0.55), transparent)' } }, [
                h('div', { key: 'l' }, [
                    h('div', { key: 'n', style: { fontSize: '18px', fontWeight: 800, letterSpacing: '-0.3px', color: '#fff' } }, name),
                    h('div', { key: 's', style: { display: 'inline-flex', alignItems: 'center', gap: '9px', marginTop: '4px' } }, [
                        h('span', { key: 'st', style: { fontFamily: MONO, fontSize: '12.5px', fontWeight: 500, color: '#e8e8eb' } }, callStatus),
                        encBadge,
                        phase === 'active' && qualityIndicator(false)
                    ])
                ]),
                h('button', { key: 'min', onClick: () => setMinimized(true), title: t('call.minimize'), style: { flex: 'none', ...minimizeBtn(true) } }, svg(ICON.minimize, 16, 2))
            ]),
            // Self-cam PiP
            h('div', { key: 'self', style: { position: 'absolute', bottom: '108px', insetInlineEnd: '18px', width: '132px', height: '176px', borderRadius: '14px', overflow: 'hidden', border: '1px solid rgba(255,255,255,0.16)', boxShadow: '0 12px 30px rgba(0,0,0,0.5)', background: '#111' } }, [
                h('video', { key: 'sv', ref: selfVideoRef, autoPlay: true, muted: true, playsInline: true, style: { width: '100%', height: '100%', objectFit: 'cover', transform: 'scaleX(-1)', display: 'block' } }),
                !call.cameraEnabled && h('div', { key: 'off', style: { position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: '8px', background: '#161618', color: '#6b6b73' } }, [
                    svg(ICON.camOff, 24, 1.8),
                    h('span', { key: 't', style: { fontSize: '10.5px', color: '#6b6b73', fontFamily: MONO } }, t('call.cameraOff'))
                ])
            ]),
            // Control bar
            h('div', { key: 'ctrls', style: { position: 'absolute', bottom: 0, left: 0, right: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '18px', padding: '22px 24px 28px', background: 'linear-gradient(0deg, rgba(0,0,0,0.6), transparent)' } }, [
                h('button', { key: 'mute', onClick: doMute, title: t('call.mute'), style: call.micEnabled ? ctrlBase : dangerCtrl }, svg(call.micEnabled ? ICON.micOn : ICON.micOff, 21, 1.9)),
                h('button', { key: 'cam', onClick: doCamera, title: t('call.camera'), style: call.cameraEnabled ? ctrlBase : dangerCtrl }, svg(call.cameraEnabled ? ICON.camOn : ICON.camOff, 21, 1.8)),
                h('button', { key: 'flip', onClick: doFlip, title: t('call.flipCamera'), style: ctrlBase }, svg(ICON.flip, 21, 1.8)),
                h('button', { key: 'end', onClick: doEnd, title: t('call.end'), style: endBtn }, svg(ICON.phoneHangup, 22, 1.9))
            ])
        ]);
    }

    // ── VOICE call (expanded) ────────────────────────────────────────────────
    return h('div', { style: { position: 'absolute', inset: 0, zIndex: 40, display: 'flex', flexDirection: 'column', background: 'radial-gradient(680px 460px at 50% 36%, rgba(240,137,42,0.08), transparent 70%), #0d0d0f', animation: 'sbExpand .2s ease' } }, [
        hiddenAudio,
        h('div', { key: 'top', style: { flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 18px' } }, [
            h('span', { key: 'enc', style: { display: 'inline-flex', alignItems: 'center', gap: '7px', fontSize: '12px', fontWeight: 600, color: '#3ecf8e' } }, [svg(ICON.lock, 13, 2), t('call.encrypted')]),
            h('button', { key: 'min', onClick: () => setMinimized(true), title: t('call.minimize'), style: minimizeBtn(false) }, svg(ICON.minimize, 16, 2))
        ]),
        h('div', { key: 'mid', style: { flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' } }, [
            avatarDisc(46, ringing),
            h('div', { key: 'nm', style: { fontSize: '24px', fontWeight: 800, letterSpacing: '-0.5px', color: '#f4f4f6' } }, name),
            h('div', { key: 'st', style: { fontFamily: MONO, fontSize: '14px', fontWeight: 500, color: '#9a9aa2', marginTop: '8px' } }, callStatus),
            phase === 'active' && h('div', { key: 'q', style: { marginTop: '12px' } }, qualityIndicator(false))
        ]),
        h('div', { key: 'ctrls', style: { flex: 'none', display: 'flex', alignItems: 'flex-start', justifyContent: 'center', gap: '26px', padding: '28px 24px 34px' } }, [
            labeled('mute', h('button', { onClick: doMute, title: t('call.mute'), style: call.micEnabled ? ctrlBase : dangerCtrl }, svg(call.micEnabled ? ICON.micOn : ICON.micOff, 22, 1.9)), call.micEnabled ? 'Mute' : t('call.muted')),
            labeled('video', h('button', { onClick: doUpgrade, title: t('call.addVideo'), style: ctrlBase }, svg(ICON.camOn, 22, 1.8)), t('call.video')),
            labeled('end', h('button', { onClick: doEnd, title: t('call.end'), style: endBtn }, svg(ICON.phoneHangup, 22, 1.9)), t('call.endShort'))
        ])
    ]);
};

if (typeof window !== 'undefined') {
    window.CallUIComponent = CallUIComponent;
}

export { CallUIComponent };
