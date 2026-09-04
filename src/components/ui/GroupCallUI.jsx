import { t } from '../../i18n/index.js';
import { LEG_STATE } from '../../group/groupCallMedia.js';
import { gridLayout, spotlightLayout, TILE_GAP } from './callLayout.js';
// Group call surfaces: the ringing prompt, the tile grid, the control bar and
// the minimized dock.
//
// It is deliberately the same visual language as the 1:1 call (CallUI.jsx) —
// same icons, same control discs, same encrypted badge — because it is the same
// thing happening more than once, and a second design would suggest otherwise.
// What it adds is the part a group call has and a 1:1 call does not: a tile per
// member, each carrying that member's own connection state, because in a mesh
// call the connection is per pair and "the call is fine" is not a thing anybody
// can say on behalf of everyone else.
//
// Purely presentational. All media and all signalling live in GroupCallMedia
// and GroupSession; this reads a snapshot and calls back.

const h = (...args) => React.createElement(...args);
const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, Menlo, monospace";

const ICON = {
    lock: '<path d="M7 11V7a5 5 0 0 1 10 0v4"/><rect x="4.5" y="11" width="15" height="9" rx="2.2"/>',
    minimize: '<path d="M9 4v4a1 1 0 0 1-1 1H4M15 4v4a1 1 0 0 0 1 1h4M9 20v-4a1 1 0 0 0-1-1H4M15 20v-4a1 1 0 0 1 1-1h4"/>',
    expand: '<path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7"/>',
    users: '<path d="M16 19v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 17.5V19"/><circle cx="10" cy="8" r="3.2"/><path d="M20 19v-1.5a3.5 3.5 0 0 0-2.6-3.4"/><path d="M15.5 5.3a3.2 3.2 0 0 1 0 5.4"/>',
    micOn: '<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5 11a7 7 0 0 0 14 0"/><path d="M12 18v3"/>',
    micOff: '<path d="M9 9v-1a3 3 0 0 1 5.1-2.1M15 11v3a3 3 0 0 1-4.6 2.5"/><path d="M5 11a7 7 0 0 0 10.3 6.2M19 11a7 7 0 0 1-.4 2.3"/><path d="M12 18v3"/><path d="M3 3l18 18"/>',
    camOn: '<path d="M23 7l-7 5 7 5V7z"/><rect x="1" y="5" width="15" height="14" rx="2.5"/>',
    camOff: '<path d="M16 16H3a1 1 0 0 1-1-1V7a1 1 0 0 1 1-1h2l2-2M11 6h2l7-3v14M2 2l20 20"/>',
    grid: '<rect x="3" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.6"/>',
    flip: '<path d="M3 7h3l2-2h8l2 2h3v12H3z"/><path d="M9.5 13a2.5 2.5 0 0 1 5 0M14.5 13l-1.3-1.3M14.5 13l1.3-1.3"/>',
    phone: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z"/>',
    phoneHangup: '<path d="M22 16.92v3a2 2 0 0 1-2.18 2 19.8 19.8 0 0 1-8.63-3.07 19.5 19.5 0 0 1-6-6A19.8 19.8 0 0 1 2.12 4.18 2 2 0 0 1 4.11 2h3a2 2 0 0 1 2 1.72c.13.96.36 1.9.7 2.81a2 2 0 0 1-.45 2.11L8.09 9.91a16 16 0 0 0 6 6l1.27-1.27a2 2 0 0 1 2.11-.45c.91.34 1.85.57 2.81.7A2 2 0 0 1 22 16.92z" transform="rotate(135 12 12)"/>',
};

const svg = (inner, size, sw) => h('span', {
    style: { display: 'grid', placeItems: 'center', width: size + 'px', height: size + 'px' },
    dangerouslySetInnerHTML: { __html: `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${inner}</svg>` },
});

const ctrlBase = {
    width: '56px', height: '56px', borderRadius: '50%', display: 'grid', placeItems: 'center',
    border: '1px solid rgba(var(--sb-ink), 0.1)', background: 'rgba(var(--sb-ink), 0.05)',
    color: 'var(--sb-text-4)', cursor: 'pointer', transition: 'all .15s',
};
const dangerCtrl = { ...ctrlBase, background: 'var(--sb-red-strong-solid)', color: '#fff', border: '1px solid transparent' };
const endBtn = {
    width: '56px', height: '56px', borderRadius: '50%', display: 'grid', placeItems: 'center',
    border: 'none', background: 'var(--sb-red-strong-solid)', color: '#fff', cursor: 'pointer',
    boxShadow: '0 8px 24px rgba(var(--sb-red-strong-rgb), 0.35)', transition: 'transform .15s',
};
const minimizeBtn = {
    width: '36px', height: '36px', borderRadius: '9px', display: 'grid', placeItems: 'center',
    border: '1px solid rgba(var(--sb-ink), 0.15)', background: 'rgba(0,0,0,0.35)',
    color: '#fff', cursor: 'pointer', transition: 'all .15s',
};

const QUALITY = {
    excellent: { bars: 4, color: 'var(--sb-green)' },
    good: { bars: 3, color: 'var(--sb-green)' },
    fair: { bars: 2, color: 'var(--sb-yellow)' },
    poor: { bars: 1, color: 'var(--sb-red)' },
};

function qualityBars(quality) {
    const q = QUALITY[quality];
    if (!q) return null;
    return h('span', { key: 'q', style: { display: 'inline-flex', alignItems: 'flex-end', gap: '2px', height: '12px' } },
        [0, 1, 2, 3].map((i) => h('span', {
            key: i,
            style: {
                width: '2.5px', height: (4 + i * 2.6) + 'px', borderRadius: '1px',
                background: i < q.bars ? q.color : 'rgba(var(--sb-ink), 0.18)',
            },
        })));
}

function initials(name) {
    const words = String(name || '').trim().split(/\s+/).filter(Boolean);
    return ((words[0]?.[0] || '') + (words[1]?.[0] || words[0]?.[1] || '')).toUpperCase() || '#';
}

const fmt = (s) => `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`;

/**
 * The size of an element, kept current as it changes.
 *
 * The layout above needs real numbers, and the only honest source of those is
 * the element itself: the window's size says nothing about a panel inside a
 * sidebar layout, and a call that is resized — a window dragged wider, a phone
 * turned — has to re-solve rather than keep the size it was born with.
 */
function useMeasuredSize() {
    const [size, setSize] = React.useState({ w: 0, h: 0 });
    // A CALLBACK ref, not an object one, and this is the whole point of the hook.
    //
    // With `useRef` the effect's only dependency is the ref object, which never
    // changes — so the effect runs exactly once, on mount. The element it wants
    // to measure is inside a branch that mount does not always render: whoever
    // JOINS a call sees the "somebody is calling" prompt first, and there is no
    // stage in it. Their effect ran against `null`, never ran again, and the
    // size stayed 0×0 for the rest of the call while the person who STARTED the
    // call — mounted straight into the grid — measured fine. One user saw a
    // normal call and the other saw tiles collapsed to the width of their own
    // labels, from the same code.
    //
    // A callback ref is state: React calls it when the node attaches and again
    // when it detaches, so the effect re-runs the moment there is something to
    // measure. It also covers the same trip through the minimized dock, which
    // unmounts the stage and brings it back.
    const [node, setNode] = React.useState(null);
    React.useLayoutEffect(() => {
        if (!node) return undefined;
        const apply = () => setSize((prev) => (
            prev.w === node.clientWidth && prev.h === node.clientHeight
                ? prev                       // same numbers, same object: no re-render
                : { w: node.clientWidth, h: node.clientHeight }
        ));
        apply();   // before paint, so the first frame is already laid out
        if (typeof ResizeObserver === 'undefined') {
            window.addEventListener('resize', apply);
            return () => window.removeEventListener('resize', apply);
        }
        const observer = new ResizeObserver(apply);
        observer.observe(node);
        return () => observer.disconnect();
    }, [node]);
    return [setNode, size];
}

/**
 * One member's tile.
 *
 * A tile always says what THIS leg is doing, never what the call is doing. In a
 * mesh call one member can be connected while another is still being dialled,
 * and a single shared status line would have to lie about one of them.
 */
function Tile({ peer, stream, self, localStream, cameraEnabled, speaking, tileW, tileH, onSelect, pinned, compact }) {
    const videoRef = React.useRef(null);
    const source = self ? localStream : stream;
    const showVideo = self ? cameraEnabled : peer.hasVideo;

    // Video only. Every tile's <video> is MUTED and the call's audio is played by
    // GroupCallMedia from elements that are not in this tree — a tile unmounts
    // whenever the user opens another chat, and a call must not go silent
    // because somebody looked at a different window.
    React.useEffect(() => {
        const el = videoRef.current;
        if (!el || !source) return;
        if (el.srcObject !== source) { el.muted = true; el.srcObject = source; }
        const played = el.play && el.play();
        if (played && played.catch) played.catch(() => {});
    });

    // Nothing to say about our own tile: its name already reads "You", and the
    // status slot repeating it put the same word at both ends of the label row.
    const statusWord = self
        ? null
        : peer.state === LEG_STATE.ACTIVE ? null
            : peer.state === LEG_STATE.UNREACHABLE ? t('groupCall.waitingLink')
                : peer.state === LEG_STATE.FAILED ? t('groupCall.legFailed')
                    : t('groupCall.connecting');

    const avatarPx = Math.max(44, Math.min(148, Math.round((tileH || 180) * 0.42)));

    // The speaking ring is drawn as a border on the tile itself rather than as an
    // overlay, so it cannot be covered by the video and does not change layout
    // when it appears — a tile that resized every time somebody spoke would make
    // the whole grid twitch.
    return h('div', {
        // A tile is a control as well as a picture: clicking it spotlights that
        // person. Given a role and a key handler rather than wrapped in a button,
        // so a <video> is not nested inside interactive content.
        role: onSelect ? 'button' : undefined,
        tabIndex: onSelect ? 0 : undefined,
        onClick: onSelect,
        onKeyDown: onSelect ? (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect(); } } : undefined,
        title: pinned ? t('groupCall.unpin', { name: peer.name })
            : onSelect ? t('groupCall.pin', { name: peer.name })
                : (speaking ? t('groupCall.speaking', { name: peer.name }) : peer.name),
        style: {
            cursor: onSelect ? 'pointer' : 'default',
            position: 'relative', borderRadius: '14px', overflow: 'hidden', background: 'var(--sb-surface)',
            border: speaking ? '2px solid var(--sb-green-solid)' : '2px solid rgba(var(--sb-ink), 0.08)',
            boxShadow: speaking ? '0 0 0 3px rgba(var(--sb-green-rgb), 0.16)' : 'none',
            transition: 'border-color .12s ease, box-shadow .12s ease',
            // Sized by the grid, which is the only thing that knows how much
            // room there is. aspectRatio stays as the fallback for the first
            // paint, before the container has been measured.
            // Measured: an exact size. Unmeasured: a shape that is still a tile.
            // The floor matters more than it looks — without a minimum a flex item
            // can shrink to its own text, and one bad containing block turned the
            // whole call into a cluster of label-sized rectangles. Measurement now
            // makes the layout GOOD; it is no longer what makes it work at all.
            flex: tileW ? '0 0 auto' : '1 1 260px',
            minWidth: tileW ? undefined : '200px',
            width: tileW ? tileW + 'px' : 'auto',
            height: tileH ? tileH + 'px' : 'auto',
            aspectRatio: tileH ? undefined : '16 / 9',
            display: 'grid', placeItems: 'center',
        },
    }, [
        showVideo
            ? h('video', {
                key: 'v', ref: videoRef, autoPlay: true, muted: true, playsInline: true,
                style: {
                    position: 'absolute', inset: 0, width: '100%', height: '100%', objectFit: 'cover',
                    transform: self ? 'scaleX(-1)' : 'none', background: 'var(--sb-bg)',
                },
            })
            : h('div', {
                key: 'av',
                style: {
                    // Proportional to the tile: a fixed disc looks lost in a
                    // large tile and crowds a small one.
                    width: avatarPx + 'px', height: avatarPx + 'px',
                    borderRadius: '50%', display: 'grid', placeItems: 'center',
                    background: 'radial-gradient(circle at 35% 30%, var(--sb-surface-4), var(--sb-surface))',
                    border: speaking ? '1.5px solid rgba(var(--sb-green-rgb), 0.65)' : '1px solid rgba(var(--sb-ink), 0.1)',
                    color: speaking ? 'var(--sb-green)' : 'var(--sb-text-4)',
                    fontFamily: MONO, fontSize: Math.round(avatarPx * 0.3) + 'px', fontWeight: 700,
                    transition: 'color .12s ease, border-color .12s ease',
                },
            }, initials(peer.name)),
        h('div', {
            key: 'label',
            style: {
                position: 'absolute', insetInline: 0, bottom: 0, display: 'flex', alignItems: 'center',
                gap: compact ? '4px' : '7px', padding: compact ? '4px 6px' : '8px 10px',
                background: 'linear-gradient(0deg, rgba(0,0,0,0.7), transparent)',
            },
        }, [
            h('span', {
                key: 'n',
                style: {
                    flex: 1, minWidth: 0, fontSize: compact ? '10.5px' : '12.5px', fontWeight: 700, color: 'var(--sb-text-1)',
                    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                },
            }, peer.name),
            speaking && h('span', {
                key: 'sp', style: { flex: 'none', color: 'var(--sb-green)', display: 'grid', placeItems: 'center' },
            }, svg(ICON.micOn, compact ? 11 : 13, 2)),
            (statusWord && !compact) && h('span', {
                key: 's',
                style: {
                    flex: 'none', fontFamily: MONO, fontSize: '10.5px',
                    color: peer.state === LEG_STATE.FAILED ? 'var(--sb-red)' : 'var(--sb-text-6)',
                },
            }, statusWord),
            (!self && !compact) && qualityBars(peer.quality),
        ]),
    ]);
}

/**
 * The whole group-call surface.
 *
 * Three states, in the order they happen: a prompt when somebody else opened a
 * call we have not joined, the grid while we are in it, and a dock when the user
 * wants the transcript back without hanging up.
 */
export function GroupCallUI({
    call, media, groupName, localStream, getRemoteStream,
    onJoin, onDismiss, onLeave, onToggleMic, onToggleCamera, onFlipCamera,
}) {
    // EVERY hook runs before EVERY early return below, without exception.
    // Measuring the stage was added underneath one of them, so the first render
    // that reached the grid ran more hooks than the render before it and React
    // refused it outright (#310, "rendered more hooks than during the previous
    // render") — which took the whole call down at the moment it started. The
    // early returns are what make this file easy to get wrong; keeping the hooks
    // in one block at the top is what makes it hard.
    const [minimized, setMinimized] = React.useState(false);
    const [seconds, setSeconds] = React.useState(0);
    const [pinned, setPinned] = React.useState(null);
    const [stageRef, stage] = useMeasuredSize();
    const joined = !!call?.joined;

    React.useEffect(() => {
        if (!joined) { setSeconds(0); return undefined; }
        const started = Date.now();
        const iv = setInterval(() => setSeconds(Math.floor((Date.now() - started) / 1000)), 1000);
        return () => clearInterval(iv);
    }, [joined, call?.callId]);

    React.useEffect(() => { if (!call) setMinimized(false); }, [!call]);

    // A pin is dropped when the call ends, and when the person it points at
    // leaves — otherwise the stage would spotlight somebody who is not in the
    // call any more and the rest of the grid would look mysteriously short.
    const present = React.useMemo(
        () => new Set(['self', ...(media?.peers || []).map((p) => p.fp)]),
        [media],
    );
    React.useEffect(() => {
        if (pinned && !present.has(pinned)) setPinned(null);
    }, [pinned, present]);

    if (!call) return null;

    const encBadge = h('span', {
        key: 'enc',
        style: { display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11.5px', fontWeight: 600, color: 'var(--sb-green)' },
    }, [svg(ICON.lock, 12, 2), t('call.encryptedShort')]);

    // ── somebody is calling the group and we have not joined ─────────────────
    if (!joined) {
        return h('div', {
            style: {
                position: 'absolute', inset: 0, zIndex: 40, display: 'flex', flexDirection: 'column',
                background: 'radial-gradient(680px 460px at 50% 36%, rgba(var(--sb-orange-rgb), 0.08), transparent 70%), var(--sb-bg-deep)',
                animation: 'sbExpand .2s ease',
            },
        }, [
            h('div', { key: 'top', style: { flex: 'none', padding: '16px 18px' } },
                h('span', { style: { display: 'inline-flex', alignItems: 'center', gap: '7px', fontSize: '12px', fontWeight: 600, color: 'var(--sb-green)' } },
                    [svg(ICON.lock, 13, 2), t('call.encrypted')])),
            h('div', { key: 'mid', style: { flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', padding: '0 24px', textAlign: 'center' } }, [
                h('div', {
                    key: 'av',
                    style: {
                        position: 'relative', width: '112px', height: '112px', marginBottom: '26px',
                        display: 'grid', placeItems: 'center',
                    },
                }, [
                    h('span', { key: 'p1', style: { position: 'absolute', inset: 0, borderRadius: '50%', border: '1.5px solid rgba(var(--sb-orange-rgb), 0.5)', animation: 'sbCallPulse 2s ease-out infinite' } }),
                    h('span', { key: 'p2', style: { position: 'absolute', inset: 0, borderRadius: '50%', border: '1.5px solid rgba(var(--sb-orange-rgb), 0.4)', animation: 'sbCallPulse 2s ease-out infinite', animationDelay: '1s' } }),
                    h('div', {
                        key: 'c',
                        style: {
                            width: '96px', height: '96px', borderRadius: '50%', display: 'grid', placeItems: 'center',
                            background: 'radial-gradient(circle at 35% 30%, var(--sb-surface-4), var(--sb-surface))',
                            border: '1px solid rgba(var(--sb-ink), 0.1)', color: 'var(--sb-text-7)',
                        },
                    }, svg(ICON.users, 42, 1.6)),
                ]),
                h('div', { key: 'n', style: { fontSize: '22px', fontWeight: 800, letterSpacing: '-0.4px', color: 'var(--sb-text-1)' } }, groupName),
                h('div', { key: 's', style: { fontFamily: MONO, fontSize: '13.5px', color: 'var(--sb-text-6)', marginTop: '8px' } },
                    call.withVideo
                        ? t('groupCall.startedVideo', { name: call.startedByName })
                        : t('groupCall.startedVoice', { name: call.startedByName })),
                h('div', { key: 'p', style: { fontSize: '12.5px', color: 'var(--sb-text-9)', marginTop: '6px' } },
                    t('groupCall.inCall', { count: call.participants.length })),
            ]),
            h('div', { key: 'ctrls', style: { flex: 'none', display: 'flex', justifyContent: 'center', gap: '48px', padding: '24px 24px 40px' } }, [
                h('div', { key: 'dec', style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' } }, [
                    h('button', { key: 'b', onClick: onDismiss, title: t('groupCall.dismiss'), style: { ...endBtn, width: '62px', height: '62px' } }, svg(ICON.phoneHangup, 24, 1.9)),
                    h('span', { key: 'l', style: { fontFamily: MONO, fontSize: '10.5px', color: 'var(--sb-text-7)' } }, t('groupCall.dismiss')),
                ]),
                h('div', { key: 'acc', style: { display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '8px' } }, [
                    h('button', {
                        key: 'b', onClick: onJoin, title: t('groupCall.join'),
                        style: {
                            width: '62px', height: '62px', borderRadius: '50%', display: 'grid', placeItems: 'center',
                            border: 'none', background: 'var(--sb-green-solid)', color: 'var(--sb-on-green)', cursor: 'pointer',
                            boxShadow: '0 8px 24px rgba(var(--sb-green-rgb), 0.35)',
                        },
                    }, svg(ICON.phone, 24, 1.9)),
                    h('span', { key: 'l', style: { fontFamily: MONO, fontSize: '10.5px', color: 'var(--sb-text-7)' } }, t('groupCall.join')),
                ]),
            ]),
        ]);
    }

    const peers = media?.peers || [];
    const selfTile = {
        fp: 'self', name: t('groupCall.you'), state: LEG_STATE.ACTIVE,
        hasVideo: media?.cameraEnabled, quality: null, speaking: media?.selfSpeaking === true,
    };

    // ── minimized dock ───────────────────────────────────────────────────────
    if (minimized) {
        // Collapsed, there are no tiles to carry the indicator, so the one line
        // the dock has says who is talking instead of how long the call has run.
        const speakers = peers.filter((p) => p.speaking).map((p) => p.name);
        const talking = speakers.length === 1 ? speakers[0]
            : speakers.length > 1 ? speakers.slice(0, 2).join(', ')
                : (media?.selfSpeaking ? t('groupCall.you') : null);
        return h('div', {
            style: {
                position: 'absolute', bottom: '18px', insetInlineEnd: '18px', zIndex: 40, width: '244px',
                borderRadius: '14px', overflow: 'hidden', background: 'var(--sb-surface)',
                border: '1px solid rgba(var(--sb-ink), 0.1)', boxShadow: '0 18px 44px rgba(var(--sb-shadow-rgb), calc(0.55 * var(--sb-shadow-k)))',
                animation: 'sbExpand .18s ease',
            },
        }, [
            h('div', { key: 'bar', style: { display: 'flex', alignItems: 'center', gap: '11px', padding: '11px 12px' } }, [
                h('span', {
                    key: 'ic',
                    style: {
                        flex: 'none', width: '34px', height: '34px', borderRadius: '9px', display: 'grid',
                        placeItems: 'center', background: 'rgba(var(--sb-green-rgb), 0.1)',
                        border: '1px solid rgba(var(--sb-green-rgb), 0.25)', color: 'var(--sb-green)',
                    },
                }, svg(ICON.users, 16, 1.9)),
                h('div', { key: 'tx', style: { flex: 1, minWidth: 0 } }, [
                    h('div', { key: 'n', style: { fontSize: '13px', fontWeight: 700, color: 'var(--sb-text-1)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' } }, groupName),
                    h('div', {
                        key: 's',
                        style: {
                            fontFamily: MONO, fontSize: '11px', color: talking ? 'var(--sb-green)' : 'var(--sb-text-6)',
                            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                        },
                    }, talking
                        ? t('groupCall.speaking', { name: talking })
                        : `${t('groupCall.inCall', { count: call.participants.length })} · ${fmt(seconds)}`),
                ]),
                h('button', { key: 'exp', onClick: () => setMinimized(false), title: t('call.expand'), style: { flex: 'none', width: '32px', height: '32px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: 'none', background: 'rgba(var(--sb-ink), 0.05)', color: 'var(--sb-text-4)', cursor: 'pointer' } }, svg(ICON.expand, 15, 2)),
                h('button', { key: 'end', onClick: onLeave, title: t('groupCall.leave'), style: { flex: 'none', width: '32px', height: '32px', borderRadius: '8px', display: 'grid', placeItems: 'center', border: 'none', background: 'var(--sb-red-strong-solid)', color: '#fff', cursor: 'pointer' } }, svg(ICON.phoneHangup, 15, 2)),
            ]),
        ]);
    }

    // ── the call itself ──────────────────────────────────────────────────────
    const tiles = [selfTile, ...peers];
    const tileFor = (id) => tiles.find((tile) => tile.fp === id) || null;
    const spotlight = pinned ? tileFor(pinned) : null;
    const others = spotlight ? tiles.filter((tile) => tile.fp !== spotlight.fp) : [];
    const spot = spotlight ? spotlightLayout(others.length, stage.w, stage.h) : null;
    // A stage too short to split honestly falls back to the gallery rather than
    // rendering a main tile with no height.
    const spotlit = spotlight && spot && spot.main.w > 0;
    const layout = gridLayout(tiles.length, stage.w, stage.h);

    const renderTile = (tile, extra = {}) => h(Tile, {
        key: tile.fp,
        peer: tile,
        self: tile.fp === 'self',
        speaking: tile.speaking === true,
        localStream,
        cameraEnabled: media?.cameraEnabled,
        stream: tile.fp === 'self' ? null : getRemoteStream(tile.fp),
        ...extra,
    });

    return h('div', {
        style: {
            position: 'absolute', inset: 0, zIndex: 40, display: 'flex', flexDirection: 'column',
            background: 'var(--sb-bg-deepest)', animation: 'sbExpand .2s ease',
        },
    }, [
        h('div', {
            key: 'top',
            style: {
                flex: 'none', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
                gap: '14px', padding: '16px 18px 10px',
            },
        }, [
            h('div', { key: 'l', style: { minWidth: 0 } }, [
                h('div', { key: 'n', style: { fontSize: '17px', fontWeight: 800, letterSpacing: '-0.3px', color: '#fff', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, groupName),
                h('div', { key: 's', style: { display: 'inline-flex', alignItems: 'center', gap: '9px', marginTop: '4px' } }, [
                    h('span', { key: 'd', style: { fontFamily: MONO, fontSize: '12.5px', color: 'var(--sb-text-2)' } }, fmt(seconds)),
                    encBadge,
                    h('span', { key: 'c', style: { fontSize: '11.5px', color: 'var(--sb-text-7)' } },
                        t('groupCall.inCall', { count: call.participants.length })),
                ]),
            ]),
            h('div', { key: 'r', style: { flex: 'none', display: 'flex', alignItems: 'center', gap: '8px' } }, [
                spotlit && h('button', {
                    key: 'grid', onClick: () => setPinned(null), title: t('groupCall.showEveryone'),
                    style: {
                        height: '36px', padding: '0 12px', borderRadius: '9px', display: 'inline-flex',
                        alignItems: 'center', gap: '7px', border: '1px solid rgba(var(--sb-ink), 0.15)',
                        background: 'rgba(0,0,0,0.35)', color: '#fff', cursor: 'pointer',
                        fontFamily: 'inherit', fontSize: '12.5px', fontWeight: 600,
                    },
                }, [svg(ICON.grid, 14, 2), t('groupCall.showEveryone')]),
                h('button', { key: 'min', onClick: () => setMinimized(true), title: t('call.minimize'), style: minimizeBtn }, svg(ICON.minimize, 16, 2)),
            ]),
        ]),

        media?.error && h('div', {
            key: 'err',
            style: {
                flex: 'none', margin: '0 18px 10px', padding: '9px 12px', borderRadius: '10px',
                background: 'rgba(var(--sb-red-rgb), 0.1)', border: '1px solid rgba(var(--sb-red-rgb), 0.28)',
                color: 'var(--sb-red)', fontSize: '12.5px', lineHeight: 1.5,
            },
        }, t(`groupCall.err.${media.error}`)),

        // The stage is what gets measured, so it carries no padding of its own —
        // padding would be counted as usable room and every tile would come out
        // slightly too large for the space that is really there.
        h('div', {
            key: 'stage',
            ref: stageRef,
            className: 'msc-scroll',
            style: {
                flex: 1, minHeight: 0, minWidth: 0, overflow: 'auto',
                // Breathing room as MARGIN, not padding: clientWidth counts
                // padding as usable space and every tile would come out that
                // much too wide for the room actually available.
                margin: '0 14px 6px',
                // Flex, not grid. A grid with `justify-content: center` sizes its
                // column to the content, so the row's `width: 100%` had nothing
                // definite to resolve against and collapsed to the widest label —
                // which is exactly what the broken screenshot showed. A flex
                // container keeps a definite content box either way, so a row
                // asking for the full width gets the full width.
                // `safe center` centres it without the clipping plain centring
                // causes once the content overflows: the first row stays
                // reachable and the stage scrolls as normal.
                display: 'flex', alignItems: 'safe center', justifyContent: 'safe center',
            },
        }, spotlit
            // ── spotlight: one person large, the rest in a strip underneath ──
            ? h('div', {
                style: {
                    display: 'flex', flexDirection: 'column', gap: TILE_GAP + 'px',
                    width: '100%', height: stage.h + 'px', minHeight: 0,
                },
            }, [
                h('div', {
                    key: 'main',
                    style: { flex: 'none', display: 'flex', justifyContent: 'center', minHeight: 0 },
                }, renderTile(spotlight, {
                    tileW: spot.main.w, tileH: spot.main.h,
                    pinned: true, onSelect: () => setPinned(null),
                })),
                others.length > 0 && h('div', {
                    key: 'strip',
                    className: 'msc-scroll',
                    style: {
                        flex: 'none', height: spot.stripH + 'px', display: 'flex',
                        gap: TILE_GAP + 'px', justifyContent: others.length > 4 ? 'flex-start' : 'center',
                        // The strip scrolls sideways rather than shrinking: past a
                        // handful of people, thumbnails that keep dividing stop
                        // being recognisable, which is the whole point of them.
                        overflowX: 'auto', overflowY: 'hidden',
                    },
                }, others.map((tile) => renderTile(tile, {
                    tileW: spot.thumbW, tileH: spot.stripH, compact: true,
                    onSelect: () => setPinned(tile.fp),
                }))),
            ])
            // ── gallery: everyone the same size ─────────────────────────────
            : h('div', {
                // Wrapping flex rather than a grid, for one reason: a call of three
                // lays out two over one, and in a grid that lone tile is stuck in the
                // first column with a hole beside it. Fixing the row width to exactly
                // `cols` tiles makes the wrap land where the layout said it should,
                // and a short last row centres itself.
                style: {
                    display: 'flex', flexWrap: 'wrap', gap: TILE_GAP + 'px',
                    justifyContent: 'center', alignContent: 'center',
                    width: layout.tileW
                        ? (layout.cols * layout.tileW + (layout.cols - 1) * TILE_GAP) + 'px'
                        : '100%',
                },
            }, tiles.map((tile) => renderTile(tile, {
                tileW: layout.tileW, tileH: layout.tileH,
                onSelect: () => setPinned(tile.fp),
            })))),

        h('div', {
            key: 'ctrls',
            style: {
                flex: 'none', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '16px',
                padding: '16px 20px calc(22px + var(--sb-safe-bottom, env(safe-area-inset-bottom, 0px)))',
                background: 'linear-gradient(0deg, rgba(0,0,0,0.6), transparent)',
            },
        }, [
            h('button', { key: 'mic', onClick: onToggleMic, title: t('call.mute'), style: media?.micEnabled ? ctrlBase : dangerCtrl },
                svg(media?.micEnabled ? ICON.micOn : ICON.micOff, 21, 1.9)),
            h('button', { key: 'cam', onClick: onToggleCamera, title: t('call.camera'), style: media?.cameraEnabled ? ctrlBase : dangerCtrl },
                svg(media?.cameraEnabled ? ICON.camOn : ICON.camOff, 21, 1.8)),
            media?.cameraEnabled && h('button', { key: 'flip', onClick: onFlipCamera, title: t('call.flipCamera'), style: ctrlBase }, svg(ICON.flip, 21, 1.8)),
            h('button', { key: 'end', onClick: onLeave, title: t('groupCall.leave'), style: endBtn }, svg(ICON.phoneHangup, 22, 1.9)),
        ]),
    ]);
}

if (typeof window !== 'undefined') {
    window.GroupCallUI = GroupCallUI;
}
