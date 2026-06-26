// Sessions registry for SecureBit.chat multi-session support.
//
// Pure, framework-free reducer + helpers. The root React component drives it via
// React.useReducer; non-serializable per-session objects (the EnhancedSecureWebRTCManager
// instance, its NotificationIntegration, offline queues, QR-animation timers) live OUTSIDE
// this state in ref-held Maps keyed by sessionId — never in here, never shared between
// sessions. Every reducer case returns fresh objects for the touched session only, so a
// change to one session can never mutate another (full isolation).
//
// sessionId is LOCAL ONLY (crypto.randomUUID). It is never sent to the peer as identity.

export const SESSION_ACTIONS = Object.freeze({
    CREATE_SESSION: 'CREATE_SESSION',
    REMOVE_SESSION: 'REMOVE_SESSION',
    SET_ACTIVE: 'SET_ACTIVE',
    SET_STATUS: 'SET_STATUS',
    SET_FINGERPRINT: 'SET_FINGERPRINT',
    SET_VERIFICATION: 'SET_VERIFICATION',
    SET_SAS: 'SET_SAS',
    ADD_MESSAGE: 'ADD_MESSAGE',
    SET_MESSAGES: 'SET_MESSAGES',
    UPDATE_MESSAGE_STATUS: 'UPDATE_MESSAGE_STATUS',
    DELETE_MESSAGE: 'DELETE_MESSAGE',
    EXPIRE_MESSAGE: 'EXPIRE_MESSAGE',
    INCREMENT_UNREAD: 'INCREMENT_UNREAD',
    CLEAR_UNREAD: 'CLEAR_UNREAD',
    SET_PENDING_FILES: 'SET_PENDING_FILES',
    PATCH_SETUP: 'PATCH_SETUP',
    RENAME: 'RENAME',
    SET_PEER_PRESENCE: 'SET_PEER_PRESENCE'
});

// Availability presence the PEER advertises to us (sent E2E over the data channel, never
// stored on a server). 'invisible' is sent on the wire as 'offline' so peers can't tell.
export const PRESENCE_DOT = { available: '#3ecf8e', away: '#e3b341', busy: '#e5727a', offline: '#6b6b73' };
export const PRESENCE_WORD = { available: 'Available', away: 'Away', busy: 'Busy', offline: 'Offline' };
// The statuses the local user can pick for themselves (design: Set your status).
export const MY_STATUS_OPTIONS = [
    { key: 'available', word: 'Available', desc: 'Online and reachable', dot: '#3ecf8e' },
    { key: 'away', word: 'Away', desc: 'Idle · stepped away', dot: '#e3b341' },
    { key: 'busy', word: 'Busy', desc: 'Do not disturb', dot: '#e5727a' },
    { key: 'invisible', word: 'Invisible', desc: 'Appear offline to peers', dot: '#6b6b73' }
];

// Short, human-friendly default label derived from the local sessionId. Never the peer's
// identity — just something stable to show before the SAS-derived label is available.
export function shortLabelFromId(id) {
    const hex = String(id || '').replace(/[^a-z0-9]/gi, '');
    return 'Chat ' + (hex.slice(0, 4) || '0000').toUpperCase();
}

// Two-letter monogram for the avatar tile (mirrors the design's `mono()` helper).
export function monoInitials(label) {
    const words = String(label || '').trim().split(/\s+/).filter(Boolean);
    const a = words[0]?.[0] || '';
    const b = words[1]?.[0] || words[0]?.[1] || '';
    return (a + b).toUpperCase() || '··';
}

// Status → dot colour (mirrors the design's DOT map).
export function statusDot(status) {
    switch (status) {
        case 'connected':
        case 'verified':
            return '#3ecf8e';
        case 'connecting':
        case 'verifying':
        case 'new':
            return '#e3b341';
        default:
            return '#e5727a'; // disconnected / peer_disconnected / lost
    }
}

// Status → header sub-text (mirrors the design's SUB map).
export function statusSub(status) {
    switch (status) {
        case 'connected':
        case 'verified':
            return 'P2P · connected';
        case 'verifying':
            return 'Verifying…';
        case 'connecting':
        case 'new':
            return 'Connecting…';
        case 'peer_disconnected':
            return 'Peer disconnected';
        default:
            return 'Disconnected';
    }
}

function emptySetup() {
    return {
        offerData: '',
        answerData: '',
        offerInput: '',
        answerInput: '',
        showOfferStep: false,
        showAnswerStep: false,
        showVerification: false,
        showQRCode: false,
        qrCodeUrl: '',
        isGeneratingKeys: false,
        qrFramesTotal: 0,
        qrFrameIndex: 0,
        qrManualMode: false
    };
}

export function createSessionEntry(opts = {}) {
    const id = opts.id || (typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : String(Date.now()) + Math.random());
    return {
        id,
        peerLabel: opts.peerLabel || shortLabelFromId(id),
        labelIsCustom: false, // becomes true once the user renames; blocks SAS auto-relabel
        createdAt: opts.createdAt || Date.now(),
        role: opts.role || 'offer', // 'offer' | 'answer'
        status: opts.status || 'new',
        keyFingerprint: '',
        verificationCode: '',
        sas: { localConfirmed: false, remoteConfirmed: false, bothConfirmed: false, isVerified: false },
        messages: [],
        unreadCount: 0,
        pendingIncomingFiles: [],
        peerPresence: null, // peer's advertised availability ('available'|'away'|'busy'|'offline'); null = unknown
        setup: emptySetup()
    };
}

export function createInitialState() {
    return { sessions: {}, order: [], activeSessionId: null };
}

// Apply a partial patch to one session, returning a new state with only that session's
// object replaced. Other sessions keep their identity (referential isolation).
function patchSession(state, id, patch) {
    const session = state.sessions[id];
    if (!session) return state;
    return {
        ...state,
        sessions: { ...state.sessions, [id]: { ...session, ...patch } }
    };
}

export function sessionsReducer(state, action) {
    const A = SESSION_ACTIONS;
    switch (action.type) {
        case A.CREATE_SESSION: {
            const entry = action.entry || createSessionEntry(action);
            if (state.sessions[entry.id]) return state;
            return {
                sessions: { ...state.sessions, [entry.id]: entry },
                order: [...state.order, entry.id],
                activeSessionId: action.activate === false ? state.activeSessionId : entry.id
            };
        }

        case A.REMOVE_SESSION: {
            const { id } = action;
            if (!state.sessions[id]) return state;
            const sessions = { ...state.sessions };
            delete sessions[id];
            const order = state.order.filter((x) => x !== id);
            let activeSessionId = state.activeSessionId;
            if (activeSessionId === id) {
                // Re-point to the previous sibling in display order, else the first remaining.
                const removedIdx = state.order.indexOf(id);
                activeSessionId = order[Math.max(0, removedIdx - 1)] || order[0] || null;
            }
            return { sessions, order, activeSessionId };
        }

        case A.SET_ACTIVE: {
            if (!state.sessions[action.id]) return state;
            if (state.activeSessionId === action.id) return state;
            return { ...state, activeSessionId: action.id };
        }

        case A.SET_STATUS: {
            const session = state.sessions[action.id];
            if (!session || session.status === action.status) return state; // no-op if unchanged
            return patchSession(state, action.id, { status: action.status });
        }

        case A.SET_FINGERPRINT:
            return patchSession(state, action.id, { keyFingerprint: action.fingerprint });

        case A.SET_VERIFICATION:
            return patchSession(state, action.id, { verificationCode: action.code });

        case A.SET_SAS: {
            const session = state.sessions[action.id];
            if (!session) return state;
            return patchSession(state, action.id, { sas: { ...session.sas, ...action.sas } });
        }

        case A.ADD_MESSAGE: {
            const session = state.sessions[action.id];
            if (!session) return state;
            return patchSession(state, action.id, { messages: [...session.messages, action.message] });
        }

        case A.SET_MESSAGES: {
            const session = state.sessions[action.id];
            if (!session) return state;
            const next = typeof action.updater === 'function'
                ? action.updater(session.messages)
                : action.messages;
            return patchSession(state, action.id, { messages: Array.isArray(next) ? next : [] });
        }

        case A.UPDATE_MESSAGE_STATUS: {
            const session = state.sessions[action.id];
            if (!session) return state;
            let changed = false;
            const messages = session.messages.map((m) => {
                if (String(m.mid) === String(action.mid) && m.status !== action.status) {
                    changed = true;
                    return { ...m, status: action.status };
                }
                return m;
            });
            return changed ? patchSession(state, action.id, { messages }) : state;
        }

        case A.DELETE_MESSAGE: {
            const session = state.sessions[action.id];
            if (!session) return state;
            const messages = session.messages.filter((m) => String(m.mid) !== String(action.mid));
            if (messages.length === session.messages.length) return state;
            return patchSession(state, action.id, { messages });
        }

        case A.EXPIRE_MESSAGE: {
            const session = state.sessions[action.id];
            if (!session) return state;
            let changed = false;
            const messages = session.messages.map((m) => {
                if (String(m.id) === String(action.messageId) && !m.expired) {
                    changed = true;
                    return { ...m, expired: true, message: '', expiresAt: undefined };
                }
                return m;
            });
            return changed ? patchSession(state, action.id, { messages }) : state;
        }

        case A.INCREMENT_UNREAD: {
            const session = state.sessions[action.id];
            if (!session) return state;
            return patchSession(state, action.id, { unreadCount: session.unreadCount + 1 });
        }

        case A.CLEAR_UNREAD: {
            const session = state.sessions[action.id];
            if (!session || session.unreadCount === 0) return state;
            return patchSession(state, action.id, { unreadCount: 0 });
        }

        case A.SET_PENDING_FILES: {
            const session = state.sessions[action.id];
            if (!session) return state;
            const next = typeof action.updater === 'function'
                ? action.updater(session.pendingIncomingFiles)
                : action.files;
            return patchSession(state, action.id, { pendingIncomingFiles: Array.isArray(next) ? next : [] });
        }

        case A.PATCH_SETUP: {
            const session = state.sessions[action.id];
            if (!session) return state;
            return patchSession(state, action.id, { setup: { ...session.setup, ...action.patch } });
        }

        case A.RENAME: {
            const session = state.sessions[action.id];
            if (!session) return state;
            const label = String(action.label || '').trim() || session.peerLabel;
            return patchSession(state, action.id, { peerLabel: label, labelIsCustom: true });
        }

        case A.SET_PEER_PRESENCE: {
            const session = state.sessions[action.id];
            if (!session || session.peerPresence === action.presence) return state;
            return patchSession(state, action.id, { peerPresence: action.presence });
        }

        default:
            return state;
    }
}

// Decorate a session into the shape the sidebar/header rendering consumes (avatar monogram,
// status dot, sub-text, last-message preview, unread badge). Pure derivation — no state.
export function decorateSession(session, activeSessionId) {
    const lastMessage = [...session.messages].reverse().find((m) => !m.expired && typeof m.message === 'string' && m.message.trim());
    const s = session.status;
    const isUp = s === 'connected' || s === 'verified';
    const isPending = s === 'connecting' || s === 'verifying' || s === 'new';
    // Avatar dot + sub-text: while a session is up, reflect the PEER's advertised presence;
    // otherwise reflect the connection state (amber = connecting, red = dropped).
    let dot, headerSub;
    if (isPending) {
        dot = '#e3b341';
        headerSub = statusSub(s);
    } else if (isUp) {
        dot = session.peerPresence ? (PRESENCE_DOT[session.peerPresence] || '#6b6b73') : '#3ecf8e';
        headerSub = session.peerPresence ? (PRESENCE_WORD[session.peerPresence] || 'Online') : 'P2P · connected';
    } else {
        dot = '#e5727a';
        headerSub = statusSub(s);
    }
    const preview = lastMessage ? lastMessage.message : headerSub;
    return {
        id: session.id,
        name: session.peerLabel,
        mono: monoInitials(session.peerLabel),
        dot,
        headerSub,
        status: session.status,
        peerPresence: session.peerPresence,
        preview,
        unread: session.unreadCount > 0 ? (session.unreadCount > 99 ? '99+' : String(session.unreadCount)) : null,
        verified: !!session.sas.isVerified,
        active: session.id === activeSessionId,
        inactive: session.id !== activeSessionId
    };
}

export function decorateSessions(state) {
    return state.order
        .map((id) => state.sessions[id])
        .filter(Boolean)
        .map((s) => decorateSession(s, state.activeSessionId));
}
