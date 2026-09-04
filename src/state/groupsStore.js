import { t } from '../i18n/index.js';
// Groups registry for SecureBit.chat.
//
// Same contract as sessionsStore.js, and deliberately a SEPARATE reducer rather
// than a slice bolted onto that one: a group is built out of pairwise sessions
// but owns none of them, and keeping the two stores apart means adding groups
// cannot disturb the 1:1 state that every existing test covers.
//
// What lives here is only what React renders. The non-serializable half of a
// group — its ECDSA identity key pair, the running commit/reveal ceremony, the
// per-member imported verifying keys, the outbound sequence counter — lives
// OUTSIDE this state in a ref-held Map keyed by groupId, exactly the way
// managersRef holds the WebRTC managers. Key material must never reach a
// reducer: it would be cloned on every dispatch and retained by React's state
// history, which is the opposite of what a non-extractable key is for.
//
// groupId is SHARED with the other members (it identifies the group on the
// wire), unlike sessionId, which is local-only. Member identity is the
// fingerprint of a member's group identity key — never a session id, and never
// a name the peer supplied.

import { GROUP_LIMITS } from '../group/groupCrypto.js';

export const GROUP_ACTIONS = Object.freeze({
    CREATE_GROUP: 'CREATE_GROUP',
    REMOVE_GROUP: 'REMOVE_GROUP',
    SET_ACTIVE_GROUP: 'SET_ACTIVE_GROUP',
    SET_PHASE: 'SET_PHASE',
    SET_MEMBERS: 'SET_MEMBERS',
    PATCH_MEMBER: 'PATCH_MEMBER',
    SET_SAS: 'SET_SAS',
    CONFIRM_SAS: 'CONFIRM_SAS',
    ADD_MESSAGE: 'ADD_MESSAGE',
    SET_MESSAGES: 'SET_MESSAGES',
    UPDATE_MESSAGE_STATUS: 'UPDATE_MESSAGE_STATUS',
    INCREMENT_UNREAD: 'INCREMENT_UNREAD',
    CLEAR_UNREAD: 'CLEAR_UNREAD',
    RENAME: 'RENAME',
    SET_ERROR: 'SET_ERROR',
});

/**
 * A group's lifecycle.
 *
 * The order matters and the UI depends on it: nothing may be sent or displayed
 * as group traffic until `ready`, and `ready` is reachable only through
 * `awaiting_sas`, where a human confirmed the code. A group that skips that step
 * is a group whose introduced members were never authenticated by anyone.
 */
export const GROUP_PHASE = Object.freeze({
    FORMING: 'forming',       // members chosen, identity keys being exchanged
    COMMITTING: 'committing', // commitments in flight
    REVEALING: 'revealing',   // every commitment in, nonces in flight
    AWAITING_SAS: 'awaiting_sas', // code computed, waiting for the humans
    READY: 'ready',           // confirmed; group traffic flows
    FAILED: 'failed',         // ceremony aborted; nothing flows
});

/** Per-member link state. 'self' is us; the rest describe the pairwise session. */
export const MEMBER_STATE = Object.freeze({
    SELF: 'self',
    LINKED: 'linked',   // pairwise session up and SAS-verified
    PENDING: 'pending', // session exists but is not verified/connected yet
    LOST: 'lost',       // was linked, connection dropped
});

export const GROUP_PHASE_WORD = {
    [GROUP_PHASE.FORMING]: t('groupPhase.forming'),
    [GROUP_PHASE.COMMITTING]: t('groupPhase.commitments'),
    [GROUP_PHASE.REVEALING]: t('groupPhase.revealing'),
    [GROUP_PHASE.AWAITING_SAS]: t('groupPhase.compare'),
    [GROUP_PHASE.READY]: t('groupPhase.ready'),
    [GROUP_PHASE.FAILED]: t('groupPhase.failed'),
};

/** Two-letter monogram for the group tile. Mirrors monoInitials in sessionsStore. */
export function groupInitials(name) {
    const words = String(name || '').trim().split(/\s+/).filter(Boolean);
    const a = words[0]?.[0] || '';
    const b = words[1]?.[0] || words[0]?.[1] || '';
    return (a + b).toUpperCase() || '##';
}

export function createGroupEntry(opts = {}) {
    return {
        id: opts.id,
        name: opts.name || 'Group',
        createdAt: opts.createdAt || Date.now(),
        adminFp: opts.adminFp || '',
        selfFp: opts.selfFp || '',
        isAdmin: !!opts.isAdmin,
        epoch: Number.isInteger(opts.epoch) ? opts.epoch : 1,
        phase: opts.phase || GROUP_PHASE.FORMING,
        // members: [{ fp, name, sessionId, state }]. Always stored in canonical
        // fingerprint order so every device renders the same list.
        members: Array.isArray(opts.members) ? [...opts.members].sort(byFingerprint) : [],
        sasCode: '',
        sasConfirmed: false,
        messages: [],
        unreadCount: 0,
        error: null,
    };
}

const NAME_ENCODER = new TextEncoder();

/** Trim a group name so its UTF-8 encoding fits the protocol's byte budget. */
function clampNameBytes(value) {
    let out = String(value);
    while (NAME_ENCODER.encode(out).length > GROUP_LIMITS.MAX_NAME_BYTES) out = out.slice(0, -1);
    return out;
}

function byFingerprint(a, b) {
    return a.fp < b.fp ? -1 : a.fp > b.fp ? 1 : 0;
}

export function createInitialGroupState() {
    return { groups: {}, order: [], activeGroupId: null };
}

/** Patch one group, leaving every sibling referentially untouched. */
function patchGroup(state, id, patch) {
    const group = state.groups[id];
    if (!group) return state;
    return { ...state, groups: { ...state.groups, [id]: { ...group, ...patch } } };
}

export function groupsReducer(state, action) {
    const A = GROUP_ACTIONS;
    switch (action.type) {
        case A.CREATE_GROUP: {
            const entry = action.entry || createGroupEntry(action);
            if (!entry.id || state.groups[entry.id]) return state;
            return {
                groups: { ...state.groups, [entry.id]: entry },
                order: [...state.order, entry.id],
                activeGroupId: action.activate === false ? state.activeGroupId : entry.id,
            };
        }

        case A.REMOVE_GROUP: {
            const { id } = action;
            if (!state.groups[id]) return state;
            const groups = { ...state.groups };
            delete groups[id];
            const order = state.order.filter((x) => x !== id);
            let activeGroupId = state.activeGroupId;
            if (activeGroupId === id) {
                const removedIdx = state.order.indexOf(id);
                activeGroupId = order[Math.max(0, removedIdx - 1)] || order[0] || null;
            }
            return { groups, order, activeGroupId };
        }

        case A.SET_ACTIVE_GROUP: {
            // null is legitimate: it means a 1:1 session took the foreground.
            if (action.id === null) {
                return state.activeGroupId === null ? state : { ...state, activeGroupId: null };
            }
            if (!state.groups[action.id] || state.activeGroupId === action.id) return state;
            return { ...state, activeGroupId: action.id };
        }

        case A.SET_PHASE: {
            const group = state.groups[action.id];
            if (!group || group.phase === action.phase) return state;
            // Leaving READY clears the confirmation: a membership change starts a
            // new epoch with a new code, and a stale "confirmed" tick would tell
            // the user they had checked something they had not.
            const patch = { phase: action.phase };
            if (action.phase !== GROUP_PHASE.READY && group.sasConfirmed) {
                patch.sasConfirmed = false;
            }
            // The code is cleared only on the way BACK to a pre-code phase.
            // AWAITING_SAS is where a code is born, so clearing it there would
            // erase the digits the user is about to be shown.
            if (action.phase !== GROUP_PHASE.READY && action.phase !== GROUP_PHASE.AWAITING_SAS) {
                patch.sasCode = '';
            }
            if (action.phase !== GROUP_PHASE.FAILED) patch.error = null;
            return patchGroup(state, action.id, patch);
        }

        case A.SET_MEMBERS: {
            const group = state.groups[action.id];
            if (!group) return state;
            const members = Array.isArray(action.members) ? [...action.members].sort(byFingerprint) : group.members;
            const patch = { members };
            if (Number.isInteger(action.epoch)) patch.epoch = action.epoch;
            return patchGroup(state, action.id, patch);
        }

        case A.PATCH_MEMBER: {
            const group = state.groups[action.id];
            if (!group) return state;
            let changed = false;
            const members = group.members.map((m) => {
                if (m.fp !== action.fp) return m;
                const next = { ...m, ...action.patch };
                // Skip the dispatch entirely when nothing actually moved — link
                // state churns on every ICE event and would otherwise re-render
                // the whole group list continuously.
                if (Object.keys(action.patch).every((k) => m[k] === next[k])) return m;
                changed = true;
                return next;
            });
            return changed ? patchGroup(state, action.id, { members }) : state;
        }

        case A.SET_SAS: {
            const group = state.groups[action.id];
            if (!group || group.sasCode === action.code) return state;
            return patchGroup(state, action.id, { sasCode: action.code || '', sasConfirmed: false });
        }

        case A.CONFIRM_SAS: {
            const group = state.groups[action.id];
            if (!group) return state;
            // Refuse the transition unless there is a code to have confirmed AND
            // the group is actually waiting on that confirmation.
            //
            // Checking only for a code was not enough: a ceremony that reached
            // AWAITING_SAS and then FAILED — a mismatched commitment, a member
            // that vanished — kept its code, so confirming promoted a group whose
            // verification had demonstrably gone wrong straight to READY. The
            // phase is what says the code in hand is still the one being asked
            // about, which mirrors the 1:1 rule that verified state comes only
            // from the local user acting on something currently true.
            if (!group.sasCode) return state;
            if (group.phase !== GROUP_PHASE.AWAITING_SAS) return state;
            if (group.sasConfirmed && group.phase === GROUP_PHASE.READY) return state;
            return patchGroup(state, action.id, { sasConfirmed: true, phase: GROUP_PHASE.READY, error: null });
        }

        case A.ADD_MESSAGE: {
            const group = state.groups[action.id];
            if (!group) return state;
            return patchGroup(state, action.id, { messages: [...group.messages, action.message] });
        }

        case A.SET_MESSAGES: {
            const group = state.groups[action.id];
            if (!group) return state;
            const next = typeof action.updater === 'function' ? action.updater(group.messages) : action.messages;
            return patchGroup(state, action.id, { messages: Array.isArray(next) ? next : [] });
        }

        case A.UPDATE_MESSAGE_STATUS: {
            const group = state.groups[action.id];
            if (!group) return state;
            let changed = false;
            const messages = group.messages.map((m) => {
                if (String(m.mid) === String(action.mid) && m.status !== action.status) {
                    changed = true;
                    return { ...m, status: action.status };
                }
                return m;
            });
            return changed ? patchGroup(state, action.id, { messages }) : state;
        }

        case A.INCREMENT_UNREAD: {
            const group = state.groups[action.id];
            if (!group) return state;
            return patchGroup(state, action.id, { unreadCount: group.unreadCount + 1 });
        }

        case A.CLEAR_UNREAD: {
            const group = state.groups[action.id];
            if (!group || group.unreadCount === 0) return state;
            return patchGroup(state, action.id, { unreadCount: 0 });
        }

        case A.RENAME: {
            const group = state.groups[action.id];
            if (!group) return state;
            // Clamped by BYTES, the unit the protocol enforces. A character slice
            // against a byte budget lets a name in a multi-byte script through
            // here and then fails when the roster carrying it is signed.
            const name = clampNameBytes(String(action.name || '').trim()) || group.name;
            return patchGroup(state, action.id, { name });
        }

        case A.SET_ERROR: {
            const group = state.groups[action.id];
            if (!group) return state;
            const patch = { error: action.error || null };
            if (action.error) patch.phase = GROUP_PHASE.FAILED;
            return patchGroup(state, action.id, patch);
        }

        default:
            return state;
    }
}

// ---------------------------------------------------------------------------
// derivation for rendering
// ---------------------------------------------------------------------------

/** How many members currently have a usable pairwise link (including us). */
export function linkedCount(group) {
    return group.members.filter((m) => m.state === MEMBER_STATE.SELF || m.state === MEMBER_STATE.LINKED).length;
}

/**
 * A group is only fully up when every member is reachable. Partial connectivity
 * is shown rather than hidden: in a mesh with no server, a member you cannot
 * reach is a member who is not receiving your messages, and the sender is the
 * only one who can know that.
 */
export function groupSub(group) {
    if (group.phase !== GROUP_PHASE.READY) return GROUP_PHASE_WORD[group.phase] || 'Group';
    const total = group.members.length;
    const linked = linkedCount(group);
    if (linked < total) return `${linked} of ${total} connected`;
    return `${total} members · P2P mesh`;
}

export function groupDot(group) {
    switch (group.phase) {
        case GROUP_PHASE.READY:
            return linkedCount(group) < group.members.length ? 'var(--sb-yellow-2-solid)' : 'var(--sb-green-solid)';
        case GROUP_PHASE.FAILED:
            return 'var(--sb-red-solid)';
        default:
            return 'var(--sb-yellow-2-solid)';
    }
}

export function decorateGroup(group, activeGroupId) {
    const lastMessage = [...group.messages].reverse().find(
        (m) => !m.expired && typeof m.message === 'string' && m.message.trim(),
    );
    const sub = groupSub(group);
    return {
        id: group.id,
        kind: 'group',
        name: group.name,
        mono: groupInitials(group.name),
        dot: groupDot(group),
        headerSub: sub,
        phase: group.phase,
        memberCount: group.members.length,
        linkedCount: linkedCount(group),
        preview: lastMessage ? lastMessage.message : sub,
        unread: group.unreadCount > 0 ? (group.unreadCount > 99 ? '99+' : String(group.unreadCount)) : null,
        verified: group.phase === GROUP_PHASE.READY && group.sasConfirmed,
        active: group.id === activeGroupId,
        inactive: group.id !== activeGroupId,
    };
}

export function decorateGroups(state) {
    return state.order
        .map((id) => state.groups[id])
        .filter(Boolean)
        .map((g) => decorateGroup(g, state.activeGroupId));
}
