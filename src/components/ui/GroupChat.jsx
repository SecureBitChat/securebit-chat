import { t } from '../../i18n/index.js';
// Group chat surfaces: the conversation view, the safety-code ceremony, the
// create dialog and the inbound invitation.
//
// These render from the reducer's group entry and call back into the app; they
// hold no protocol state and no key material. The safety-code modal is the one
// piece here that carries security weight, so it is deliberately blunt: it shows
// the digits, says who has to compare them and how, and offers no way to skip.
//
// React is a global in this app (loaded before the bundle), matching app.jsx.

import { GROUP_PHASE, MEMBER_STATE, groupInitials } from '../../state/groupsStore.js';
import { GROUP_LIMITS } from '../../group/groupCrypto.js';

const h = (...args) => React.createElement(...args);

const C = {
    bg: '#0c0c0e',
    panel: '#141417',
    panel2: '#1b1b1f',
    line: 'rgba(255,255,255,0.07)',
    line2: 'rgba(255,255,255,0.13)',
    ink: '#f4f4f6',
    ink2: '#a7a7b0',
    ink3: '#6b6b73',
    accent: '#f0892a',
    good: '#3ecf8e',
    warn: '#e3b341',
    bad: '#e5727a',
    mono: "'JetBrains Mono', ui-monospace, monospace",
};

const ICON = {
    users: '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 19v-1.5a3.5 3.5 0 0 0-3.5-3.5h-5A3.5 3.5 0 0 0 4 17.5V19"/><circle cx="10" cy="8" r="3.2"/><path d="M20 19v-1.5a3.5 3.5 0 0 0-2.6-3.4"/><path d="M15.5 5.3a3.2 3.2 0 0 1 0 5.4"/></svg>',
    send: '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2 11 13"/><path d="m22 2-7 20-4-9-9-4 20-7z"/></svg>',
    shield: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>',
    x: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>',
    plus: '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></svg>',
    relay: '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 12h4l3-7 4 14 3-7h2"/></svg>',
};

const svg = (markup, extra = {}) => h('span', {
    style: { display: 'grid', placeItems: 'center', ...extra },
    dangerouslySetInnerHTML: { __html: markup },
});

const btn = (accent = false) => ({
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center', gap: '8px',
    padding: '11px 18px', borderRadius: '10px', cursor: 'pointer',
    fontFamily: 'inherit', fontSize: '14px', fontWeight: 700,
    border: accent ? 'none' : `1px solid ${C.line2}`,
    background: accent ? C.accent : 'transparent',
    color: accent ? '#1a0f04' : C.ink2,
});

const overlay = {
    position: 'fixed', inset: 0, zIndex: 90, display: 'grid', placeItems: 'center',
    background: 'rgba(5,5,7,0.72)', backdropFilter: 'blur(6px)', padding: '20px',
};

const card = {
    width: '100%', maxWidth: '440px', background: C.panel, border: `1px solid ${C.line}`,
    borderRadius: '16px', padding: '24px', display: 'flex', flexDirection: 'column', gap: '18px',
    boxShadow: '0 24px 60px rgba(0,0,0,0.5)',
};

/** Trim a string so its UTF-8 encoding fits `max` bytes, never mid-character. */
function clampToBytes(value, max) {
    const enc = new TextEncoder();
    let out = String(value);
    while (enc.encode(out).length > max) out = out.slice(0, -1);
    return out;
}

const label = {
    fontFamily: C.mono, fontSize: '10px', fontWeight: 700, letterSpacing: '1.3px',
    textTransform: 'uppercase', color: C.ink3,
};

// ---------------------------------------------------------------------------
// the safety-code ceremony
// ---------------------------------------------------------------------------

/**
 * The group's safety code.
 *
 * Every member sees the same seven digits, and the comparison has to happen over
 * something an attacker cannot impersonate. The copy says so plainly, because
 * this is the step that distinguishes the intended group from a member who
 * introduced two people and sat between them — the code is the only thing that
 * catches it, and a user who dismisses it has verified nothing.
 */
/**
 * What to say while there is no code yet.
 *
 * This used to collapse to t('group.exchangingNonces') for every phase that was not
 * COMMITTING — which included FAILED. A group that had actually died therefore
 * looked identical to one still working, the confirm button stayed disabled, and
 * the only visible symptom was a dialog that never finished. Naming the real
 * state is the difference between a hang and a diagnosis.
 */
function waitingWord(group) {
    switch (group.phase) {
        case GROUP_PHASE.FORMING: return t('group.waitingJoin');
        case GROUP_PHASE.COMMITTING: return t('group.waitingCommit');
        case GROUP_PHASE.REVEALING: return t('group.exchangingNonces');
        case GROUP_PHASE.FAILED: return GROUP_ERROR_WORD[group.error] || t('group.errNotFormed');
        default: return t('group.working');
    }
}

/** Failure codes from GroupSession, in words a person can act on. */
const GROUP_ERROR_WORD = {
    invitations_could_not_be_sent: t('group.errInviteFailed'),
    invitees_did_not_respond: t('group.errNobodyAccepted'),
    roster_never_arrived: t('group.errNoMemberList'),
    ceremony_timed_out: t('groupErr.timeout'),
    bad_signature: t('group.errUnsignedList'),
    wrong_admin: t('group.errNotOwner'),
    fingerprint_mismatch: t('groupErr.keyMismatch'),
    commitment_mismatch: t('groupErr.revealMismatch'),
    commitment_changed: t('groupErr.commitChanged'),
    missing_member_key: t('groupErr.missingKey'),
    not_a_member: t('groupErr.outsider'),
    bad_name: t('group.nameTooLong'),
    too_many_members: t('groupErr.limit'),
    frame_too_large: t('groupErr.tooLarge'),
};

export function GroupSasModal({ group, onConfirm, onCancel }) {
    if (!group) return null;
    const failed = group.phase === GROUP_PHASE.FAILED;
    const waiting = group.phase !== GROUP_PHASE.AWAITING_SAS || !group.sasCode;

    return h('div', { style: overlay, role: 'dialog', 'aria-modal': 'true' },
        h('div', { style: card }, [
            h('div', { key: 'h', style: { display: 'flex', flexDirection: 'column', gap: '6px' } }, [
                h('span', { key: 'l', style: label }, t('group.sasTitle')),
                h('h3', { key: 't', style: { margin: 0, fontSize: '19px', fontWeight: 700, color: C.ink } }, group.name),
            ]),

            waiting
                ? h('div', {
                    key: 'wait',
                    style: {
                        padding: '28px 16px', textAlign: 'center', borderRadius: '12px',
                        background: C.panel2, border: `1px solid ${C.line}`, color: C.ink2, fontSize: '14px',
                    },
                }, [
                    h('div', {
                        key: 'd',
                        style: {
                            fontFamily: C.mono, fontSize: '26px', letterSpacing: '6px',
                            color: failed ? C.bad : C.ink3,
                        },
                    }, '·······'),
                    h('div', { key: 's', style: { marginTop: '10px', color: failed ? C.bad : C.ink2 } }, waitingWord(group)),
                    failed && h('div', {
                        key: 'why',
                        style: { marginTop: '6px', fontFamily: C.mono, fontSize: '11px', color: C.ink3 },
                    }, group.error || 'unknown'),
                ])
                : h('div', {
                    key: 'code',
                    style: {
                        padding: '22px 16px', textAlign: 'center', borderRadius: '12px',
                        background: 'rgba(240,137,42,0.09)', border: '1px solid rgba(240,137,42,0.3)',
                    },
                }, h('span', {
                    style: {
                        fontFamily: C.mono, fontSize: 'clamp(30px, 9vw, 42px)', fontWeight: 700,
                        letterSpacing: '9px', color: C.accent,
                    },
                }, group.sasCode)),

            h('p', {
                key: 'why',
                style: { margin: 0, fontSize: '13.5px', lineHeight: 1.62, color: C.ink2 },
            }, [
                t('group.sasReadAloud'), h('b', { key: 'b', style: { color: C.ink } }, `all ${group.members.length - 1} other members`),
                ' — in person, or on a call where you recognise every voice. Everyone must see the same code.',
            ]),

            h('p', {
                key: 'warn',
                style: {
                    margin: 0, padding: '11px 13px', borderRadius: '9px', fontSize: '12.5px', lineHeight: 1.55,
                    background: 'rgba(229,114,122,0.09)', border: '1px solid rgba(229,114,122,0.26)', color: '#f0a6ab',
                },
            }, failed
                ? t('group.errNothingSent')
                : t('group.sasWarning')),

            h('div', { key: 'actions', style: { display: 'flex', gap: '10px' } }, [
                h('button', { key: 'c', onClick: onCancel, style: { ...btn(failed), flex: failed ? 2 : 1 } },
                    failed ? t('group.close') : t('group.cancel')),
                !failed && h('button', {
                    key: 'ok', onClick: onConfirm, disabled: waiting,
                    style: { ...btn(true), flex: 2, opacity: waiting ? 0.4 : 1, cursor: waiting ? 'not-allowed' : 'pointer' },
                }, [svg(ICON.shield, { key: 'i' }), t('group.sasEveryone')]),
            ]),
        ]));
}

// ---------------------------------------------------------------------------
// creating a group
// ---------------------------------------------------------------------------

/**
 * Pick members from the 1:1 chats that are already verified.
 *
 * Only verified sessions are offered. A group built on an unverified session
 * would inherit that session's uncertainty and hide it behind a group code that
 * looks like it settled the question.
 */
export function CreateGroupModal({ candidates, relayOnly, onCreate, onCancel }) {
    const [name, setName] = React.useState('');
    const [picked, setPicked] = React.useState([]);
    const max = GROUP_LIMITS.MAX_MEMBERS - 1; // the creator takes one slot

    const toggle = (id) => setPicked((prev) => (
        prev.includes(id) ? prev.filter((x) => x !== id)
            : prev.length >= max ? prev : [...prev, id]
    ));

    const ready = name.trim().length > 0 && picked.length >= 1;

    return h('div', { style: overlay, role: 'dialog', 'aria-modal': 'true' },
        h('div', { style: { ...card, maxWidth: '470px' } }, [
            h('div', { key: 'h', style: { display: 'flex', flexDirection: 'column', gap: '6px' } }, [
                h('span', { key: 'l', style: label }, t('group.new')),
                h('p', {
                    key: 'p',
                    style: { margin: 0, fontSize: '13.5px', lineHeight: 1.6, color: C.ink2 },
                }, t('group.capacity', { max: GROUP_LIMITS.MAX_MEMBERS })),
            ]),

            h('input', {
                key: 'name',
                value: name,
                // Clamped by BYTES, because that is the limit the protocol
                // enforces. Counting characters here let a Cyrillic name through
                // the dialog that the admin's roster signing then rejected.
                onChange: (e) => setName(clampToBytes(e.target.value, GROUP_LIMITS.MAX_NAME_BYTES)),
                placeholder: t('group.name'),
                style: {
                    width: '100%', padding: '12px 14px', borderRadius: '10px', outline: 'none',
                    background: C.panel2, border: `1px solid ${C.line2}`, color: C.ink,
                    fontFamily: 'inherit', fontSize: '14.5px',
                },
            }),

            h('div', { key: 'pick', style: { display: 'flex', flexDirection: 'column', gap: '9px' } }, [
                h('div', { key: 'l', style: { display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' } }, [
                    h('span', { key: 'a', style: label }, t('group.members')),
                    h('span', { key: 'b', style: { ...label, color: picked.length >= max ? C.warn : C.ink3 } },
                        `${picked.length} / ${max}`),
                ]),
                candidates.length === 0
                    ? h('div', {
                        key: 'empty',
                        style: {
                            padding: '18px 14px', borderRadius: '10px', textAlign: 'center',
                            background: C.panel2, border: `1px dashed ${C.line2}`, color: C.ink3, fontSize: '13px', lineHeight: 1.55,
                        },
                    }, t('group.noVerified'))
                    : h('div', {
                        key: 'list',
                        className: 'msc-scroll',
                        style: { display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '240px', overflowY: 'auto' },
                    }, candidates.map((c) => {
                        const on = picked.includes(c.id);
                        const full = !on && picked.length >= max;
                        return h('button', {
                            key: c.id,
                            onClick: () => toggle(c.id),
                            disabled: full,
                            style: {
                                display: 'flex', alignItems: 'center', gap: '11px', padding: '10px 12px',
                                borderRadius: '10px', cursor: full ? 'not-allowed' : 'pointer', textAlign: 'left',
                                background: on ? 'rgba(240,137,42,0.1)' : 'transparent',
                                border: `1px solid ${on ? 'rgba(240,137,42,0.32)' : C.line}`,
                                opacity: full ? 0.4 : 1, fontFamily: 'inherit',
                            },
                        }, [
                            h('span', {
                                key: 'av',
                                style: {
                                    flex: 'none', width: '32px', height: '32px', borderRadius: '9px', display: 'grid',
                                    placeItems: 'center', background: C.panel2, border: `1px solid ${C.line}`,
                                    fontFamily: C.mono, fontSize: '11px', fontWeight: 700, color: C.ink2,
                                },
                            }, c.mono),
                            h('span', { key: 'n', style: { flex: 1, minWidth: 0, fontSize: '14px', color: C.ink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, c.name),
                            h('span', {
                                key: 'tick',
                                style: {
                                    flex: 'none', width: '18px', height: '18px', borderRadius: '5px',
                                    background: on ? C.accent : 'transparent',
                                    border: `1px solid ${on ? C.accent : C.line2}`,
                                },
                            }),
                        ]);
                    })),
            ]),

            // A group is a bigger exposure than a 1:1 chat: without a relay, every
            // member's address is visible to every other member, including people
            // the user did not personally invite. Say it before they commit, not
            // after.
            !relayOnly && h('p', {
                key: 'ip',
                style: {
                    margin: 0, padding: '11px 13px', borderRadius: '9px', fontSize: '12.5px', lineHeight: 1.55,
                    background: 'rgba(227,179,65,0.08)', border: '1px solid rgba(227,179,65,0.26)', color: '#e3b341',
                },
            }, t('group.relayOnlyOff')),

            h('div', { key: 'actions', style: { display: 'flex', gap: '10px' } }, [
                h('button', { key: 'c', onClick: onCancel, style: { ...btn(false), flex: 1 } }, t('group.cancelBtn')),
                h('button', {
                    key: 'ok',
                    onClick: () => ready && onCreate({ name: name.trim(), sessionIds: picked }),
                    disabled: !ready,
                    style: { ...btn(true), flex: 2, opacity: ready ? 1 : 0.4, cursor: ready ? 'pointer' : 'not-allowed' },
                }, t('group.create')),
            ]),
        ]));
}

// ---------------------------------------------------------------------------
// something went wrong forming a group
// ---------------------------------------------------------------------------

/**
 * Says what failed and what to do about it.
 *
 * Group formation runs across several links at once, so a failure here is
 * usually one dead connection rather than anything the user did wrong. The
 * message names the cause; there is nothing to retry automatically, because a
 * link that is down will still be down a second later.
 */
export function GroupErrorModal({ message, onDismiss }) {
    if (!message) return null;
    return h('div', { style: overlay, role: 'alertdialog', 'aria-modal': 'true' },
        h('div', { style: { ...card, maxWidth: '400px' } }, [
            h('span', { key: 'l', style: label }, t('group.errNotCreated')),
            h('p', {
                key: 'm',
                style: { margin: 0, fontSize: '14px', lineHeight: 1.6, color: C.ink2 },
            }, message),
            h('button', { key: 'ok', onClick: onDismiss, style: btn(true) }, t('group.close')),
        ]));
}

// ---------------------------------------------------------------------------
// adding people to a running group
// ---------------------------------------------------------------------------

/**
 * Invite more members into an open group.
 *
 * Only verified 1:1 chats that are not already in the group are offered, and the
 * dialog says plainly what adding somebody costs: a new epoch, and a new code
 * that everyone has to compare again. The safety code covers the member set, so
 * a changed set means the old code no longer describes who is in the room.
 */
export function AddMembersModal({ candidates, remaining, onAdd, onCancel }) {
    const [picked, setPicked] = React.useState([]);
    const toggle = (id) => setPicked((prev) => (
        prev.includes(id) ? prev.filter((x) => x !== id)
            : prev.length >= remaining ? prev : [...prev, id]
    ));

    return h('div', { style: overlay, role: 'dialog', 'aria-modal': 'true' },
        h('div', { style: { ...card, maxWidth: '440px' } }, [
            h('div', { key: 'h', style: { display: 'flex', flexDirection: 'column', gap: '6px' } }, [
                h('span', { key: 'l', style: label }, t('group.addMembers')),
                h('p', {
                    key: 'p',
                    style: { margin: 0, fontSize: '13.5px', lineHeight: 1.6, color: C.ink2 },
                }, remaining > 0
                    ? t('group.roomFor', { remaining })
                    : t('group.errFull')),
            ]),

            candidates.length === 0
                ? h('div', {
                    key: 'empty',
                    style: {
                        padding: '18px 14px', borderRadius: '10px', textAlign: 'center',
                        background: C.panel2, border: `1px dashed ${C.line2}`, color: C.ink3, fontSize: '13px', lineHeight: 1.55,
                    },
                }, t('group.noMoreToAdd'))
                : h('div', {
                    key: 'list',
                    className: 'msc-scroll',
                    style: { display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '260px', overflowY: 'auto' },
                }, candidates.map((c) => {
                    const on = picked.includes(c.id);
                    const full = !on && picked.length >= remaining;
                    return h('button', {
                        key: c.id,
                        onClick: () => toggle(c.id),
                        disabled: full,
                        style: {
                            display: 'flex', alignItems: 'center', gap: '11px', padding: '10px 12px',
                            borderRadius: '10px', cursor: full ? 'not-allowed' : 'pointer', textAlign: 'left',
                            background: on ? 'rgba(240,137,42,0.1)' : 'transparent',
                            border: `1px solid ${on ? 'rgba(240,137,42,0.32)' : C.line}`,
                            opacity: full ? 0.4 : 1, fontFamily: 'inherit',
                        },
                    }, [
                        h('span', {
                            key: 'av',
                            style: {
                                flex: 'none', width: '32px', height: '32px', borderRadius: '9px', display: 'grid',
                                placeItems: 'center', background: C.panel2, border: `1px solid ${C.line}`,
                                fontFamily: C.mono, fontSize: '11px', fontWeight: 700, color: C.ink2,
                            },
                        }, c.mono),
                        h('span', { key: 'n', style: { flex: 1, minWidth: 0, fontSize: '14px', color: C.ink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' } }, c.name),
                        h('span', {
                            key: 'tick',
                            style: {
                                flex: 'none', width: '18px', height: '18px', borderRadius: '5px',
                                background: on ? C.accent : 'transparent',
                                border: `1px solid ${on ? C.accent : C.line2}`,
                            },
                        }),
                    ]);
                })),

            h('p', {
                key: 'note',
                style: {
                    margin: 0, padding: '11px 13px', borderRadius: '9px', fontSize: '12.5px', lineHeight: 1.55,
                    background: C.panel2, border: `1px solid ${C.line}`, color: C.ink3,
                },
            }, t('group.inviteSentNote')),

            h('div', { key: 'actions', style: { display: 'flex', gap: '10px' } }, [
                h('button', { key: 'c', onClick: onCancel, style: { ...btn(false), flex: 1 } }, t('group.cancelBtn')),
                h('button', {
                    key: 'ok',
                    onClick: () => picked.length && onAdd(picked),
                    disabled: picked.length === 0,
                    style: { ...btn(true), flex: 2, opacity: picked.length ? 1 : 0.4, cursor: picked.length ? 'pointer' : 'not-allowed' },
                }, picked.length > 1 ? t('group.invitePeople', { count: picked.length }) : t('group.invite')),
            ]),
        ]));
}

// ---------------------------------------------------------------------------
// an inbound invitation
// ---------------------------------------------------------------------------

export function GroupInviteModal({ invite, onAccept, onDecline }) {
    if (!invite) return null;
    return h('div', { style: overlay, role: 'dialog', 'aria-modal': 'true' },
        h('div', { style: card }, [
            h('div', { key: 'h', style: { display: 'flex', flexDirection: 'column', gap: '6px' } }, [
                h('span', { key: 'l', style: label }, t('group.invitation')),
                h('h3', { key: 't', style: { margin: 0, fontSize: '19px', fontWeight: 700, color: C.ink } }, invite.name),
            ]),
            h('p', {
                key: 'p',
                style: { margin: 0, fontSize: '13.5px', lineHeight: 1.62, color: C.ink2 },
            }, [
                h('b', { key: 'b', style: { color: C.ink } }, invite.fromLabel),
                ' invited you to a peer-to-peer group. You will compare one safety code with every member before anything is sent.',
            ]),
            h('p', {
                key: 'note',
                style: {
                    margin: 0, padding: '11px 13px', borderRadius: '9px', fontSize: '12.5px', lineHeight: 1.55,
                    background: C.panel2, border: `1px solid ${C.line}`, color: C.ink3,
                },
            }, t('group.joinNote')),
            h('div', { key: 'actions', style: { display: 'flex', gap: '10px' } }, [
                h('button', { key: 'd', onClick: onDecline, style: { ...btn(false), flex: 1 } }, t('group.decline')),
                h('button', { key: 'a', onClick: onAccept, style: { ...btn(true), flex: 2 } }, t('group.join')),
            ]),
        ]));
}

// ---------------------------------------------------------------------------
// the conversation
// ---------------------------------------------------------------------------

function MemberStrip({ group, onRemove, isAdmin }) {
    return h('div', {
        className: 'msc-scroll',
        style: {
            display: 'flex', gap: '7px', padding: '9px 16px', overflowX: 'auto',
            borderBottom: `1px solid ${C.line}`, flex: 'none',
        },
    }, group.members.map((m) => {
        const self = m.state === MEMBER_STATE.SELF;
        const lost = m.state === MEMBER_STATE.LOST;
        const dot = self || m.state === MEMBER_STATE.LINKED ? C.good
            : m.state === MEMBER_STATE.PENDING ? C.warn : C.bad;
        const via = m.state === MEMBER_STATE.PENDING;
        return h('span', {
            key: m.fp,
            title: self ? 'You'
                : m.state === MEMBER_STATE.LINKED ? t('group.directLink')
                : m.state === MEMBER_STATE.PENDING ? t('group.noDirectLink')
                : t('group.memberOffline', { name: m.name }),
            style: {
                flex: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px',
                padding: '5px 10px', borderRadius: '20px',
                // A member who is offline should not read as one who is present.
                // They stay listed because membership is a signed, epoch-ordered
                // fact that a dropped connection does not change — but the chip
                // says plainly that nothing sent now reaches them.
                background: lost ? 'transparent' : C.panel2,
                border: `1px solid ${lost ? 'rgba(229,114,122,0.3)' : C.line}`,
                fontSize: '12.5px', color: self ? C.ink : (lost ? C.ink3 : C.ink2),
                opacity: lost ? 0.75 : 1,
            },
        }, [
            h('span', { key: 'd', style: { width: '7px', height: '7px', borderRadius: '50%', background: dot } }),
            h('span', { key: 'n', style: lost ? { textDecoration: 'line-through' } : undefined }, self ? 'You' : m.name),
            lost && h('span', {
                key: 'off',
                style: { fontFamily: C.mono, fontSize: '10px', color: C.bad, letterSpacing: '0.04em' },
            }, 'offline'),
            via && svg(ICON.relay, { key: 'r', color: C.warn }),
            (isAdmin && !self && onRemove) && h('button', {
                key: 'x',
                onClick: () => onRemove(m.fp),
                title: t('group.remove', { name: m.name }),
                style: { border: 'none', background: 'transparent', color: C.ink3, cursor: 'pointer', display: 'grid', padding: 0 },
                dangerouslySetInnerHTML: { __html: '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round"><path d="M18 6 6 18M6 6l12 12"/></svg>' },
            }),
        ]);
    }));
}

function Bubble({ msg }) {
    const mine = msg.type === 'sent';
    const system = msg.type === 'system';
    if (system) {
        return h('div', {
            style: {
                alignSelf: 'center', maxWidth: '80%', textAlign: 'center', padding: '6px 12px',
                borderRadius: '9px', background: C.panel2, border: `1px solid ${C.line}`,
                fontSize: '12px', color: C.ink3, lineHeight: 1.5,
            },
        }, msg.message);
    }
    return h('div', {
        style: {
            alignSelf: mine ? 'flex-end' : 'flex-start', maxWidth: 'min(74%, 560px)',
            display: 'flex', flexDirection: 'column', gap: '3px',
        },
    }, [
        !mine && h('span', {
            key: 'who',
            style: { fontSize: '11.5px', fontWeight: 600, color: C.accent, paddingLeft: '3px' },
        }, msg.senderName || t('group.member')),
        h('div', {
            key: 'b',
            style: {
                padding: '9px 13px', borderRadius: mine ? '13px 13px 4px 13px' : '13px 13px 13px 4px',
                background: mine ? 'rgba(240,137,42,0.14)' : C.panel2,
                border: `1px solid ${mine ? 'rgba(240,137,42,0.26)' : C.line}`,
                color: C.ink, fontSize: '14.5px', lineHeight: 1.5, wordBreak: 'break-word', whiteSpace: 'pre-wrap',
            },
        }, msg.message),
        h('span', {
            key: 't',
            style: { fontFamily: C.mono, fontSize: '10px', color: C.ink3, alignSelf: mine ? 'flex-end' : 'flex-start', padding: '0 3px' },
        }, [
            new Date(msg.timestamp || Date.now()).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
            msg.relayed ? ' · relayed' : '',
        ].join('')),
    ]);
}

export function GroupChatView({
    group, input, setInput, onSend, onLeave, onRemoveMember, onAddMembers, isAdmin, scrollRef,
}) {
    const ready = group.phase === GROUP_PHASE.READY && group.sasConfirmed;
    // Only members we are RELAYING to. A member who is offline is not relayed —
    // they are unreachable, which the member strip already says in its own
    // words — and counting them here put a notice about relaying on screen for
    // a situation where nothing is being relayed at all.
    const degraded = group.members.some((m) => m.state === MEMBER_STATE.PENDING);

    const submit = (e) => {
        e.preventDefault();
        if (!ready || !input.trim()) return;
        onSend(input);
    };

    return h('div', {
        style: { display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, background: C.bg },
    }, [
        // header
        h('div', {
            key: 'head',
            style: {
                flex: 'none', display: 'flex', alignItems: 'center', gap: '12px', padding: '0 16px',
                height: '64px', borderBottom: `1px solid ${C.line}`,
            },
        }, [
            h('span', {
                key: 'av',
                style: {
                    flex: 'none', width: '38px', height: '38px', borderRadius: '11px', display: 'grid',
                    placeItems: 'center', background: 'rgba(240,137,42,0.12)',
                    border: '1px solid rgba(240,137,42,0.24)', color: C.accent,
                    fontFamily: C.mono, fontSize: '12px', fontWeight: 700,
                },
            }, groupInitials(group.name)),
            h('div', { key: 'meta', style: { flex: 1, minWidth: 0 } }, [
                h('div', {
                    key: 'n',
                    style: { fontSize: '15px', fontWeight: 700, color: C.ink, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
                }, group.name),
                h('div', {
                    key: 's',
                    style: { fontSize: '11.5px', color: degraded ? C.warn : C.ink3, display: 'flex', alignItems: 'center', gap: '5px' },
                }, [
                    svg(ICON.users, { key: 'i', width: '13px', height: '13px' }),
                    t('group.membersCount', { count: group.members.length }),
                    ready && group.sasCode ? t('group.codeSuffix', { code: group.sasCode }) : '',
                ]),
            ]),
            (isAdmin && onAddMembers && group.members.length < GROUP_LIMITS.MAX_MEMBERS) && h('button', {
                key: 'add', onClick: onAddMembers, title: t('group.inviteMore'),
                style: { ...btn(false), padding: '8px 12px', fontSize: '12.5px' },
            }, [svg(ICON.plus, { key: 'i' }), t('group.add')]),
            h('button', {
                key: 'leave', onClick: onLeave, title: t('group.leaveThis'),
                style: { ...btn(false), padding: '8px 12px', fontSize: '12.5px', color: C.bad, borderColor: 'rgba(229,114,122,0.3)' },
            }, t('group.leave')),
        ]),

        h(MemberStrip, { key: 'strip', group, onRemove: onRemoveMember, isAdmin }),

        degraded && ready && h('div', {
            key: 'relay-note',
            style: {
                flex: 'none', padding: '8px 16px', fontSize: '12px', lineHeight: 1.5, color: C.warn,
                background: 'rgba(227,179,65,0.08)', borderBottom: `1px solid ${C.line}`,
            },
        }, t('group.relayNote')),

        // transcript
        h('div', {
            key: 'msgs',
            ref: scrollRef,
            className: 'msc-scroll',
            style: {
                flex: 1, minHeight: 0, overflowY: 'auto', padding: '18px 16px',
                display: 'flex', flexDirection: 'column', gap: '11px',
            },
        }, group.messages.length === 0
            ? [h('div', {
                key: 'empty',
                style: { margin: 'auto', textAlign: 'center', color: C.ink3, fontSize: '13.5px', lineHeight: 1.6, maxWidth: '320px' },
            }, ready
                ? t('group.emptyChat')
                : t('group.sasCompare'))]
            : group.messages.map((m) => h(Bubble, { key: m.id, msg: m }))),

        // composer
        h('form', {
            key: 'composer',
            onSubmit: submit,
            style: {
                flex: 'none', display: 'flex', gap: '9px', padding: '12px 16px',
                borderTop: `1px solid ${C.line}`, alignItems: 'flex-end',
            },
        }, [
            h('input', {
                key: 'in',
                value: input,
                onChange: (e) => setInput(e.target.value),
                placeholder: ready ? t('group.message', { name: group.name }) : t('group.confirmFirst'),
                disabled: !ready,
                maxLength: GROUP_LIMITS.MAX_BODY_BYTES,
                style: {
                    flex: 1, minWidth: 0, padding: '12px 14px', borderRadius: '11px', outline: 'none',
                    background: C.panel2, border: `1px solid ${C.line2}`, color: C.ink,
                    fontFamily: 'inherit', fontSize: '14.5px', opacity: ready ? 1 : 0.5,
                },
            }),
            h('button', {
                key: 'send', type: 'submit', disabled: !ready || !input.trim(), title: t('group.send'),
                style: {
                    ...btn(true), flex: 'none', width: '44px', height: '44px', padding: 0, borderRadius: '11px',
                    opacity: (!ready || !input.trim()) ? 0.4 : 1,
                },
            }, svg(ICON.send)),
        ]),
    ]);
}
