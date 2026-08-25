// Group frames against the transport's real rate limit.
//
// This is the test that was missing when group formation kept dying. The manager
// allows a burst of ten sends per second, but one group frame spends TWO of those
// slots — sendMessage checks the shared limiter and then sendSecureMessage checks
// it again — so the six frames formation sends back to back asked for twelve.
// The overflow was rejected as a plain Error with no code, which reached the user
// as a meaningless "frame_rejected", while the peer that never got the dropped
// frame waited until "ceremony_timed_out".
//
// The stand-in manager below reproduces that accounting exactly. Time is
// injected, so the pacing is asserted rather than waited for.

import assert from 'node:assert/strict';

const { createGroupSender, GROUP_SEND_GAP_MS } = await import('../src/group/groupSender.js');

/** A virtual clock: sleeps advance it instead of blocking. */
function makeClock() {
    let t = 0;
    return {
        now: () => t,
        sleep: async (ms) => { t += Math.max(0, ms); },
        advance: (ms) => { t += ms; },
    };
}

/**
 * A manager with the real limiter's shape: ten slots per rolling second, and two
 * slots consumed per outbound message.
 */
function makeManager(clock, { burst = 10, slotsPerSend = 2, connected = true } = {}) {
    let windowStart = clock.now();
    let used = 0;
    const sent = [];
    return {
        sent,
        isConnected: () => connected,
        async sendMessage(payload) {
            if (clock.now() - windowStart >= 1000) { windowStart = clock.now(); used = 0; }
            if (used + slotsPerSend > burst) {
                // Verbatim from EnhancedSecureWebRTCManager: a plain Error, no code.
                throw new Error('Rate limit exceeded for message sending');
            }
            used += slotsPerSend;
            sent.push({ at: clock.now(), payload });
            return true;
        },
    };
}

// ---------------------------------------------------------------------------
// the six frames of group formation all arrive
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    const manager = makeManager(clock);
    const send = createGroupSender({
        getManager: () => manager, now: clock.now, sleep: clock.sleep,
    });

    // Exactly what forming a group puts on one session.
    const frames = ['g_invite', 'g_member', 'g_member', 'g_roster', 'g_commit', 'g_reveal']
        .map((type, i) => ({ type, gid: 'a'.repeat(32), seq: i }));

    await Promise.all(frames.map((f) => send('s1', f)));

    assert.equal(manager.sent.length, 6, 'every formation frame must reach the transport');

    // Order is protocol-critical: a commitment has to arrive before the reveal
    // that opens it. Concurrent sends must not reorder.
    assert.deepEqual(
        manager.sent.map((s) => JSON.parse(s.payload).type),
        ['g_invite', 'g_member', 'g_member', 'g_roster', 'g_commit', 'g_reveal'],
        'frames keep the order they were queued in',
    );

    // And they are spaced, which is what keeps them inside the burst budget.
    for (let i = 1; i < manager.sent.length; i++) {
        const gap = manager.sent[i].at - manager.sent[i - 1].at;
        assert.ok(gap >= GROUP_SEND_GAP_MS,
            `frame ${i} came ${gap}ms after the last, under the ${GROUP_SEND_GAP_MS}ms budget`);
    }
}

// ---------------------------------------------------------------------------
// without pacing the same run fails — the bug this exists to prevent
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    const manager = makeManager(clock);
    const send = createGroupSender({
        getManager: () => manager, now: clock.now, sleep: clock.sleep,
        gapMs: 0, attempts: 1, // pacing and retries disabled
    });

    const results = await Promise.allSettled(
        Array.from({ length: 6 }, (_, i) => send('s1', { type: 'g_commit', seq: i })),
    );
    const rejected = results.filter((r) => r.status === 'rejected');
    assert.ok(rejected.length > 0, 'unpaced, the burst limit really does reject frames');
    assert.match(rejected[0].reason.message, /Rate limit exceeded/);
    // And the rejection carries no `code`, which is why it surfaced as the
    // generic frame_rejected rather than anything a user could act on.
    assert.equal(rejected[0].reason.code, undefined);
}

// ---------------------------------------------------------------------------
// a rate-limited frame is retried, not dropped
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    let calls = 0;
    const manager = {
        isConnected: () => true,
        async sendMessage() {
            calls++;
            if (calls <= 2) throw new Error('Rate limit exceeded for secure message sending');
            return true;
        },
    };
    const send = createGroupSender({ getManager: () => manager, now: clock.now, sleep: clock.sleep });

    await send('s1', { type: 'g_commit' });
    assert.equal(calls, 3, 'the frame is retried until it lands — losing one strands every member');
}

// ---------------------------------------------------------------------------
// failures that will not improve are surfaced, not retried
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    let calls = 0;
    const manager = {
        isConnected: () => true,
        async sendMessage() { calls++; throw new Error('Data channel not ready'); },
    };
    const send = createGroupSender({ getManager: () => manager, now: clock.now, sleep: clock.sleep });

    await assert.rejects(() => send('s1', { type: 'g_commit' }), /Data channel not ready/);
    assert.equal(calls, 1, 'a closed channel is reported at once rather than retried');

    // One failure must not wedge the session: later frames still go out.
    const ok = { isConnected: () => true, sent: 0, async sendMessage() { this.sent++; return true; } };
    const send2 = createGroupSender({
        getManager: (id) => (id === 'dead' ? manager : ok), now: clock.now, sleep: clock.sleep,
    });
    await assert.rejects(() => send2('dead', { type: 'g_commit' }));
    await send2('dead', { type: 'g_reveal' }).catch(() => {});
    await send2('live', { type: 'g_reveal' });
    assert.equal(ok.sent, 1, 'a rejected frame does not block the queue behind it');
}

// ---------------------------------------------------------------------------
// a link that is gone is refused before anything is queued
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    const send = createGroupSender({ getManager: () => null, now: clock.now, sleep: clock.sleep });
    await assert.rejects(() => send('s1', { type: 'g_commit' }), /no such link/);

    const offline = createGroupSender({
        getManager: () => ({ isConnected: () => false, sendMessage: async () => true }),
        now: clock.now, sleep: clock.sleep,
    });
    await assert.rejects(() => offline('s1', { type: 'g_commit' }), /link is down/);
}

// ---------------------------------------------------------------------------
// separate sessions do not queue behind each other
// ---------------------------------------------------------------------------
{
    const clock = makeClock();
    const a = makeManager(clock);
    const b = makeManager(clock);
    const send = createGroupSender({
        getManager: (id) => (id === 'a' ? a : b), now: clock.now, sleep: clock.sleep,
    });

    await Promise.all([send('a', { type: 'g_commit' }), send('b', { type: 'g_commit' })]);
    assert.equal(a.sent.length, 1);
    assert.equal(b.sent.length, 1);
    assert.equal(a.sent[0].at, b.sent[0].at, 'each session paces independently');
}

console.log('group-sender.test.mjs: all assertions passed');
