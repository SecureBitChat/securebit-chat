// Paced, serialised delivery of group frames over pairwise sessions.
//
// WHY THIS EXISTS
// ---------------
// A group frame rides `EnhancedSecureWebRTCManager.sendMessage`, which is the
// right call — it inherits the session's encryption, ratchet, replay protection
// and verification gate without adding a second path through the transport. But
// that path is rate limited, and the accounting is not what it looks like:
// `sendMessage` checks the limiter and then hands off to `sendSecureMessage`,
// which checks the SAME shared counter again. One frame therefore spends two of
// the ten burst slots available per second.
//
// Forming a group sends six frames back to back on one session — invite, two
// member keys, roster, commit, reveal — which asks for twelve slots out of ten.
// The overflow was rejected, and rejected as a plain `Error` with no code, so it
// surfaced to the user as a meaningless `frame_rejected`; the peer that never
// received the dropped frame simply waited until the ceremony timed out. Two
// different symptoms, one cause.
//
// The fix belongs here rather than in the limiter. Widening the burst allowance
// would loosen a control that exists for the 1:1 chat, to suit a caller that can
// perfectly well wait: five frames a second makes group formation take about a
// second and a half, which nobody notices.
//
// Sends are also SERIALISED per session. The protocol is order-dependent — a
// commitment must reach a peer before the reveal that opens it — and firing
// several `sendMessage` calls concurrently at one channel puts that ordering at
// the mercy of the manager's internal mutex.
//
// Time is injected so the pacing can be tested without waiting for it.

/**
 * Minimum gap between two group frames on one session, in milliseconds.
 * Two limiter slots per frame against a ten-per-second burst means five frames
 * per second is the real budget; 260ms leaves a little headroom.
 */
export const GROUP_SEND_GAP_MS = 260;

/** How many times a rate-limited frame is retried before giving up. */
export const GROUP_SEND_ATTEMPTS = 4;

const isRateLimit = (error) => /rate limit/i.test(error?.message || '');

/**
 * Build the `send` function a GroupSession is constructed with.
 *
 * @param {object} opts
 * @param {(sessionId: string) => object|null} opts.getManager  resolve a live manager
 * @param {number} [opts.gapMs]
 * @param {number} [opts.attempts]
 * @param {() => number} [opts.now]
 * @param {(ms: number) => Promise<void>} [opts.sleep]
 */
export function createGroupSender({
    getManager,
    gapMs = GROUP_SEND_GAP_MS,
    attempts = GROUP_SEND_ATTEMPTS,
    now = () => Date.now(),
    sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
} = {}) {
    /** sessionId -> { chain, lastAt } */
    const queues = new Map();

    return async function sendGroupFrame(sessionId, frame) {
        const manager = getManager(sessionId);
        if (!manager || typeof manager.sendMessage !== 'function') throw new Error('no such link');
        if (typeof manager.isConnected === 'function' && !manager.isConnected()) {
            throw new Error('link is down');
        }

        const queue = queues.get(sessionId) || { chain: Promise.resolve(), lastAt: 0 };
        const payload = JSON.stringify(frame);

        const run = queue.chain.then(async () => {
            const wait = gapMs - (now() - queue.lastAt);
            if (wait > 0) await sleep(wait);

            let lastError = null;
            for (let attempt = 0; attempt < attempts; attempt++) {
                try {
                    await manager.sendMessage(payload);
                    queue.lastAt = now();
                    return true;
                } catch (error) {
                    lastError = error;
                    // Only a rate-limit rejection is worth retrying. A closed
                    // channel or a refused verification gate will not improve by
                    // being asked again, and retrying would just delay the error
                    // the caller needs to see.
                    if (!isRateLimit(error)) throw error;
                    await sleep(gapMs * (attempt + 1));
                }
            }
            throw lastError;
        });

        // The chain has to survive a failure. Leaving a rejected promise in it
        // would wedge every later frame on that session behind the first error.
        queue.chain = run.catch(() => {});
        queues.set(sessionId, queue);
        return run;
    };
}
