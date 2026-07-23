// getStats parsing + quality classification for adaptive calls.
//
// summarizeStats() takes a plain array of RTCStats objects (Array.from(report
// .values())) plus the previous counter snapshot, so it is fully unit-testable
// in Node without a live RTCPeerConnection.

/**
 * Reduce a getStats() report to the few numbers the controller / UI need.
 * @param {Array<object>} stats  RTCStats objects (video preferred over audio).
 * @param {{packetsSent?:number, packetsLost?:number}} [prev] previous counters.
 * @returns {{lossPct:number, rttMs:number, jitterMs:number,
 *            availableOutgoingBitrate:(number|null), qualityLimitationReason:string,
 *            counters:{packetsSent:number, packetsLost:number}, hasData:boolean}}
 */
export function summarizeStats(stats, prev = {}) {
    let outbound = null, remoteInbound = null, candidatePair = null;
    for (const s of stats) {
        if (!s || typeof s.type !== 'string') continue;
        if (s.type === 'outbound-rtp' && !s.isRemote) {
            if (!outbound || s.kind === 'video') outbound = s;         // prefer video
        } else if (s.type === 'remote-inbound-rtp') {
            if (!remoteInbound || s.kind === 'video') remoteInbound = s;
        } else if (s.type === 'candidate-pair') {
            const active = s.nominated || s.selected || s.state === 'succeeded';
            if (active && (!candidatePair || s.nominated)) candidatePair = s;
        }
    }

    const packetsSent = Number(outbound?.packetsSent ?? 0);
    const packetsLost = Number(remoteInbound?.packetsLost ?? 0);
    const dSent = packetsSent - (prev.packetsSent ?? packetsSent);
    const dLost = packetsLost - (prev.packetsLost ?? packetsLost);
    const denom = dSent + dLost;
    // Interval loss ratio (guard against counter resets / first sample).
    const lossPct = denom > 0 ? Math.min(1, Math.max(0, dLost / denom)) : 0;

    const rttSec = candidatePair?.currentRoundTripTime ?? remoteInbound?.roundTripTime ?? 0;
    const rttMs = Number(rttSec) * 1000;
    const jitterMs = Number(remoteInbound?.jitter ?? 0) * 1000;
    const availableOutgoingBitrate = candidatePair?.availableOutgoingBitrate != null
        ? Number(candidatePair.availableOutgoingBitrate) : null;
    const qualityLimitationReason = outbound?.qualityLimitationReason ?? 'none';

    return {
        lossPct, rttMs, jitterMs, availableOutgoingBitrate, qualityLimitationReason,
        counters: { packetsSent, packetsLost },
        hasData: !!(outbound && (remoteInbound || candidatePair)),
    };
}

/**
 * Coarse connection-quality label for the UI, from loss + RTT.
 * @returns {'excellent'|'good'|'fair'|'poor'|null} null when there's no data yet.
 */
export function qualityFromMetrics(m) {
    if (!m || !m.hasData) return null;
    const l = m.lossPct, r = m.rttMs;
    if (l < 0.03 && r < 150) return 'excellent';
    if (l < 0.07 && r < 250) return 'good';
    if (l < 0.15 && r < 400) return 'fair';
    return 'poor';
}
