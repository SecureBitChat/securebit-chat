// NetworkAdaptationController — reactive bitrate control for calls.
//
// Once a second it reads pc.getStats(), classifies the link, and nudges the VIDEO
// sender's maxBitrate / scaleResolutionDownBy via setParameters — never
// renegotiation, never touching the tracks, never touching AUDIO (audio stays at
// its configured bitrate so speech survives; see ADAPTATION_CONFIG.audioProtect).
//
// The decision logic (decideAdaptation) is pure and unit-tested separately from
// the live getStats/setParameters plumbing.

import { ADAPTATION_CONFIG, IS_WEBKIT } from '../config.js';
import { summarizeStats, qualityFromMetrics } from './metrics.js';

/**
 * Pure adaptation decision.
 * @param {object} m      metrics from summarizeStats
 * @param {object} state  { targetBitrate, ceilingBitrate, scaleResolutionDownBy, goodTicks }
 * @param {object} cfg    ADAPTATION_CONFIG
 * @returns {{targetBitrate:number, scaleResolutionDownBy:number, goodTicks:number,
 *            changed:boolean, reason:string}}
 */
export function decideAdaptation(m, state, cfg = ADAPTATION_CONFIG) {
    let { targetBitrate, ceilingBitrate, scaleResolutionDownBy, goodTicks } = state;
    let changed = false, reason = 'steady';

    if (m.qualityLimitationReason === 'cpu') {
        // CPU-bound: drop resolution, leave bitrate alone (brief §5).
        const next = Math.min(4, +(scaleResolutionDownBy * cfg.cpuScaleStep).toFixed(3));
        if (next !== scaleResolutionDownBy) { scaleResolutionDownBy = next; changed = true; }
        goodTicks = 0; reason = 'cpu';
    } else if (m.lossPct > cfg.loss.highPct || m.rttMs > cfg.rtt.highMs) {
        // Congestion: step video bitrate down (never below the floor).
        const next = Math.max(cfg.minVideoBitrate, Math.round(targetBitrate * (1 - cfg.stepDownPct)));
        if (next !== targetBitrate) { targetBitrate = next; changed = true; }
        goodTicks = 0; reason = 'backoff';
    } else if (m.lossPct < cfg.loss.recoverPct && m.rttMs < cfg.rtt.recoverMs) {
        // Sustained good link: ramp up after enough consecutive good ticks.
        goodTicks += 1; reason = 'recovering';
        if (goodTicks >= cfg.recoverStableTicks) {
            const next = Math.min(ceilingBitrate, Math.round(targetBitrate * (1 + cfg.stepUpPct)));
            if (next !== targetBitrate) { targetBitrate = next; changed = true; reason = 'rampup'; }
            goodTicks = 0;
        }
    } else {
        goodTicks = 0; // neutral zone: hold.
    }

    return { targetBitrate, scaleResolutionDownBy, goodTicks, changed, reason };
}

export class NetworkAdaptationController {
    /**
     * @param {RTCPeerConnection} pc
     * @param {object} opts { getVideoSender:()=>RTCRtpSender|null, ceilingBitrate?, onQuality?, cfg? }
     */
    constructor(pc, opts = {}) {
        this.pc = pc;
        this.getVideoSender = opts.getVideoSender || (() => null);
        this.onQuality = opts.onQuality || (() => {});
        this.cfg = opts.cfg || ADAPTATION_CONFIG;
        this._timer = null;
        this._prevCounters = {};
        this._lastQuality = undefined;
        this.state = {
            targetBitrate: opts.ceilingBitrate || 1500000,
            ceilingBitrate: opts.ceilingBitrate || 1500000,
            scaleResolutionDownBy: 1,
            goodTicks: 0,
        };
    }

    start() {
        if (this._timer) return;
        this._timer = setInterval(() => { this._tick().catch(() => {}); }, this.cfg.intervalMs);
    }

    stop() {
        if (this._timer) { clearInterval(this._timer); this._timer = null; }
    }

    async _tick() {
        if (!this.pc || typeof this.pc.getStats !== 'function') return;
        const report = await this.pc.getStats();
        const stats = typeof report.values === 'function' ? Array.from(report.values()) : report;
        const m = summarizeStats(stats, this._prevCounters);
        this._prevCounters = m.counters;

        // Quality → UI (only emit on change).
        const q = qualityFromMetrics(m);
        if (q && q !== this._lastQuality) {
            this._lastQuality = q;
            try { this.onQuality(q, m); } catch (_) {}
        }

        if (!m.hasData) return;

        const decision = decideAdaptation(m, this.state, this.cfg);
        this.state = {
            targetBitrate: decision.targetBitrate,
            ceilingBitrate: this.state.ceilingBitrate,
            scaleResolutionDownBy: decision.scaleResolutionDownBy,
            goodTicks: decision.goodTicks,
        };
        if (decision.changed) {
            await this._applyToVideoSender();
        }
    }

    async _applyToVideoSender() {
        // WebKit: never write sender params (kills the capture); quality indicator
        // still works (read-only getStats). Safari's own congestion control adapts.
        if (IS_WEBKIT) return;
        const sender = this.getVideoSender();
        if (!sender || typeof sender.getParameters !== 'function') return;
        try {
            const params = sender.getParameters();
            if (!params.encodings || params.encodings.length === 0) params.encodings = [{}];
            if (params.encodings.length === 1) {
                // Single encoding (SVC or plain): cap bitrate + scale resolution.
                params.encodings[0].maxBitrate = this.state.targetBitrate;
                params.encodings[0].scaleResolutionDownBy = this.state.scaleResolutionDownBy;
            } else {
                // Simulcast: throttle only the TOP (highest-bitrate) layer so the
                // low/mid layers keep flowing; leave their per-rid scale ladder intact.
                const top = params.encodings[params.encodings.length - 1];
                top.maxBitrate = this.state.targetBitrate;
            }
            await sender.setParameters(params);
        } catch (e) {
            // WebKit/older browsers can reject setParameters; safe to skip this tick.
        }
    }
}
