// GroupCallMedia — the media half of a group call.
//
// WHAT THIS IS
// ------------
// A group call in SecureBit is not a conference. There is no mixer, no SFU and
// no server: it is N-1 ordinary encrypted 1:1 calls, one to each other member,
// each riding the pairwise session that member already has with us — a session
// whose DTLS transport a human authenticated by comparing a safety code. Nobody
// but the two endpoints of a leg ever holds the keys that leg's audio is under,
// which is the same guarantee the 1:1 call has, kept N-1 times over rather than
// traded away for a server that would make the call cheaper.
//
// This class owns exactly three things:
//
//   1. ONE capture for the whole call. Not one per leg. Seven legs opening
//      getUserMedia on the same microphone is seven captures of one microphone,
//      seven camera indicators, and on several devices simply a failure. The
//      capture is made here and handed to each manager, which attaches its
//      tracks and is forbidden from stopping them.
//
//   2. WHO DIALS. Both ends of a pair would otherwise place a call to each
//      other at the same moment and negotiate over the top of themselves. The
//      rule is the whole of the fix: the member with the lexicographically
//      smaller fingerprint calls, the other answers. Every member computes it
//      from the same two values and gets the same answer, so exactly one call
//      is placed per pair with nothing to coordinate.
//
//   3. WHAT THE UI SEES. One snapshot covering every leg, so the call renders
//      as one call rather than as N-1 unrelated ones.
//
// WHAT IT DOES NOT OWN
// --------------------
// Who is in the call. That is GroupSession's, and it travels as signed group
// frames that reach members this class can never reach — a member with no
// direct link has no leg here, and is shown as "connecting" while the mesh
// builds one, rather than being invisible.
//
// Injected rather than imported (`getManager`, `getUserMedia`), for the same
// reason GroupSession injects its transport: the dialling rule and the leg
// bookkeeping are the parts worth testing, and they should not need a browser.

/** Per-leg lifecycle, as the UI reads it. */
export const LEG_STATE = Object.freeze({
    UNREACHABLE: 'unreachable', // no direct link yet — the mesh is still building one
    CONNECTING: 'connecting',   // a leg exists, media has not started flowing
    ACTIVE: 'active',           // audio (and video, if any) is flowing
    FAILED: 'failed',           // the leg was attempted and did not come up
});

/** Media the leg is actually carrying, for the tile that renders it. */
const PHASE_TO_STATE = {
    idle: LEG_STATE.CONNECTING,
    outgoing: LEG_STATE.CONNECTING,
    incoming: LEG_STATE.CONNECTING,
    connecting: LEG_STATE.CONNECTING,
    active: LEG_STATE.ACTIVE,
    ended: LEG_STATE.FAILED,
};

/**
 * Speech detection thresholds, on the RMS of a 0..1 normalised waveform.
 *
 * Two of them, not one, because a single threshold makes the indicator flicker
 * on every syllable boundary: normal speech crosses any fixed line several times
 * a second. Rising past ON marks someone as speaking; they stay marked until
 * they have been continuously below OFF for HOLD_MS, which is roughly the length
 * of a pause between words.
 */
export const SPEAKING = Object.freeze({ ON: 0.05, OFF: 0.025, HOLD_MS: 600, SAMPLE_MS: 120 });

/**
 * How long the answering side waits before dialling the pair itself.
 *
 * Long enough that a working dial has certainly arrived — offers travel the same
 * data channel the group already uses, so this is seconds of margin, not
 * guesswork — and short enough that a member who would otherwise be stuck on
 * "connecting" for the whole call gets a second chance while the call still
 * matters.
 */
export const FALLBACK_DIAL_MS = 8000;

/**
 * A level meter over one MediaStream, built on Web Audio.
 *
 * Web Audio rather than the WebRTC stats API on purpose: `audioLevel` on a
 * receiver is not carried by every browser this app runs in, and where it is,
 * it arrives on the stats interval rather than on demand. An AnalyserNode is
 * available everywhere, reads the actual decoded waveform, and works the same
 * way for the local microphone as for a remote leg — so "who is speaking" is one
 * mechanism rather than two that disagree.
 */
function webAudioLevelMeter(context, stream) {
    if (!context || !stream) return null;
    let source;
    try {
        source = context.createMediaStreamSource(stream);
    } catch (_) {
        return null;   // a stream with no audio track, or a context that is gone
    }
    const analyser = context.createAnalyser();
    analyser.fftSize = 512;
    analyser.smoothingTimeConstant = 0.2;
    source.connect(analyser);
    // Deliberately NOT connected to the destination: playback is the audio
    // element's job, and routing it here too would play every voice twice.
    const buffer = new Uint8Array(analyser.fftSize);

    return {
        read() {
            analyser.getByteTimeDomainData(buffer);
            let sum = 0;
            for (let i = 0; i < buffer.length; i++) {
                const v = (buffer[i] - 128) / 128;
                sum += v * v;
            }
            return Math.sqrt(sum / buffer.length);
        },
        close() {
            try { source.disconnect(); } catch (_) {}
            try { analyser.disconnect(); } catch (_) {}
        },
    };
}

export class GroupCallMedia {
    /**
     * @param {object} deps
     * @param {(sessionId: string) => object|null} deps.getManager  pairwise manager by session id
     * @param {(constraints: object) => Promise<MediaStream>} [deps.getUserMedia]
     * @param {() => void} [deps.onChange]  called whenever the snapshot changes
     * @param {(level: string, message: string, context?: object) => void} [deps.log]
     */
    constructor({
        getManager, getUserMedia = null, createAudioSink = null, createLevelMeter = null,
        onChange = () => {}, log = () => {},
    }) {
        this._getManager = getManager;
        this._getUserMedia = getUserMedia
            || ((constraints) => navigator.mediaDevices.getUserMedia(constraints));
        /**
         * Where a member's voice actually plays.
         *
         * NOT in the call's React tree, deliberately. The tiles unmount whenever
         * the user switches to another chat, and audio elements that live in
         * them take the call's sound with them — a call that goes silent because
         * somebody looked at a different window is not a call. The controller
         * owns one detached audio element per leg for the life of that leg, and
         * the tiles render video only.
         */
        this._createAudioSink = createAudioSink
            || (() => (typeof Audio === 'function' ? new Audio() : null));
        /**
         * How loud a stream is right now, for the speaking indicator.
         *
         * Injected so the whole hysteresis rule below can be tested without a
         * browser, and so a platform with no Web Audio simply has no indicator
         * rather than no call.
         */
        this._createLevelMeter = createLevelMeter
            || ((stream) => webAudioLevelMeter(this._audioContext(), stream));
        this._onChange = onChange;
        this._log = log;

        this.callId = null;
        this.selfFp = '';
        this.withVideo = false;
        this.micEnabled = true;
        this.cameraEnabled = false;
        this.facingMode = 'user';
        this.error = null;

        this.localStream = null;
        /** fp -> { fp, name, sessionId, manager, unsubscribe, sink, state, quality, hasVideo } */
        this._legs = new Map();
        /** The participant list as GroupSession last reported it. */
        this._peers = [];
        /** Guards flipCamera / setCamera against overlapping captures. */
        this._busy = false;

        /** Shared AudioContext for every level meter in this call. */
        this._ctx = null;
        /** Our own microphone's meter, and whether it is currently carrying speech. */
        this._selfMeter = null;
        this.selfSpeaking = false;
        this._selfQuietSince = 0;
        /** The polling timer that reads every meter. */
        this._levelTimer = null;
    }

    /**
     * One AudioContext for the whole call, created on first use.
     *
     * A context per leg would be several audio graphs and several hardware
     * callbacks for one conversation, and browsers cap how many a page may hold.
     * It is resumed rather than assumed: a context created outside a gesture
     * starts suspended, and a suspended context reads silence forever — which
     * would look exactly like nobody ever speaking.
     */
    _audioContext() {
        if (this._ctx) return this._ctx;
        const Ctor = typeof AudioContext !== 'undefined' ? AudioContext
            : (typeof webkitAudioContext !== 'undefined' ? webkitAudioContext : null);
        if (!Ctor) return null;
        try {
            this._ctx = new Ctor();
            if (this._ctx.state === 'suspended') this._ctx.resume().catch(() => {});
        } catch (_) {
            this._ctx = null;
        }
        return this._ctx;
    }

    get active() {
        return this.callId !== null;
    }

    // -----------------------------------------------------------------------
    // joining and leaving
    // -----------------------------------------------------------------------

    /**
     * Capture, then start building legs.
     *
     * The capture comes FIRST and its failure aborts the join, because a call
     * this device cannot speak into is not a call — and the failure has to be
     * reported as a device problem (permission, no microphone, another app
     * holding it) rather than left to look like the group failed to connect.
     *
     * CALL IT WITH NO PEERS to capture without connecting anything, then call
     * setPeers once the group has been told you are in the call. That ordering
     * is not cosmetic — see setPeers.
     *
     * @param {{callId: string, selfFp: string, withVideo?: boolean, peers?: object[]}} opts
     */
    async join({ callId, selfFp, withVideo = false, peers = [] }) {
        if (this.callId === callId) { this.setPeers(peers); return; }
        if (this.callId) await this.leave();

        this.callId = callId;
        this.selfFp = selfFp;
        this.withVideo = withVideo === true;
        this.micEnabled = true;
        this.cameraEnabled = this.withVideo;
        this.error = null;
        this._changed();

        try {
            this.localStream = await this._getUserMedia({
                audio: { echoCancellation: true, noiseSuppression: true, autoGainControl: true },
                video: this.withVideo
                    ? { facingMode: this.facingMode, width: { ideal: 1280 }, height: { ideal: 720 } }
                    : false,
            });
        } catch (error) {
            this.callId = null;
            this.error = mediaErrorCode(error);
            this._changed();
            throw error;
        }

        this._selfMeter = this._createLevelMeter(this.localStream);
        this._startLevelPolling();
        this.setPeers(peers);
    }

    /**
     * The participant list changed: reconcile the legs against it.
     *
     * Called whenever anything moves — somebody joins, somebody leaves, a member
     * who was relayed gets a direct link. Idempotent, so the caller can run it
     * on every group event without tracking what actually differs.
     *
     * ORDERING: the group must be told we are in the call BEFORE this runs.
     * Attaching a leg can place an offer immediately, and an offer that arrives
     * at a member who has not yet heard we joined lands on a session they do not
     * yet know is a call leg — so they ring instead of answering, and the dialler
     * sits at "connecting" for the rest of the call. Announcing first works
     * because both the join frame and the offer travel the same ordered data
     * channel, so the join cannot overtake it.
     *
     * @param {{fp: string, name: string, sessionId: string|null, self?: boolean}[]} peers
     */
    setPeers(peers) {
        this._peers = Array.isArray(peers) ? peers : [];
        if (!this.active) return;

        const wanted = new Map();
        for (const peer of this._peers) {
            if (!peer || !peer.fp || peer.fp === this.selfFp) continue;
            wanted.set(peer.fp, peer);
        }

        // Legs whose member left the call, or whose link moved to a different
        // session, are torn down first — a leg on a dead session id would keep a
        // sender attached to a peer connection nobody is on the other end of.
        for (const [fp, leg] of [...this._legs]) {
            const peer = wanted.get(fp);
            if (!peer || peer.sessionId !== leg.sessionId) this._detach(fp);
        }

        for (const [fp, peer] of wanted) {
            const existing = this._legs.get(fp);
            if (existing) {
                // A leg that failed is retried on the next reconciliation rather
                // than being written off for the rest of the call. The usual
                // cause is transient — the pairwise session was mid-repair when
                // the offer was placed — and without this the member stayed
                // silent for as long as the call lasted even after their link
                // came back.
                if (existing.state === LEG_STATE.FAILED && this._weDial(fp)) this._dial(existing);
                continue;
            }
            if (!peer.sessionId) continue;   // relayed only: no leg to build yet
            this._attach(fp, peer);
        }

        this._changed();
    }

    /** Tear down every leg and release the capture. */
    async leave() {
        this._stopLevelPolling();
        if (this._selfMeter) { try { this._selfMeter.close?.(); } catch (_) {} this._selfMeter = null; }
        this.selfSpeaking = false;
        for (const fp of [...this._legs.keys()]) this._detach(fp);
        if (this._ctx) { try { this._ctx.close?.(); } catch (_) {} this._ctx = null; }
        if (this.localStream) {
            for (const track of this.localStream.getTracks()) {
                try { track.stop(); } catch (_) { /* already ended */ }
            }
        }
        this.localStream = null;
        this.callId = null;
        this.selfFp = '';
        this.withVideo = false;
        this.cameraEnabled = false;
        this.micEnabled = true;
        this._peers = [];
        this._changed();
    }

    // -----------------------------------------------------------------------
    // legs
    // -----------------------------------------------------------------------

    /**
     * Who places the call for this pair.
     *
     * Both members run this and get opposite answers, so exactly one offer is
     * made. Comparing fingerprints rather than, say, join order means the answer
     * does not depend on anything the two members might disagree about.
     */
    _weDial(peerFp) {
        return this.selfFp < peerFp;
    }

    _attach(fp, peer) {
        const manager = this._getManager(peer.sessionId);
        if (!manager) return;

        const leg = {
            fp,
            name: peer.name || 'Member',
            sessionId: peer.sessionId,
            manager,
            unsubscribe: null,
            sink: this._createAudioSink(),
            meter: null,
            fallback: null,
            speaking: false,
            quietSince: 0,
            state: LEG_STATE.CONNECTING,
            quality: null,
            hasVideo: false,
        };
        if (leg.sink) { leg.sink.autoplay = true; leg.sink.muted = false; }
        this._legs.set(fp, leg);

        // Order matters: the context has to be set before the offer can arrive,
        // or the answering side rings the user for a call they already joined.
        try { manager.setCallGroupContext(this.callId); } catch (_) {}
        try { manager.setExternalMediaStream(this.localStream); } catch (_) {}

        if (typeof manager.addCallStateListener === 'function') {
            leg.unsubscribe = manager.addCallStateListener((state) => this._onLegState(fp, state));
        }

        // Start from what the session is ACTUALLY doing. A leg attached to a
        // manager that is already mid-call — a member rebound to a link that was
        // carrying us a moment ago — would otherwise sit at "connecting" until
        // the next state change happened to come along, which for a call that is
        // already up may be never.
        this._onLegState(fp, manager.getCallState?.() || {});

        if (this._weDial(fp)) {
            this._dial(leg);
            return;
        }
        // We are the answering side, so there is nothing to do but wait — unless
        // the offer never comes. That is not hypothetical: the peer's dial can
        // fail on their side and their retry only runs when a group event happens
        // to fire. After a grace period long enough that a working dial would
        // have arrived, take the call ourselves. Only ONE side of a pair ever
        // does this — the side that was not going to dial — so it cannot produce
        // two offers crossing, and it is skipped outright if anything has reached
        // this session in the meantime.
        leg.fallback = setTimeout(() => this._dialFallback(fp), FALLBACK_DIAL_MS);
    }

    _dialFallback(fp) {
        const leg = this._legs.get(fp);
        if (!leg || !this.active) return;
        leg.fallback = null;
        const phase = leg.manager.getCallState?.().phase || 'idle';
        if (phase !== 'idle') return;   // something arrived; leave it alone
        this._log('info', 'group call leg was never dialled by the peer; dialling it', {});
        Promise.resolve()
            .then(() => leg.manager.startCall(this.withVideo))
            .catch(() => {
                const live = this._legs.get(fp);
                if (live === leg) { live.state = LEG_STATE.FAILED; this._changed(); }
            });
    }

    /** Place this leg's call. */
    _dial(leg) {
        const phase = leg.manager.getCallState?.().phase || 'idle';
        if (phase !== 'idle') return;
        leg.state = LEG_STATE.CONNECTING;
        Promise.resolve()
            .then(() => leg.manager.startCall(this.withVideo))
            .catch((error) => {
                this._log('warn', 'group call leg could not be placed', {
                    errorType: error?.constructor?.name,
                });
                const live = this._legs.get(leg.fp);
                if (live === leg) { live.state = LEG_STATE.FAILED; this._changed(); }
            });
    }

    _detach(fp) {
        const leg = this._legs.get(fp);
        if (!leg) return;
        this._legs.delete(fp);
        if (leg.fallback) { clearTimeout(leg.fallback); leg.fallback = null; }
        try { leg.unsubscribe?.(); } catch (_) {}
        if (leg.sink) {
            try { leg.sink.pause?.(); } catch (_) {}
            try { leg.sink.srcObject = null; } catch (_) {}
        }
        if (leg.meter) { try { leg.meter.close?.(); } catch (_) {} leg.meter = null; }
        // End first, then release the borrowed capture and the context: ending
        // the other way round would have the manager tear down a call it no
        // longer believes belongs to a group.
        try { leg.manager.endCall?.(); } catch (_) {}
        try { leg.manager.setExternalMediaStream?.(null); } catch (_) {}
        try { leg.manager.setCallGroupContext?.(null); } catch (_) {}
    }

    _onLegState(fp, state) {
        const leg = this._legs.get(fp);
        if (!leg) return;
        const phase = state?.phase || 'idle';
        if (leg.fallback && phase !== 'idle') { clearTimeout(leg.fallback); leg.fallback = null; }
        leg.state = PHASE_TO_STATE[phase] || LEG_STATE.CONNECTING;
        leg.quality = state?.quality || null;
        leg.hasVideo = state?.remoteHasVideo === true;
        this._pumpAudio(leg);
        this._changed();
    }

    /**
     * Keep this leg's audio element pointed at its current inbound stream.
     *
     * The manager rebuilds that stream whenever its receivers change — a track
     * arriving late, a camera being switched on — and hands back a NEW
     * MediaStream each time so a consumer can tell. Reassigning here on every
     * state change is what keeps a leg audible across those rebuilds; assigning
     * once at attach time left the first seconds of some calls silent.
     */
    _pumpAudio(leg) {
        if (!leg.sink) return;
        let stream = null;
        try { stream = leg.manager.getRemoteMediaStream?.() || null; } catch (_) { return; }
        if (!stream || leg.sink.srcObject === stream) return;
        try {
            leg.sink.srcObject = stream;
            const played = leg.sink.play?.();
            if (played && played.catch) played.catch(() => {});
        } catch (_) { /* an element that will not play is not worth throwing over */ }
        // The meter follows the stream, not the leg: the manager hands back a new
        // MediaStream whenever its receivers change, and a meter left on the old
        // one reads silence from then on.
        if (leg.meter) { try { leg.meter.close?.(); } catch (_) {} }
        leg.meter = this._createLevelMeter(stream);
        leg.speaking = false;
    }

    // -----------------------------------------------------------------------
    // who is speaking
    // -----------------------------------------------------------------------

    _startLevelPolling() {
        if (this._levelTimer || typeof setInterval !== 'function') return;
        this._levelTimer = setInterval(() => this._sampleLevels(), SPEAKING.SAMPLE_MS);
    }

    _stopLevelPolling() {
        if (this._levelTimer) { clearInterval(this._levelTimer); this._levelTimer = null; }
    }

    /**
     * Turn a level into a speaking flag, with hysteresis and a hold.
     *
     * `holder` is whatever object carries the flag — a leg, or this instance for
     * our own microphone — so the same rule runs for everyone and the local tile
     * cannot disagree with a remote one about what counts as talking.
     */
    _applyLevel(holder, key, quietKey, level, now) {
        const speaking = holder[key] === true;
        if (level >= SPEAKING.ON) {
            holder[quietKey] = 0;
            if (!speaking) { holder[key] = true; return true; }
            return false;
        }
        if (!speaking) return false;
        if (level > SPEAKING.OFF) { holder[quietKey] = 0; return false; }
        if (!holder[quietKey]) { holder[quietKey] = now; return false; }
        if (now - holder[quietKey] >= SPEAKING.HOLD_MS) { holder[key] = false; return true; }
        return false;
    }

    _sampleLevels() {
        if (!this.active) return;
        const now = Date.now();
        let changed = false;

        // A muted microphone is not speech, whatever the waveform says — the
        // track is disabled, so nothing is going out, and showing ourselves as
        // talking would be telling the user the opposite of what is happening.
        const selfLevel = (this.micEnabled && this._selfMeter) ? safeRead(this._selfMeter) : 0;
        if (this._applyLevel(this, 'selfSpeaking', '_selfQuietSince', selfLevel, now)) changed = true;

        for (const leg of this._legs.values()) {
            const level = leg.meter ? safeRead(leg.meter) : 0;
            if (this._applyLevel(leg, 'speaking', 'quietSince', level, now)) changed = true;
        }

        // Only when a flag actually flipped. Pushing a snapshot every 120ms would
        // re-render the whole call ten times a second for no visible reason.
        if (changed) this._changed();
    }

    // -----------------------------------------------------------------------
    // controls — applied to every leg at once, because it is one call
    // -----------------------------------------------------------------------

    setMic(enabled) {
        this.micEnabled = enabled !== false;
        if (this.localStream) {
            for (const track of this.localStream.getAudioTracks()) track.enabled = this.micEnabled;
        }
        // Muting clears the speaking mark at once rather than letting it decay
        // through the hold: the hold exists to ride out pauses in speech, and
        // pressing mute is not a pause. Half a second of still looking like you
        // are talking is exactly the half second that matters.
        if (!this.micEnabled) { this.selfSpeaking = false; this._selfQuietSince = 0; }
        // The per-leg managers read enabled-ness off the shared tracks, so this
        // is the whole of it — but their own call state still carries a mic flag
        // that a 1:1 UI would render, so keep it honest.
        for (const leg of this._legs.values()) {
            try { leg.manager.setMicEnabled?.(this.micEnabled); } catch (_) {}
        }
        this._changed();
    }

    toggleMic() { this.setMic(!this.micEnabled); }

    /**
     * Turn the camera on or off for the whole call.
     *
     * Turning it on when the call started as voice captures a camera track and
     * adds it to every leg, each of which renegotiates its own connection. That
     * is N-1 renegotiations for one button, which is the honest cost of having
     * no server in the middle.
     */
    async setCamera(enabled) {
        if (!this.active || this._busy) return;
        if (enabled === false) {
            this.cameraEnabled = false;
            if (this.localStream) {
                for (const track of this.localStream.getVideoTracks()) track.enabled = false;
            }
            for (const leg of this._legs.values()) {
                try { leg.manager.setCameraEnabled?.(false); } catch (_) {}
            }
            this._changed();
            return;
        }

        const existing = this.localStream?.getVideoTracks?.() || [];
        if (existing.length) {
            for (const track of existing) track.enabled = true;
            this.cameraEnabled = true;
            this.withVideo = true;
            this._changed();
            return;
        }

        this._busy = true;
        try {
            const camera = await this._getUserMedia({
                video: { facingMode: this.facingMode, width: { ideal: 1280 }, height: { ideal: 720 } },
            });
            const track = camera.getVideoTracks()[0];
            if (!track) return;
            this.localStream.addTrack(track);
            this.cameraEnabled = true;
            this.withVideo = true;
            await Promise.allSettled([...this._legs.values()].map(
                (leg) => Promise.resolve().then(() => leg.manager.addVideoTrack?.(track)),
            ));
        } catch (error) {
            this.error = mediaErrorCode(error);
            this.cameraEnabled = false;
        } finally {
            this._busy = false;
            this._changed();
        }
    }

    async toggleCamera() { await this.setCamera(!this.cameraEnabled); }

    /** Front/back camera. One capture, swapped into every leg without renegotiating. */
    async flipCamera() {
        if (!this.active || this._busy || !this.localStream) return;
        const old = this.localStream.getVideoTracks()[0];
        if (!old) return;

        this._busy = true;
        const previous = this.facingMode;
        this.facingMode = this.facingMode === 'user' ? 'environment' : 'user';
        try {
            const camera = await this._getUserMedia({ video: { facingMode: this.facingMode } });
            const track = camera.getVideoTracks()[0];
            if (!track) { this.facingMode = previous; return; }
            track.enabled = this.cameraEnabled;
            this.localStream.removeTrack(old);
            try { old.stop(); } catch (_) {}
            this.localStream.addTrack(track);
            await Promise.allSettled([...this._legs.values()].map(
                (leg) => Promise.resolve().then(() => leg.manager.replaceVideoTrack?.(track)),
            ));
        } catch (error) {
            this.facingMode = previous;
            this._log('warn', 'group call camera flip failed', { errorType: error?.constructor?.name });
        } finally {
            this._busy = false;
            this._changed();
        }
    }

    // -----------------------------------------------------------------------
    // what the UI reads
    // -----------------------------------------------------------------------

    getLocalStream() {
        return this.localStream;
    }

    /** The inbound stream for one member, or null while their leg is coming up. */
    getRemoteStream(fp) {
        const leg = this._legs.get(fp);
        if (!leg) return null;
        try { return leg.manager.getRemoteMediaStream?.() || null; } catch (_) { return null; }
    }

    /**
     * One call, as one object.
     *
     * Every participant appears, including the ones with no leg: a member who is
     * in the call but reachable only through a relay is CONNECTING, not absent.
     * Hiding them would make a mesh that is still building look like a member
     * who declined.
     */
    snapshot() {
        const peers = this._peers
            .filter((peer) => peer && peer.fp !== this.selfFp)
            .map((peer) => {
                const leg = this._legs.get(peer.fp);
                return {
                    fp: peer.fp,
                    name: peer.name || 'Member',
                    state: leg ? leg.state : LEG_STATE.UNREACHABLE,
                    quality: leg ? leg.quality : null,
                    hasVideo: leg ? leg.hasVideo : false,
                    speaking: leg ? leg.speaking === true : false,
                };
            })
            .sort((a, b) => (a.fp < b.fp ? -1 : a.fp > b.fp ? 1 : 0));

        return {
            active: this.active,
            callId: this.callId,
            withVideo: this.withVideo,
            micEnabled: this.micEnabled,
            cameraEnabled: this.cameraEnabled,
            facingMode: this.facingMode,
            error: this.error,
            selfSpeaking: this.selfSpeaking,
            peers,
            connected: peers.filter((p) => p.state === LEG_STATE.ACTIVE).length,
        };
    }

    _changed() {
        try { this._onChange(this.snapshot()); } catch (_) {}
    }
}

/**
 * A getUserMedia failure, as a code the UI can turn into a sentence.
 *
 * Kept identical to the 1:1 call's vocabulary: these are device and permission
 * problems, and telling them apart from a connection problem is the difference
 * between "allow the microphone" and a user staring at a call that looks broken.
 */
/** A meter that throws is a meter that is gone; it must not take the call with it. */
function safeRead(meter) {
    try { return meter.read(); } catch (_) { return 0; }
}

export function mediaErrorCode(error) {
    const name = error?.name || '';
    if (name === 'NotAllowedError' || name === 'SecurityError') return 'permission_denied';
    if (name === 'NotFoundError' || name === 'OverconstrainedError') return 'device_not_found';
    if (name === 'NotReadableError' || name === 'AbortError') return 'device_busy';
    return 'media_failed';
}
