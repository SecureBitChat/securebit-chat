// Motion primitives — Apple's "Designing Fluid Interfaces" physics, on the web.
//
// The whole point of this file is that a gesture-driven interface cannot be built
// out of CSS transitions. A transition runs from a value it captured when it
// started, for a duration fixed in advance; grab the element halfway through and
// it either ignores you or snaps. A spring has no duration — it always integrates
// from wherever the thing currently *is*, at whatever speed it is currently
// moving — so it can be interrupted, re-targeted and reversed mid-flight without
// a visible seam. Everything here exists to serve that one property.
//
// Nothing in here is a dependency. The app ships offline as a PWA and has no
// bundled animation library; these are ~150 lines of physics instead of ~30KB.

// Apple exposes two designer-facing parameters instead of mass/stiffness/damping:
//
//   damping (ratio)  1.0 = critically damped, settles without overshoot.
//                    < 1.0 overshoots; lower is bouncier.
//   response (s)     how quickly the value reaches the target. NOT a duration —
//                    a spring's settle time emerges from the parameters.
//
// These are the values Apple ships, and the ones to reach for by default.
export const SPRING = {
    // Move / reposition something. No overshoot: a panel that bounces when it
    // was not thrown reads as decoration.
    move:   { damping: 1.0, response: 0.4 },
    // A sheet or drawer the user dragged. The bounce is earned — the gesture
    // carried momentum into it.
    drawer: { damping: 0.8, response: 0.3 },
    // Rotation.
    rotate: { damping: 0.8, response: 0.4 }
};

// Integration step. Fixed and small, so the same gesture produces the same
// motion on a 60Hz phone and a 120Hz iPad — frame-rate must not be a physics
// parameter.
const DT = 1 / 480;
const MAX_FRAME = 0.064; // clamp after a stall, or the spring explodes

/**
 * True when the user has asked the system for less motion.
 *
 * Read live rather than cached: the setting can be flipped while the app is
 * open, and a long-lived PWA session would otherwise keep animating.
 */
export function prefersReducedMotion() {
    try {
        return typeof matchMedia === 'function' &&
            matchMedia('(prefers-reduced-motion: reduce)').matches;
    } catch (_) {
        return false;
    }
}

/**
 * Where a flick would come to rest, if you let it decelerate.
 *
 * This is the exponential-decay projection from Apple's sample code, not the
 * textbook v²/2a. Use it to pick which snap point a gesture was aiming at:
 * snapping to whatever is nearest the *release* point throws away the user's
 * velocity and makes a fast flick feel identical to a slow drag.
 *
 * @param {number} velocity px/s at release
 * @param {number} decelerationRate 0.998 ≈ normal scroll feel, 0.99 snappier
 * @returns {number} signed distance the gesture would still travel
 */
export function project(velocity, decelerationRate = 0.998) {
    return (velocity / 1000) * decelerationRate / (1 - decelerationRate);
}

/**
 * Which snap point a release was aiming at.
 *
 * Two rules, in this order:
 *
 *   A deliberate flick is decided by its *direction*. Someone who threw a panel
 *   leftwards meant "away", even if they let go while it was still nearer the
 *   open position than the closed one — position at the moment of release says
 *   nothing about intent when the hand is still moving fast.
 *
 *   A slow drag has no direction worth trusting, so it is decided by where its
 *   remaining momentum would have carried it. That is still not the same as
 *   "nearest the release point": a gentle push that was clearly going somewhere
 *   should be allowed to arrive.
 *
 * @param {number} position current value at release
 * @param {number} velocity px/s at release
 * @param {number[]} points the values it is allowed to rest at
 * @param {object} [o]
 * @param {number} [o.flick] px/s above which direction wins over projection
 * @param {number} [o.decelerationRate] passed through to project()
 */
export function snapTarget(position, velocity, points, o = {}) {
    const { flick = 220, decelerationRate = 0.998 } = o;
    if (!points || !points.length) return position;
    const projected = position + project(velocity, decelerationRate);
    let pool = points;
    if (Math.abs(velocity) > flick) {
        const ahead = points.filter((p) => (velocity > 0 ? p >= position : p <= position));
        if (ahead.length) pool = ahead;
    }
    return pool.reduce(
        (best, p) => (Math.abs(p - projected) < Math.abs(best - projected) ? p : best),
        pool[0]
    );
}

/**
 * Progressive resistance past a boundary.
 *
 * A hard stop reads as "the app froze". Continuous resistance reads as
 * "responsive, but there is nothing more this way" — the finger keeps moving
 * and the element keeps answering, just less and less.
 *
 * @param {number} overshoot how far past the bound the pointer is (px, signed)
 * @param {number} dimension the size the resistance is scaled against (px)
 * @param {number} constant lower = stiffer
 */
export function rubberband(overshoot, dimension, constant = 0.55) {
    if (!dimension) return 0;
    return (overshoot * dimension * constant) / (dimension + constant * Math.abs(overshoot));
}

/**
 * Tracks a short position history so a release can be handed a real velocity.
 *
 * The instantaneous delta between the last two pointer events is far too noisy
 * to animate from — one stalled frame and a fast flick reports as a dead stop.
 * Averaging over a small trailing window is what makes the handoff invisible.
 */
export function velocityTracker(windowMs = 100) {
    const samples = [];
    return {
        add(value, time = performance.now()) {
            samples.push({ value, time });
            while (samples.length > 2 && time - samples[0].time > windowMs) samples.shift();
        },
        /** @returns {number} px/s over the trailing window */
        get(now = performance.now()) {
            if (samples.length < 2) return 0;
            const last = samples[samples.length - 1];
            // A pointer that has been still for a while has stopped, whatever
            // the older samples say.
            if (now - last.time > windowMs) return 0;
            const first = samples[0];
            const dt = (last.time - first.time) / 1000;
            if (dt <= 0) return 0;
            return (last.value - first.value) / dt;
        },
        reset() { samples.length = 0; }
    };
}

/**
 * A spring animation that can be interrupted, re-targeted and reversed.
 *
 * The handle deliberately exposes live `value` and `velocity`: that is what a
 * gesture needs when it grabs a moving element — it must continue from the
 * *presentation* value, never from the logical target, or the element jumps.
 *
 * @param {object} o
 * @param {number} o.from starting value
 * @param {number} o.to target value
 * @param {number} [o.velocity] initial velocity, px/s — hand the release velocity here
 * @param {number} [o.damping] 1 = no overshoot, < 1 bounces
 * @param {number} [o.response] seconds to reach the target
 * @param {number} [o.restDelta] how close counts as arrived
 * @param {number} [o.restSpeed] how slow counts as stopped, px/s
 * @param {boolean} [o.respectReducedMotion] jump to the target instead of animating
 * @param {(v:number)=>void} [o.onUpdate]
 * @param {()=>void} [o.onComplete]
 */
export function spring(o) {
    const {
        from, to, velocity = 0,
        damping = SPRING.move.damping,
        response = SPRING.move.response,
        restDelta = 0.1, restSpeed = 0.5,
        respectReducedMotion = true,
        onUpdate, onComplete
    } = o;

    let value = from;
    let vel = velocity;
    let target = to;
    let raf = 0;
    let last = 0;
    let done = false;

    const omega = (2 * Math.PI) / response;
    const zeta = damping;

    const finish = () => {
        done = true;
        raf = 0;
        value = target;
        vel = 0;
        if (onUpdate) onUpdate(value);
        if (onComplete) onComplete();
    };

    // Reduced motion means no vestibular travel — but it does not mean no
    // feedback. The caller still gets its final value; it is up to the caller
    // to cross-fade instead of slide.
    if (respectReducedMotion && prefersReducedMotion()) {
        finish();
        return {
            get value() { return value; },
            get velocity() { return 0; },
            get done() { return true; },
            retarget(next) { target = next; finish(); },
            stop() {}
        };
    }

    const step = (now) => {
        raf = 0;
        const frame = Math.min((now - last) / 1000, MAX_FRAME);
        last = now;

        // Semi-implicit Euler at a fixed sub-step. Explicit Euler at frame size
        // is unstable for a stiff spring; this stays well inside the stability
        // bound for every response value we use.
        let t = frame;
        while (t > 0) {
            const dt = Math.min(DT, t);
            const accel = -omega * omega * (value - target) - 2 * zeta * omega * vel;
            vel += accel * dt;
            value += vel * dt;
            t -= dt;
        }

        if (Math.abs(value - target) < restDelta && Math.abs(vel) < restSpeed) {
            finish();
            return;
        }
        if (onUpdate) onUpdate(value);
        raf = requestAnimationFrame(step);
    };

    last = performance.now();
    raf = requestAnimationFrame(step);

    return {
        get value() { return value; },
        get velocity() { return vel; },
        get done() { return done; },
        /**
         * Point the spring somewhere else without touching its current velocity.
         *
         * This is the anti-"brick wall" move. Killing this animation and starting
         * a new one at velocity 0 puts a discontinuity exactly where the user
         * reversed direction, which is the moment they are most attentive.
         */
        retarget(next) { target = next; },
        stop() {
            if (raf) cancelAnimationFrame(raf);
            raf = 0;
            done = true;
        }
    };
}
