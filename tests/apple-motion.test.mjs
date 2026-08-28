// The motion primitives, and the places the app is wired to them.
//
// These are unit tests for physics, which is unusual for this repo, but the
// numbers here are the ones a gesture is judged by. A projection that is off by
// a factor of two turns a flick into a shove; a spring that overshoots when it
// was told not to puts a wobble on a panel nobody threw. Both are invisible in
// a screenshot and obvious in the hand, so they get asserted instead of eyeballed.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// A controllable clock, installed before the module under test is imported so
// its rAF loop runs on virtual time. Real timers would make this test slow and
// flaky for no benefit — the integrator only cares about the deltas it is fed.
// ---------------------------------------------------------------------------
let now = 0;
let nextId = 1;
const frames = new Map();

globalThis.performance = { now: () => now };
globalThis.requestAnimationFrame = (cb) => { const id = nextId++; frames.set(id, cb); return id; };
globalThis.cancelAnimationFrame = (id) => { frames.delete(id); };

let reduceMotion = false;
globalThis.matchMedia = (q) => ({
    matches: q.includes('prefers-reduced-motion') ? reduceMotion : false
});

/** Advance the virtual clock one frame and run whatever was scheduled. */
function tick(ms = 16) {
    now += ms;
    const due = [...frames.entries()];
    frames.clear();
    for (const [, cb] of due) cb(now);
}
/** Run frames until the spring reports done, or give up. */
function run(handle, maxFrames = 600) {
    let n = 0;
    while (!handle.done && n++ < maxFrames) tick();
    return n;
}

const { spring, project, snapTarget, rubberband, velocityTracker, prefersReducedMotion, SPRING } =
    await import('../src/ui/motion.js');

// ---------------------------------------------------------------------------
// project() — momentum, not proximity
// ---------------------------------------------------------------------------
{
    // Apple's exponential-decay form, not the textbook v²/2a. At the default
    // deceleration rate a metre-per-second flick carries about half a screen.
    assert.ok(Math.abs(project(1000) - 499) < 1,
        'project(1000px/s) must be ~499px — this is the constant every snap ' +
        'decision is measured against');

    assert.equal(project(0), 0, 'a release with no velocity travels nowhere');
    assert.ok(project(-800) < 0, 'projection keeps the sign of the gesture');
    assert.ok(project(2000) > project(1000),
        'a faster flick must project further, or velocity is being discarded');

    // A snappier deceleration rate must land shorter, not longer.
    assert.ok(project(1000, 0.99) < project(1000, 0.998));
}

// ---------------------------------------------------------------------------
// snapTarget() — where the gesture was going, not where it stopped
//
// These are the drawer's actual numbers: a 292px panel, closed at -292, open
// at 0. Getting this wrong is the difference between a drawer you can flick
// shut and one that argues with you.
// ---------------------------------------------------------------------------
{
    const W = 292;
    const ends = [-W, 0];

    // Released at a standstill, barely open: it falls back closed.
    assert.equal(snapTarget(-250, 0, ends), -W);
    // Released at a standstill, mostly open: it completes.
    assert.equal(snapTarget(-40, 0, ends), 0);

    // The case position alone gets wrong. Dragged nearly all the way open, then
    // flicked back hard — intent is unmistakably "away", even though the panel
    // is sitting closer to open than to closed at the instant of release.
    assert.equal(snapTarget(-30, -1600, ends), -W,
        'a hard flick must be decided by its direction, not by where it let go');

    // And the mirror: barely peeked open, but thrown forward.
    assert.equal(snapTarget(-260, 1600, ends), 0,
        'a flick towards open must be allowed to arrive');

    // Below the flick threshold, momentum still counts — a gentle push that was
    // clearly going somewhere should not be snapped back to the nearest edge.
    assert.equal(snapTarget(-160, 180, ends), 0,
        'a slow push past the midpoint should complete on its projection');

    // Degenerate inputs must not throw; a gesture with nowhere to go stays put.
    assert.equal(snapTarget(-100, 500, []), -100);
    assert.equal(snapTarget(-100, 500, [-100]), -100);
}

// ---------------------------------------------------------------------------
// rubberband() — resistance, not a wall
// ---------------------------------------------------------------------------
{
    assert.equal(rubberband(0, 300), 0, 'at the boundary there is no resistance yet');

    // The defining property: the element keeps following, but always less than
    // the finger. Equal movement would mean no boundary; zero would mean a wall.
    for (const overshoot of [10, 50, 120, 400, 2000]) {
        const out = rubberband(overshoot, 300);
        assert.ok(out > 0 && out < overshoot,
            `overshoot ${overshoot} must still move the element, but less than the finger`);
    }

    // Resistance increases: each extra pixel of finger buys less travel.
    const gain = (o) => rubberband(o + 1, 300) - rubberband(o, 300);
    assert.ok(gain(200) < gain(10), 'resistance must grow the further past the edge you drag');

    assert.ok(rubberband(-100, 300) < 0, 'resistance is symmetric');
    assert.equal(rubberband(100, 0), 0, 'a zero-sized dimension cannot resist anything');
}

// ---------------------------------------------------------------------------
// velocityTracker() — the number handed to the spring on release
// ---------------------------------------------------------------------------
{
    const v = velocityTracker();
    assert.equal(v.get(0), 0, 'a single sample is not a velocity');

    // 100px over 100ms = 1000px/s, averaged over the window rather than taken
    // from the last pair of events, which is far too noisy to animate from.
    v.add(0, 0); v.add(50, 50); v.add(100, 100);
    assert.ok(Math.abs(v.get(100) - 1000) < 1, 'steady drag must report its true speed');

    // A finger that has come to rest has stopped, whatever the older samples say.
    // Without this, lifting after a pause throws the element across the screen.
    assert.equal(v.get(1000), 0, 'a stale history must not resurrect an old velocity');

    v.reset();
    assert.equal(v.get(0), 0);
}

// ---------------------------------------------------------------------------
// spring() — arrives, and only bounces when told to
// ---------------------------------------------------------------------------
{
    // Critically damped: the default for anything the user did not throw.
    let peak = -Infinity;
    const s = spring({
        from: 0, to: 100,
        damping: SPRING.move.damping, response: SPRING.move.response,
        onUpdate: (v) => { peak = Math.max(peak, v); }
    });
    run(s);
    assert.ok(s.done, 'the spring must come to rest, not run forever');
    assert.equal(s.value, 100, 'and it must rest exactly on the target');
    assert.ok(peak <= 100.01, `damping 1.0 must not overshoot (peaked at ${peak.toFixed(2)})`);
}
{
    // Under-damped: overshoot is the whole point, and it is what a flick earns.
    let peak = -Infinity;
    const s = spring({
        from: 0, to: 100,
        damping: SPRING.drawer.damping, response: SPRING.drawer.response,
        velocity: 900,
        onUpdate: (v) => { peak = Math.max(peak, v); }
    });
    run(s);
    assert.ok(peak > 100, 'damping 0.8 with velocity behind it must overshoot');
    assert.equal(s.value, 100, 'and still settle on the target');
}
{
    // Velocity handoff: the spring must leave the gesture at the speed the
    // gesture arrived. Starting from rest is the visible seam between dragging
    // and animating that separates "fluid" from merely "fine".
    const slow = spring({ from: 0, to: 100, velocity: 0, onUpdate() {} });
    const fast = spring({ from: 0, to: 100, velocity: 2000, onUpdate() {} });
    tick(); tick();
    assert.ok(fast.value > slow.value,
        'a spring handed a release velocity must already be ahead after two frames');
    slow.stop(); fast.stop();
}
{
    // Interruption and reversal. Re-targeting keeps the live velocity instead of
    // resetting it to zero, so a reversed gesture bends rather than hitting a
    // brick wall at the moment the user changed their mind.
    const s = spring({ from: 0, to: 300, response: 0.5, onUpdate() {} });
    tick(); tick(); tick();
    const mid = s.value;
    const carried = s.velocity;
    assert.ok(mid > 0 && mid < 300, 'caught mid-flight');
    assert.ok(carried > 0, 'and still moving');

    s.retarget(0);
    assert.equal(s.velocity, carried, 'retarget must not zero the velocity');
    assert.equal(s.value, mid, 'nor teleport the presentation value');
    run(s);
    assert.equal(s.value, 0, 'the reversed spring lands on the new target');
}
{
    // stop() must actually unschedule, or a dismissed drawer keeps burning
    // frames for the life of the session.
    const s = spring({ from: 0, to: 100, onUpdate() {} });
    tick();
    assert.ok(frames.size > 0, 'a live spring keeps a frame queued');
    s.stop();
    assert.equal(frames.size, 0, 'stop() must unschedule the pending frame');
    tick();
    assert.equal(frames.size, 0, 'and never queue another');
    assert.ok(s.done);
}
{
    // Reduced motion: no travel, but the caller still gets its value. Silently
    // dropping the update would leave the drawer stuck off-screen.
    reduceMotion = true;
    assert.equal(prefersReducedMotion(), true);
    const seen = [];
    const s = spring({ from: 0, to: 100, onUpdate: (v) => seen.push(v) });
    assert.deepEqual(seen, [100], 'with motion reduced the value arrives immediately');
    assert.ok(s.done, 'and nothing is left animating');
    assert.equal(frames.size, 0, 'no frame is scheduled at all');

    // Opting out is possible for motion that is not vestibular.
    const t = spring({ from: 0, to: 100, respectReducedMotion: false, onUpdate() {} });
    assert.equal(t.done, false, 'respectReducedMotion:false still animates');
    t.stop();
    reduceMotion = false;
}

// ---------------------------------------------------------------------------
// Wiring — the primitives are worth nothing sitting in a file nobody imports
// ---------------------------------------------------------------------------
const app = readFileSync(new URL('../src/app.jsx', import.meta.url), 'utf8');
const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const css = readFileSync(new URL('../src/styles/apple-motion.css', import.meta.url), 'utf8');

assert.match(app, /from '\.\/ui\/motion\.js'/, 'app.jsx must use the motion primitives');

// The drawer is the one true gesture surface in the app. If it goes back to a
// display toggle, everything above is decoration.
assert.match(app, /onPointerDown: drawerDown/, 'the drawer must be dragged, not toggled');
assert.match(app, /snapTarget\(offsetRef\.current, v, \[-w, 0\]/,
    'the release must be resolved by projection, not by which edge is nearer');
assert.match(app, /onPointerMove: drawerMove/);
assert.match(app, /onPointerCancel: drawerUp/, 'a cancelled pointer must release the drag too');
assert.match(app, /setPointerCapture/, 'tracking must survive the pointer leaving the panel');
assert.ok(app.includes("touchAction: 'pan-y'"),
    'the drawer must hand the vertical axis back to the browser, or its list stops scrolling');
assert.ok(!/display: drawerOpen \? 'block' : 'none'/.test(app),
    'the old display toggle must be gone — it is what made the drawer un-grabbable');

// Every programmatic scroll goes through the reduced-motion check.
assert.ok(!app.includes("behavior: 'smooth'"),
    "no raw behavior:'smooth' — it must go through scrollBehavior()");
assert.match(app, /const scrollBehavior = \(\) =>/);

// The stylesheet has to load, and it has to load last.
assert.match(html, /apple-motion\.css/, 'apple-motion.css must be linked');
const idxMotion = html.indexOf('apple-motion.css');
const idxComponents = html.indexOf('components.css');
assert.ok(idxMotion > idxComponents,
    'apple-motion.css must come after components.css — it settles arguments on source order');

// The three accessibility signals, all three of them.
assert.match(css, /@media \(prefers-reduced-motion: reduce\)/);
assert.match(css, /@media \(prefers-reduced-transparency: reduce\)/);
assert.match(css, /@media \(prefers-contrast: more\)/);

// Press feedback exists and lands on :active, which fires on pointer-down.
assert.match(css, /button:not\(:disabled\):active/, 'controls must acknowledge the press itself');
assert.match(css, /touch-action: manipulation/, 'the ~300ms tap delay must be dropped');

// Tracking is a scale, not a constant.
const tracking = [...css.matchAll(/letter-spacing: (-?[\d.]+)em/g)].map((m) => Number(m[1]));
assert.ok(tracking.some((t) => t < -0.01), 'display sizes must tighten');
assert.ok(tracking.some((t) => t > 0), 'small sizes must open up');

console.log('apple-motion: ok');
