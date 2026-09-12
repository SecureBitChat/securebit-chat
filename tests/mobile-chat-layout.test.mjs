// Invariants that keep the chat from shifting on mobile, iOS in particular.
//
// Every assertion here corresponds to something that was actually wrong:
//
//  - `env(safe-area-inset-*)` was already used by the composer but resolved to 0,
//    because the viewport meta lacked `viewport-fit=cover`.
//  - A first attempt pinned the shell with position:fixed and chased
//    visualViewport.offsetTop from JS. That is the wrong instrument: a fixed box
//    is laid out against the layout viewport, which iOS never shrinks for the
//    keyboard, so it must be chased forever — and it felt nailed down rather
//    than laid out. The shell is sized from the visual viewport instead.
//  - `--sb-vh` was rewritten on every `visualViewport` *scroll* event, so the
//    whole layout resized under the finger while the iOS URL bar collapsed.
//  - Children re-asserted a full viewport height, adding the header back.
//  - The message list is `flex: 1` in a column, which defaults to
//    `min-height: auto` — it refuses to shrink below its content and pushes the
//    composer off the bottom once the conversation is long enough.
//
// These are structural checks. The layout itself is measured against a real
// connection in a real browser; see the notes in the pull request.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8');
const app = readFileSync(new URL('../src/app.jsx', import.meta.url), 'utf8');

// ---------------------------------------------------------------------------
// safe areas
// ---------------------------------------------------------------------------
const meta = /<meta\s+name="viewport"\s+content="([^"]+)"/.exec(html);
assert.ok(meta, 'a viewport meta tag must exist');
assert.match(meta[1], /viewport-fit=cover/,
    'without viewport-fit=cover, env(safe-area-inset-*) is 0 on iOS and the ' +
    'composer padding that depends on it does nothing');
assert.match(meta[1], /width=device-width/);
assert.ok(app.includes('env(safe-area-inset-bottom'),
    'the composer must pad for the home indicator');

// ---------------------------------------------------------------------------
// the shell is sized AND pinned to the visible rect
//
// Sizing came first, and on its own it was not enough. Reported from iOS Safari,
// with a screenshot: tap the composer, the keyboard comes up, and the entire app
// has slid off the top of the screen — the bottom sliver of the composer at the
// very top, black underneath it all the way down to the keyboard, header gone.
//
// That is the visual viewport being PANNED. WebKit shrinks it for the keyboard
// and then moves it down inside the layout viewport (which it never shrinks) to
// reveal the focused field. The shell had shrunk correctly, to the top --sb-vh of
// the layout viewport; the window had simply moved off it. No CSS declines that
// pan, and it is not a document scroll, so there is no scrollTop to put back.
//
// So the shell is fixed to the layout viewport and translated by
// visualViewport.offsetTop. The earlier objection to pinning is still honoured
// where it was right: HEIGHT never moves on a scroll event (that is what made the
// layout twitch under the finger), and the offset rides a transform rather than
// `top`. Off iOS nothing pans, --sb-vv-top stays 0, and this is inert.
// ---------------------------------------------------------------------------
assert.match(app, /\.sb-app-shell\{height:var\(--sb-vh,100dvh\) !important/,
    'the shell must be sized from the visual viewport, with a dvh fallback');

// The floor has to come off, or the height above is decorative.
//
// The shell and the column both carry .minimal-bg, which sets min-height:100vh
// (src/styles/components.css, src/styles/main.css) — and min-height always beats
// height. On iOS `100vh` is the URL-bar-retracted *large* viewport, so with the bar
// showing the shell was held ~60-100px taller than the visible area; that surplus
// made the document scrollable, and a scrolling document is how the header rode off
// the top. Measured before the fix: with --sb-vh forced to 700px the shell stayed
// 844px. After: 700px, and the document is not scrollable.
assert.match(app, /\.sb-app-shell\{[^}]*min-height:0 !important/,
    'the shell must clear the min-height:100vh it inherits from .minimal-bg, or ' +
    '--sb-vh can never shrink it and the whole viewport-tracking path is inert');
assert.match(app, /\.sb-app-col\{[^}]*min-height:0 !important/,
    'the column carries .minimal-bg too and needs the same floor removed');
assert.match(app, /\.sb-app-shell\{[^}]*position:fixed/,
    'the shell must be pinned to the layout viewport, or an iOS pan leaves it ' +
    'off the top of the screen with the keyboard up');
assert.match(app, /\.sb-app-shell\{[^}]*transform:translate3d\(0,var\(--sb-vv-top, 0px\),0\)/,
    'the pin must follow visualViewport.offsetTop, and it must do so with a ' +
    'transform — `top` on a fixed box relayouts the whole shell every frame');
assert.ok(!/sb-scroll-locked/.test(app),
    'the body scroll lock existed only to stop rubber-banding behind a pinned ' +
    'shell; without the pin it just breaks normal scrolling');

// Children fill the shell; they must not restate a viewport height.
for (const sel of ['.sb-app-col', '.chat-container']) {
    const re = new RegExp(`\\${sel}\\{height:100% !important`);
    assert.match(app, re, `${sel} must fill the shell, not re-assert a viewport height`);
    assert.ok(!new RegExp(`\\${sel}\\{height:var\\(--sb-vh`).test(app),
        `${sel} must not set a viewport height of its own — nested full-height ` +
        'boxes are how the header got counted twice');
}

// ---------------------------------------------------------------------------
// the header stays at the top
//
// Sticky, and nothing more. An earlier attempt pinned the header by removing the
// document's ability to scroll (html/body overflow:hidden). That is a far broader
// change than the problem called for: it also killed scrolling on the connection
// screen. The layout was already right at that point — the header was the only
// outstanding item — and the lesson is to keep the fix the size of the problem.
// ---------------------------------------------------------------------------
assert.match(app, /\.sb-chat-header\{position:sticky;top:0/,
    'the header must stick to the top of whatever scrolls');
assert.ok(!/sb-app-open/.test(app),
    'the document scroll lock must stay gone: it broke the connection screen and ' +
    'was never what the header needed');
assert.ok(!/html[^{]*\{[^}]*overflow:hidden/.test(app),
    'nothing may take the document\'s scroll away');

// ---------------------------------------------------------------------------
// the message list is the only scroller
// ---------------------------------------------------------------------------
assert.match(app, /\.sb-scroll\{min-height:0 !important/,
    'a flex:1 item in a column needs min-height:0 or it pushes the composer off ' +
    'the bottom of the screen');
assert.match(app, /\.sb-scroll\{[^}]*overscroll-behavior:contain/,
    'the list must not chain its scroll to the document');

// ---------------------------------------------------------------------------
// the home-indicator inset collapses while the keyboard is up
// ---------------------------------------------------------------------------
assert.match(app, /--sb-safe-bottom/,
    'the safe-area inset must be a variable so it can collapse with the keyboard');
assert.match(app, /var\(--sb-safe-bottom, env\(safe-area-inset-bottom, 0px\)\)/,
    'the composer must use the toggled inset, falling back to the raw env()');

// ---------------------------------------------------------------------------
// viewport tracking: resize only, never scroll
// ---------------------------------------------------------------------------
{
    const i = app.indexOf('const applyHeight = ');
    assert.notEqual(i, -1, 'height tracking must exist');
    const block = app.slice(i, i + 6000);

    assert.match(block, /vv\.addEventListener\('resize', apply\)/,
        'height must be recomputed on resize');
    assert.ok(!/vv\.addEventListener\('scroll', apply\)/.test(block),
        'HEIGHT must not be recomputed on visualViewport scroll: on iOS that ' +
        'fires while the URL bar collapses and during rubber-banding, and ' +
        'resizing the shell there is what made the layout twitch under the finger');
    assert.match(block, /vv\.addEventListener\('scroll', onPan\)/,
        'the pan, on the other hand, must be followed on scroll — that event is ' +
        'the only notice iOS gives that the visible rect has moved');
    assert.match(block, /requestAnimationFrame\(\(\) => \{ raf = 0; applyOffset\(\); \}\)/,
        'a burst of scroll events must collapse into one style write per frame');
    assert.match(block, /const zoomed = !!vv && vv\.scale > 1\.01/,
        'the only thing that may switch the pan off is a pinch-zoomed page. It ' +
        'must not be gated on the window being taller than the visual viewport: ' +
        'that assumes iOS never shrinks the layout viewport, and the day it does ' +
        'the guard turns the whole fix off without a word');

    // Redundant writes cause a style recalculation on every event.
    assert.match(block, /h !== lastH/, 'skip no-op height writes');
    assert.match(block, /Math\.round/, 'sub-pixel churn must be rounded away');
}

// ---------------------------------------------------------------------------
// layout preview
// ---------------------------------------------------------------------------
assert.match(app, /get\('preview'\) === 'chat'/,
    '?preview=chat must render the chat layout without a connection');
assert.match(app, /webrtcManager: null/,
    'the preview must not be given a peer manager');
{
    const i = app.indexOf('if (previewMode) {');
    assert.notEqual(i, -1, 'the preview branch must exist');
    const branch = app.slice(i, app.indexOf('return React.createElement(\'div\', {\n                        className: showSidebar', i) + 1 || i + 6000);
    assert.ok(!/onSendMessage: handleSendMessage/.test(branch),
        'the preview must not wire real send handlers');
}

// ---------------------------------------------------------------------------
// the connection toast must not sit on the header
//
// It is `fixed top-4 left-1/2` (src/pwa/pwa-manager.js), which inside the chat
// lands on the header and covers the peer name. The offset is expressed in the
// same two variables the header's own height is (--sb-bar-h for the content row,
// --sb-safe-top for the status-bar strip an installed app draws under), so the
// toast follows the bar instead of restating a number that only holds in a
// browser tab.
// ---------------------------------------------------------------------------
{
    const css = readFileSync(new URL('../src/styles/components.css', import.meta.url), 'utf8');
    const rule = css.match(/body\.sb-in-chat #pwa-connection-status\s*\{[^}]*\}/);
    assert.ok(rule, 'the online/offline toast must be offset inside the chat');
    assert.match(rule[0], /top:\s*calc\([^)]*var\(--sb-bar-h/,
        'the toast offset must track the header height, not a hard-coded 64px');
    assert.match(rule[0], /var\(--sb-safe-top/,
        'the toast must also clear the status-bar strip in an installed app');
}

// ---------------------------------------------------------------------------
// iOS focus zoom
// ---------------------------------------------------------------------------
assert.match(app, /textarea,input,select\{font-size:16px !important/,
    'iOS zooms the page when a focused field is under 16px, which reflows ' +
    'everything and looks like the layout jumping');

console.log('mobile-chat-layout: all assertions passed');
