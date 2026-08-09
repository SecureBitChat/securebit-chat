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
// the shell is sized, not pinned
//
// An earlier fix pinned the shell with position:fixed and chased the visual
// viewport offset from JS. That is the wrong instrument — the reference iOS chat
// implementations drive HEIGHT from visualViewport and leave positioning alone —
// and it made the layout feel nailed down instead of laid out.
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
assert.ok(!/\.sb-app-shell\{position:fixed/.test(app),
    'the shell must not be position:fixed: a fixed box is laid out against the ' +
    'layout viewport, which iOS never shrinks for the keyboard, so it has to be ' +
    'chased with JS forever');
assert.ok(!/--sb-vv-top/.test(app),
    'chasing visualViewport.offsetTop belongs to the pinned approach and should ' +
    'be gone with it');
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
    const block = app.slice(i, i + 2500);

    assert.match(block, /vv\.addEventListener\('resize', apply\)/,
        'height must be recomputed on resize');
    assert.ok(!/vv\.addEventListener\('scroll'/.test(block),
        'nothing may be recomputed on visualViewport scroll: on iOS that fires ' +
        'while the URL bar collapses and during rubber-banding, and resizing the ' +
        'shell there is what made the layout twitch under the finger');

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
// lands on the 64px header and covers the peer name.
// ---------------------------------------------------------------------------
{
    const css = readFileSync(new URL('../src/styles/components.css', import.meta.url), 'utf8');
    assert.match(css, /body\.sb-in-chat #pwa-connection-status\s*\{[^}]*top:\s*calc\(64px/,
        'the online/offline toast must clear the chat header');
}

// ---------------------------------------------------------------------------
// iOS focus zoom
// ---------------------------------------------------------------------------
assert.match(app, /textarea,input,select\{font-size:16px !important/,
    'iOS zooms the page when a focused field is under 16px, which reflows ' +
    'everything and looks like the layout jumping');

console.log('mobile-chat-layout: all assertions passed');
