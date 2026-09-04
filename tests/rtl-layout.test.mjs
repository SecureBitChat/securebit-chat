// Right-to-left is a layout property, not a translation. Arabic strings in a left-to-right
// page are not a localized app — the avatar still sits on the wrong side of the name, the
// drawer still flies in from the wrong edge, the chevron still points away from "next".
//
// So this test guards the mechanism rather than the wording: that direction reaches the
// document, that the source no longer hard-codes a physical side, and that the two things
// which must NOT mirror — the swipe maths and machine-readable text — are handled.
//
// It reads the source rather than rendering it because there is no DOM here that resolves
// logical properties: jsdom parses `margin-inline-start` but has no layout engine to
// mirror it, so an assertion about pixels would be an assertion about jsdom.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');
const site = JSON.parse(read('locales/site.json'));

/** Every source file the UI is built from. */
function sources() {
    const out = [];
    const walk = (dir) => {
        for (const entry of readdirSync(path.join(ROOT, dir))) {
            const rel = `${dir}/${entry}`;
            if (statSync(path.join(ROOT, rel)).isDirectory()) walk(rel);
            else if (/\.(jsx?|css)$/.test(entry) && !rel.endsWith('i18n/generated.js')) out.push(rel);
        }
    };
    walk('src');
    return out;
}

// ── The direction reaches the page ───────────────────────────────────────────────────
// It has to be in the served HTML, not applied by the app: styling and first paint both
// happen long before React mounts, so a direction set in JS shows one frame of a mirrored
// layout to every RTL reader.
{
    const rtl = site.locales.filter((code) => JSON.parse(read(`locales/${code}.json`)).dir === 'rtl');
    assert.ok(rtl.length > 0, 'no RTL locale is registered — this test has nothing to protect');

    for (const code of rtl) {
        const locale = JSON.parse(read(`locales/${code}.json`));
        const page = read(code === site.defaultLocale ? 'index.html' : `${code}/index.html`);
        assert.match(page, new RegExp(`<html lang="${locale.htmlLang}" dir="rtl">`),
            `${code}: the generated page does not declare its writing direction`);
        assert.equal(JSON.parse(read(`${code}/manifest.json`)).dir, 'rtl',
            `${code}: an installed PWA would launch left-to-right`);
    }

    // The sheets are no longer linked one by one; scripts/build-css.js concatenates
    // them into assets/app.css to save eight render-blocking round trips. So check the
    // two things that actually matter: rtl.css is still in the bundle's list, and it is
    // still last in it — its rules exist to win over everything above them.
    const cssBuild = read('scripts/build-css.js');
    const order = [...cssBuild.matchAll(/'((?:src|assets)\/[^']+\.css)'/g)].map((m) => m[1]);
    assert.ok(order.includes('src/styles/rtl.css'),
        'the mirroring stylesheet is not in the CSS bundle, so it never reaches the page');
    assert.ok(order.indexOf('src/styles/rtl.css') > order.indexOf('src/styles/components.css'),
        'rtl.css must come after the sheets it overrides, or the mirroring loses on source order');
    assert.ok(read('templates/index.template.html').includes('/assets/app.css'),
        'the template does not link the bundled stylesheet');

    // And that the built file really carries them: a bundler that silently dropped an
    // input would leave every one of these assertions above still passing.
    const bundled = read('assets/app.css');
    assert.match(bundled, /\[dir=["']?rtl["']?\]/,
        'assets/app.css carries no right-to-left rules (the minifier drops the quotes)');
}

// ── The runtime exposes direction ────────────────────────────────────────────────────
{
    const i18n = await import(pathToFileURL(path.join(ROOT, 'src/i18n/index.js')));
    const rtl = site.locales.find((code) => JSON.parse(read(`locales/${code}.json`)).dir === 'rtl');

    assert.equal(i18n.localeDir(site.defaultLocale), 'ltr');
    assert.equal(i18n.localeDir(rtl), 'rtl');
    assert.equal(i18n.isRTL(rtl), true);
    assert.equal(i18n.isRTL(site.defaultLocale), false);
    assert.equal(i18n.localeDir('nope'), 'ltr', 'an unknown locale must not throw or mirror');

    // The sign is what call sites multiply an offset by, so it is the part that breaks
    // silently: a drawer with the wrong sign slides off-screen instead of open.
    assert.equal(i18n.direction(site.defaultLocale), 1);
    assert.equal(i18n.direction(rtl), -1);

    assert.equal(i18n.LTR_TEXT.dir, 'ltr');
    assert.equal(i18n.LTR_TEXT.style.unicodeBidi, 'isolate',
        'an LTR run inside RTL text must be isolated, or it drags the sentence around it');
}

// ── No physical sides left in the UI ─────────────────────────────────────────────────
// A single margin-left is enough to put an icon on the wrong side of its label, and it is
// invisible to anyone testing in English. Logical properties are the whole mechanism, so
// a regression here is a regression in RTL support.
{
    // camelCase in React style objects, kebab-case in stylesheets and injected CSS strings.
    const banned = [
        [/\bmarginLeft\s*:/, 'marginLeft → marginInlineStart'],
        [/\bmarginRight\s*:/, 'marginRight → marginInlineEnd'],
        [/\bpaddingLeft\s*:/, 'paddingLeft → paddingInlineStart'],
        [/\bpaddingRight\s*:/, 'paddingRight → paddingInlineEnd'],
        [/\bborderLeft\s*:/, 'borderLeft → borderInlineStart'],
        [/\bborderRight\s*:/, 'borderRight → borderInlineEnd'],
        [/textAlign\s*:\s*['"](?:left|right)['"]/, "textAlign: 'left'/'right' → 'start'/'end'"],
        [/(?<![-\w])margin-(?:left|right)\s*:/, 'margin-left/right → margin-inline-start/end'],
        [/(?<![-\w])padding-(?:left|right)\s*:/, 'padding-left/right → padding-inline-start/end'],
        [/(?<![-\w])border-(?:left|right)\s*:/, 'border-left/right → border-inline-start/end'],
        [/text-align\s*:\s*(?:left|right)\b/, 'text-align: left/right → start/end'],
        [/(?<![-\w])\bml-\d/, 'Tailwind ml-* → ms-*'],
        [/(?<![-\w])\bmr-\d/, 'Tailwind mr-* → me-*'],
        [/(?<![-\w])\bpl-\d/, 'Tailwind pl-* → ps-*'],
        [/(?<![-\w])\bpr-\d/, 'Tailwind pr-* → pe-*'],
        [/(?<![-\w])\btext-(?:left|right)\b/, 'Tailwind text-left/right → text-start/end'],
    ];

    // rtl.css is where the exceptions live — it exists precisely to say "left" on purpose.
    const files = sources().filter((f) => f !== 'src/styles/rtl.css');

    // A notch is on the physical left of the handset whichever way the text runs, so
    // safe-area insets are the one place where a physical side is the correct answer.
    const physicalOnPurpose = (line) => line.includes('env(safe-area-inset-');

    const offences = [];
    for (const file of files) {
        const lines = read(file).split('\n');
        lines.forEach((line, i) => {
            if (physicalOnPurpose(line)) return;
            for (const [pattern, fix] of banned) {
                if (pattern.test(line)) offences.push(`${file}:${i + 1}  ${fix}`);
            }
        });
    }
    assert.deepEqual(offences, [], `physical directions left in the UI:\n  ${offences.join('\n  ')}`);
}

// ── The gesture mirrors with the layout ──────────────────────────────────────────────
// The drawer keeps one logical offset (0 open, -width closed) in both directions, and
// mirrors at exactly two points: the pixels it paints and the finger that drives it. Miss
// either and the panel tracks the wrong way under the thumb.
{
    const app = read('src/app.jsx');
    assert.match(app, /const DIR = direction\(\);/, 'app.jsx does not resolve the layout direction');
    assert.match(app, /translate3d\(' \+ \(x \* DIR\)/, 'the drawer paints an unmirrored offset');
    assert.match(app, /d\.base \+ \(e\.clientX - d\.x0\) \* DIR/, 'the drawer drag is not mirrored');
    assert.ok(app.includes('d.vel.add(e.clientX * DIR'),
        'the velocity tracker samples raw screen x, so a flick would settle the wrong way');
}

// ── Machine text is pinned left-to-right ─────────────────────────────────────────────
// Bidi reordering rewrites exactly the strings this app is made of. A session descriptor
// or a SAS code printed in the wrong order still looks like a key, so the reader compares
// it happily against their peer's screen and confirms a channel they never verified.
{
    const app = read('src/app.jsx');
    for (const field of ['value: sasInput', 'value: answerInput', 'value: offerInput']) {
        const at = [...app.matchAll(new RegExp(field.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'g'))]
            .map((m) => m.index);
        assert.notEqual(at.length, 0, `${field} is gone — this guard now protects nothing`);
        // Every one of them, not just the first: the app renders the SAS code in two
        // places, and it was the one further up the file that got missed.
        for (const i of at) {
            assert.ok(app.slice(Math.max(0, i - 260), i).includes("dir: 'ltr'"),
                `the field holding ${field} at offset ${i} must be dir="ltr" or bidi reorders what the user compares`);
        }
    }

    // Displaying a code is as dangerous as typing one, and easier to miss. The safety
    // code is drawn one character per tile in a flex row, and a flex row follows the
    // writing direction — so in Arabic the first character lands on the right and the
    // code reads backwards. It still looks like a code, which is the whole problem.
    const cells = app.indexOf("key: 'cells'");
    assert.notEqual(cells, -1, 'the safety-code tiles are gone — this guard now protects nothing');
    assert.ok(app.slice(cells, cells + 60).includes("dir: 'ltr'"),
        'the safety-code tiles sit in a flex row, so they must be pinned left-to-right');

    // The group code, wherever it is put on screen. A plain `group.sasCode` also appears
    // in guard conditions, which render nothing — so the window looks both ways and only
    // the sites that are actually inside an element have to carry the direction.
    const group = read('src/components/ui/GroupChat.jsx');
    // `!group.sasCode` is an existence check that renders nothing; everything else puts
    // the digits somewhere a person can read them.
    const shown = [...group.matchAll(/(!?)group\.sasCode/g)]
        .filter((m) => m[1] !== '!')
        .map((m) => m.index);
    assert.ok(shown.length >= 2, 'the group safety code is no longer rendered where expected');
    let pinned = 0;
    for (const i of shown) {
        if (group.slice(Math.max(0, i - 420), i + 260).includes("dir: 'ltr'")) pinned += 1;
    }
    assert.equal(pinned, shown.length,
        `${shown.length - pinned} of ${shown.length} group-safety-code sites are not pinned ` +
        'left-to-right — everyone in the group compares those digits against each other');

    const rtlCss = read('src/styles/rtl.css');
    for (const selector of ['[dir="rtl"] code', '[dir="rtl"] pre', '[dir="rtl"] .sb-sc']) {
        assert.ok(rtlCss.includes(selector), `rtl.css no longer isolates ${selector}`);
    }
    assert.match(rtlCss, /unicode-bidi:\s*isolate/, 'isolation is what stops a run dragging its neighbours');
}

console.log('rtl-layout.test.mjs: all assertions passed');
