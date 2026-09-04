// The light theme rests on four things that are all easy to break without noticing,
// because breaking any of them still looks correct in whichever theme you happen to be
// developing in:
//
//  - The boot script decides the theme before first paint. If it stops being blocking,
//    or stops being reachable under the page's CSP, the site paints dark and corrects
//    itself a moment later — the flash that a theme switch exists to avoid.
//  - Every colour token is declared in both palettes. One missing from the light block
//    silently falls back to the dark value, which is how you get white text on white.
//  - No component re-introduces a literal colour. One hard-coded hex is invisible in
//    dark and unreadable in light.
//  - "System" is stored as a mode, not as the colour it resolved to. Storing 'dark'
//    when the user asked to follow the system means the page stops following it.

import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');

const themeCss = read('src/styles/theme.css');
const bootJs = read('src/scripts/theme-boot.js');
const switcher = read('src/components/ui/ThemeSwitcher.jsx');
const header = read('src/components/ui/Header.jsx');
const template = read('templates/index.template.html');

// ── The boot script has to win the race against first paint ──────────────────────────
{
    const tag = template.match(/<script src="\/src\/scripts\/theme-boot\.js[^>]*><\/script>/);
    assert.ok(tag, 'theme-boot.js must be linked from the template');
    assert.equal(/defer|async|type="module"/.test(tag[0]), false,
        'theme-boot must be blocking: deferred or module scripts run after first paint');

    const head = template.slice(0, template.indexOf('</head>'));
    assert.ok(head.includes(tag[0]), 'theme-boot must be in <head>');
    assert.ok(
        head.indexOf(tag[0]) < head.indexOf('/assets/app.css'),
        'theme-boot must run before the stylesheet so the first match is already correct'
    );

    // The page's CSP is script-src 'self' with no nonce and no hash, so an inline
    // script here would be blocked outright and the theme would never be applied.
    assert.equal(/<script>[\s\S]*?data-theme/.test(template), false,
        'the theme cannot be applied from an inline script under this CSP');
}

// ── The installed app follows the theme too ─────────────────────────────────────────
{
    // Comments stripped first — the note above the tags names <meta name="theme-color">
    // in prose, and that is not a third tag.
    const markup = template.replace(/<!--[\s\S]*?-->/g, '');
    const bars = [...markup.matchAll(/<meta name="theme-color"[^>]*>/g)].map((m) => m[0]);
    assert.equal(bars.length, 2, 'one tag per scheme, so the answer is right before any script runs');
    assert.ok(bars.some((t) => /media="\(prefers-color-scheme: dark\)"/.test(t) && /#0f0f11/.test(t)));
    assert.ok(bars.some((t) => /media="\(prefers-color-scheme: light\)"/.test(t) && /#f6f7f8/.test(t)));
    assert.match(bootJs, /removeAttribute\('media'\)/,
        'an explicit choice has to override the media queries, not sit behind them');

    // black-translucent draws the iOS clock in white whatever the page does, and the
    // meta is read once at launch, so it cannot be corrected from script.
    assert.match(markup, /apple-mobile-web-app-status-bar-style" content="default"/,
        'the iOS status bar must be free to pick a glyph colour that contrasts with the theme');

    const manifest = JSON.parse(read('manifest.json'));
    assert.equal(manifest.theme_color, '#0f0f11',
        'the installed window title bar should be the page ground, not the brand orange');
    assert.equal(manifest.background_color, '#0f0f11');
}

// ── Both palettes declare exactly the same tokens ────────────────────────────────────
{
    const blocks = [...themeCss.matchAll(/(:root(?:\[data-theme="light"\])?)\s*\{([\s\S]*?)\n\}/g)];
    const collect = (selector) => {
        const found = new Set();
        for (const [, sel, body] of blocks) {
            if (sel !== selector) continue;
            for (const m of body.matchAll(/(--sb-[a-z0-9-]+)\s*:/g)) found.add(m[1]);
        }
        return found;
    };
    const dark = collect(':root');
    const light = collect(':root[data-theme="light"]');

    assert.ok(dark.size > 60, `expected a full palette, found ${dark.size} tokens`);
    assert.deepEqual([...dark].filter((t) => !light.has(t)), [],
        'every token needs a light value — a missing one silently keeps the dark colour');
    assert.deepEqual([...light].filter((t) => !dark.has(t)), [],
        'a token that exists only in the light block is undefined in dark');
}

// ── A filled accent is the brand colour in both themes ──────────────────────────────
{
    // This is what made the first light build's buttons brown: the accent was darkened
    // for contrast as *text*, and the fills inherited it. A fill does not need to be
    // darkened — the ink on it is near-black in both themes — so it must not be.
    const blocks = [...themeCss.matchAll(/(:root(?:\[data-theme="light"\])?)\s*\{([\s\S]*?)\n\}/g)];
    const read1 = (selector, token) => {
        for (const [, sel, body] of blocks) {
            if (sel !== selector) continue;
            const m = body.match(new RegExp(`${token}\\s*:\\s*([^;]+);`));
            if (m) return m[1].trim();
        }
        return null;
    };
    for (const token of ['--sb-orange-solid', '--sb-green-solid', '--sb-red-solid',
                         '--sb-red-strong-solid', '--sb-yellow-solid', '--sb-yellow-2-solid']) {
        assert.equal(read1(':root[data-theme="light"]', token), read1(':root', token),
            `${token} is a fill and must be the same colour in both themes`);
    }
    // And the ink that sits on those fills stays near-black, not white.
    for (const token of ['--sb-on-accent', '--sb-on-green', '--sb-on-green-2']) {
        assert.equal(read1(':root[data-theme="light"]', token), read1(':root', token),
            `${token} sits on a fill that did not change, so it must not change either`);
    }

    // No mark may reach for the text-safe token by mistake. This is the check that
    // matters most, because a colour reaches a fill by more routes than one style
    // property: through a constant (`background: C_ORANGE`), through a helper argument
    // (`svg(icon, 26, ACCENT, 1.9)`), and through SVG written as a source string
    // (`stroke="var(--sb-green)"`). The first pass at this only looked at style
    // properties naming the token inline, and every button that went through a constant
    // stayed brown.
    const sources = [
        'src/app.jsx', 'src/state/sessionsStore.js', 'src/state/groupsStore.js',
        'src/styles/components.css', 'src/scripts/pwa-globals.js',
        'src/pwa/install-prompt.js', 'src/pwa/pwa-manager.js',
        'src/components/UpdateChecker.jsx',
        ...readdirSync(new URL('../src/components/ui', import.meta.url))
            .filter((f) => f.endsWith('.jsx')).map((f) => `src/components/ui/${f}`),
    ];
    const BARE = '(orange|green|red|red-strong|yellow|yellow-2)';
    const ROUTES = [
        // a paint property naming the token directly, in JS or in CSS
        new RegExp(`(background|background-color|backgroundColor|border-color|borderColor|fill|stroke)[a-zA-Z-]*\\s*:\\s*'?[^,;}]{0,70}var\\(--sb-${BARE}\\)`, 'g'),
        // SVG attributes inside a template string
        new RegExp(`(stroke|fill)="var\\(--sb-${BARE}\\)"`, 'g'),
        // a paint property naming one of the text-safe *constants* rather than the
        // token — this is the route that left the Generate and Start buttons brown,
        // because the property never mentions a token for a regex to find.
        /(background|backgroundColor|borderColor|fill|stroke)[a-zA-Z-]*\s*[:=]\s*'?[^,;}]{0,40}\b(C_ORANGE|C_GREEN|ACCENT)\b(?!_SOLID)/g,
        // a helper argument: svg(icon, size, ACCENT, width) puts its third argument on
        // `stroke`, so the colour reaches a mark without ever naming a property.
        /\bsvg\([^)]*?\b(C_ORANGE|C_GREEN|ACCENT)\b(?!_SOLID)/g,
        // a variable whose name says it is a dot. A dot is always a mark.
        /\b\w*[Dd]ot\w*\s*=\s*[^;]{0,120}var\(--sb-(orange|green|red|red-strong|yellow|yellow-2)\)/g,
    ];
    const offenders = [];
    for (const rel of sources) {
        const text = read(rel);
        for (const rx of ROUTES) {
            for (const m of text.matchAll(rx)) offenders.push(`${rel}: ${m[0].slice(0, 62)}`);
        }
    }
    assert.deepEqual(offenders, [],
        `these marks would go brown in the light theme; use the -solid token:\n  ${offenders.join('\n  ')}`);

    // The stores hold nothing but dot colours — presence, connection state, group
    // health — and every one of them is a mark. No text-safe accent belongs there at
    // all, so the rule can be flat rather than property-by-property.
    for (const rel of ['src/state/sessionsStore.js', 'src/state/groupsStore.js']) {
        const bare = [...read(rel).matchAll(/var\(--sb-(orange|green|red|red-strong|yellow|yellow-2)\)/g)];
        assert.deepEqual(bare.map((m) => m[0]), [],
            `${rel} only paints dots; every accent there must be the -solid form`);
    }

    // A constant that feeds a fill has to be the solid one. Both forms must exist
    // wherever the file declares either, so the two are never confused for each other.
    for (const rel of ['src/app.jsx', 'src/components/ui/IceServerSettings.jsx']) {
        const text = read(rel);
        assert.match(text, /const C_ORANGE_SOLID = 'var\(--sb-orange-solid\)'/, `${rel} needs the fill form`);
        assert.match(text, /const C_GREEN_SOLID = 'var\(--sb-green-solid\)'/, `${rel} needs the fill form`);
    }

    // The shades that only ever paint — the hover ground under every primary button and
    // the dots in the connection animation — must not darken either.
    for (const token of ['--sb-orange-hi', '--sb-orange-2']) {
        assert.equal(read1(':root[data-theme="light"]', token), read1(':root', token),
            `${token} is only ever a fill; darkening it browns the button hover and the animation`);
    }
}

// ── Every token that is used is declared, and every token declared is used ───────────
{
    const declared = new Set([...themeCss.matchAll(/(--sb-[a-z0-9-]+)\s*:/g)].map((m) => m[1]));
    // Layout variables that predate this file and are declared elsewhere.
    const elsewhere = new Set([
        '--sb-press', '--sb-settle', '--sb-bar-h', '--sb-bar-extra',
        '--sb-safe-top', '--sb-safe-bottom', '--sb-vh',
    ]);

    const sources = [
        ...readdirSync(new URL('../src/components/ui', import.meta.url))
            .filter((f) => f.endsWith('.jsx')).map((f) => `src/components/ui/${f}`),
        'src/app.jsx',
        'src/styles/main.css', 'src/styles/components.css',
        'src/styles/apple-motion.css', 'src/styles/pwa.css',
        'src/pwa/install-prompt.js', 'src/pwa/pwa-manager.js', 'src/scripts/pwa-globals.js',
    ];

    const used = new Map();
    for (const rel of sources) {
        for (const m of read(rel).matchAll(/var\((--sb-[a-z0-9-]+)/g)) {
            if (!used.has(m[1])) used.set(m[1], rel);
        }
    }

    const undeclared = [...used].filter(([t]) => !declared.has(t) && !elsewhere.has(t));
    assert.deepEqual(undeclared, [],
        `these resolve to nothing: ${undeclared.map(([t, f]) => `${t} (${f})`).join(', ')}`);
}

// ── No component may go back to a literal colour ─────────────────────────────────────
{
    // The exceptions are colours that are the same in both themes by nature: white
    // behind a QR code, black behind a video track, and the brand mark's own gradient.
    const ALLOWED = new Set(['#fff', '#ffffff', '#000', '#000000', '#111']);
    const offenders = [];

    for (const rel of ['src/app.jsx',
        ...readdirSync(new URL('../src/components/ui', import.meta.url))
            .filter((f) => f.endsWith('.jsx')).map((f) => `src/components/ui/${f}`)]) {
        const text = read(rel);
        for (const m of text.matchAll(/#[0-9a-fA-F]{3,8}\b/g)) {
            if (ALLOWED.has(m[0].toLowerCase())) continue;
            // A "#310" in prose is an issue number, not a colour.
            const line = text.slice(text.lastIndexOf('\n', m.index) + 1,
                text.indexOf('\n', m.index));
            if (/^\s*(\/\/|\*)/.test(line)) continue;
            offenders.push(`${rel}: ${m[0]}`);
        }
        // rgba(255,255,255,…) is the other way a dark-only colour sneaks back in: it is
        // a hairline on a dark ground and invisible on a light one.
        for (const m of text.matchAll(/rgba\(\s*255\s*,\s*255\s*,\s*255\s*,/g)) {
            offenders.push(`${rel}: ${m[0]}…  (use rgba(var(--sb-ink), …))`);
        }
    }

    assert.deepEqual(offenders, [],
        `literal colours cannot follow the theme:\n  ${offenders.join('\n  ')}`);
}

// ── The stored preference is a mode, never a resolved colour ─────────────────────────
{
    assert.match(bootJs, /var MODES = \['system', 'light', 'dark'\]/,
        'three modes: following the system is a preference of its own');
    assert.match(bootJs, /window\.localStorage\.setItem\(STORAGE_KEY, mode\)/,
        'the mode is what gets stored — storing the resolved colour stops it following');
    assert.match(bootJs, /catch \(e\)/,
        'storage throws in private windows and with site data blocked; it cannot take the page down');
    assert.match(bootJs, /prefers-color-scheme: light/,
        'system mode has to ask the OS');
    assert.match(bootJs, /addEventListener\('change', onSystemChange\)/,
        'the OS theme changing mid-session must be followed while in system mode');
}

// ── It actually runs, and it actually switches ───────────────────────────────────────
{
    // The two media-query tags the template ships, so the strip-and-set behaviour is
    // exercised rather than the single-tag shortcut.
    const dom = new JSDOM(
        '<!doctype html><html><head>'
        + '<meta name="theme-color" media="(prefers-color-scheme: dark)" content="#0f0f11">'
        + '<meta name="theme-color" media="(prefers-color-scheme: light)" content="#f6f7f8">'
        + '</head><body></body></html>',
        { url: 'https://securebit.chat/', runScripts: 'outside-only' });
    const store = new Map();
    Object.defineProperty(dom.window, 'localStorage', {
        value: {
            getItem: (k) => (store.has(k) ? store.get(k) : null),
            setItem: (k, v) => store.set(k, String(v)),
        },
        configurable: true,
    });
    // jsdom has no matchMedia; a system that says "light" is the interesting case,
    // because it is the one where doing nothing would be wrong.
    dom.window.matchMedia = () => ({ matches: true, addEventListener() {}, addListener() {} });

    dom.window.eval(bootJs);
    const { document, SecureBitTheme } = dom.window;

    assert.ok(SecureBitTheme, 'the boot script must publish its API');
    assert.equal(SecureBitTheme.get(), 'system', 'no stored preference means follow the system');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'light',
        'a light system with no stored preference must paint light');
    const bars = () => [...document.querySelectorAll('meta[name="theme-color"]')];
    assert.deepEqual(bars().map((m) => m.getAttribute('content')), ['#f6f7f8', '#f6f7f8'],
        'the browser UI around the page has to match it');
    assert.deepEqual(bars().map((m) => m.hasAttribute('media')), [false, false],
        'the media attributes must come off, or the tag whose query does not match is ignored');

    // An explicit choice must beat the system, which is the whole reason data-theme is
    // stamped rather than left to a media query.
    assert.equal(SecureBitTheme.set('dark'), 'dark');
    assert.equal(document.documentElement.getAttribute('data-theme'), 'dark');
    assert.deepEqual(bars().map((m) => m.getAttribute('content')), ['#0f0f11', '#0f0f11'],
        'an explicit dark choice on a light system must still darken the browser UI');
    assert.equal(store.get('securebit-theme'), 'dark', 'the choice has to survive a reload');
    assert.equal(SecureBitTheme.resolved(), 'dark');

    assert.equal(SecureBitTheme.set('system'), 'light', 'going back to system re-asks the OS');
    assert.equal(store.get('securebit-theme'), 'system', 'the mode is stored, not the colour');

    // A value that is not one of the three modes must be ignored rather than stamped.
    SecureBitTheme.set('chartreuse');
    assert.equal(SecureBitTheme.get(), 'system');

    let seen = null;
    const off = SecureBitTheme.subscribe((mode, resolved) => { seen = [mode, resolved]; });
    SecureBitTheme.set('light');
    assert.deepEqual(seen, ['light', 'light'], 'subscribers are told both the mode and what it resolved to');
    off();
    SecureBitTheme.set('dark');
    assert.deepEqual(seen, ['light', 'light'], 'unsubscribing has to actually unsubscribe');
}

// ── The control is on the landing page and reflects the boot script ─────────────────
{
    assert.match(header, /import \{ ThemeSwitcher \} from '\.\/ThemeSwitcher\.jsx'/);
    assert.match(header, /onLanding && React\.createElement\(ThemeSwitcher/,
        'the switcher belongs to the landing header, beside the language menu');

    assert.match(switcher, /window\.SecureBitTheme/,
        'the component is a view onto the boot script, not a second source of truth');
    assert.match(switcher, /api\.subscribe\(/,
        'it has to re-render when the OS or another tab changes the theme');
    assert.equal(/localStorage/.test(switcher), false,
        'only the boot script touches storage — two writers would drift');
    assert.match(switcher, /if \(!api\) return null;/,
        'with no boot script there is nothing to drive');
    assert.match(switcher, /'aria-checked'/, 'a three-way choice needs its selection announced');

    for (const key of ['theme.label', 'theme.system', 'theme.light', 'theme.dark']) {
        assert.ok(switcher.includes(`t('${key}')`), `${key} must come from the dictionary`);
    }
}

// ── Every locale carries the strings, or that locale's menu shows key names ──────────
{
    // site.json holds the build's own configuration, not a locale's strings.
    const locales = readdirSync(new URL('../locales', import.meta.url))
        .filter((f) => f.endsWith('.json') && f !== 'site.json');
    assert.ok(locales.length >= 13, 'expected every shipped locale');
    for (const file of locales) {
        const { ui } = JSON.parse(read(`locales/${file}`));
        for (const key of ['theme.label', 'theme.system', 'theme.light', 'theme.dark']) {
            assert.ok(ui[key] && ui[key].trim(), `${file} is missing ${key}`);
        }
    }
}

// ── Nothing splits a colour apart at runtime any more ───────────────────────────────
{
    // The roadmap used to take the literal hex out of its status table and cut it into
    // channels with parseInt. A custom property cannot be parsed that way — it is still
    // the string "var(--sb-green)" when the script sees it — so that helper produced
    // rgba(NaN,NaN,NaN,a) and the status pills lost their fill and border.
    const roadmap = read('src/components/ui/Roadmap.jsx');
    assert.equal(/parseInt\([^)]*\.slice\(1\)/.test(roadmap), false,
        'a var() reference cannot be split into channels by hand; publish the channels instead');
    assert.match(roadmap, /rgb: "var\(--sb-[a-z0-9-]+-rgb\)"/,
        'the status table must carry the channels alongside the colour');

    // The status pill is desktop-only: on a phone the word does not fit, and a bordered
    // box around one dot repeats what the timeline marker already shows.
    assert.match(roadmap, /\{!isMobile && \(\s*\n\s*<span style=\{\{ display: 'inline-flex'/,
        'the whole status pill must be hidden on mobile, not only its label');
}

console.log('✅ theme switching');
