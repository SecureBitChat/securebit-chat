// Android install was minting a home-screen shortcut instead of the app.
//
// Chrome offers the real install once, via beforeinstallprompt, and never
// replays it. Two things have to hold or the offer is lost and the Install
// button degrades to a page of manual instructions — which on a phone reads as
// "add a bookmark", and a bookmark is what people got:
//
//   1. A listener exists before Chrome fires the event. install-prompt.js is a
//      module, so it is evaluated too late; the capture script has to be a
//      plain blocking <script> in <head>, ahead of everything else.
//   2. preventDefault() is called, so the event is ours to prompt() with later
//      instead of being spent on Chrome's own default action.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

const CAPTURE = 'src/scripts/pwa-install-capture.js';

// The capture script itself.
{
    const src = read(CAPTURE);
    assert.match(src, /addEventListener\(\s*'beforeinstallprompt'/,
        'the capture script must listen for beforeinstallprompt');
    assert.match(src, /event\.preventDefault\(\)/,
        'the capture script must call preventDefault() — without it the event cannot be prompted with later');
    assert.match(src, /window\.__pwaInstallEvent\s*=\s*event/,
        'the captured event must be stashed where install-prompt.js can find it');
}

// It must be in <head> of every shell, blocking, and before the PWA modules.
{
    const site = JSON.parse(read('locales/site.json'));
    const shells = [
        'index.html',
        ...site.locales.filter((c) => c !== site.defaultLocale).map((c) => `${c}/index.html`),
    ];

    for (const shell of shells) {
        const html = read(shell);
        const tag = html.match(new RegExp(`<script([^>]*)src="/${CAPTURE}[^"]*"[^>]*>`));
        assert.ok(tag, `${shell} does not load ${CAPTURE}`);

        assert.equal(/\b(defer|async|type="module")/.test(tag[1]), false,
            `${shell} loads the capture script deferred — beforeinstallprompt will have fired already`);

        const headEnd = html.indexOf('</head>');
        assert.ok(headEnd > -1 && html.indexOf(tag[0]) < headEnd,
            `${shell} loads the capture script outside <head>`);

        assert.ok(html.indexOf(tag[0]) < html.indexOf('/src/pwa/install-prompt.js'),
            `${shell} loads install-prompt.js before the capture script`);
    }
}

// And the prompt UI must both adopt what was captured and defend itself.
{
    const src = read('src/pwa/install-prompt.js');
    assert.match(src, /adoptInstallEvent\s*\(/,
        'install-prompt.js must expose adoptInstallEvent for the capture script to hand off to');
    assert.match(src, /if\s*\(window\.__pwaInstallEvent\)/,
        'install-prompt.js must pick up an event captured before it was evaluated');
    assert.match(src, /event\.preventDefault\(\);\s*\n\s*this\.adoptInstallEvent/,
        'install-prompt.js must preventDefault() its own beforeinstallprompt before stashing it');
}

console.log('pwa-install-prompt-capture.test.mjs: all assertions passed');
