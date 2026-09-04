// The QR bundle is the third largest thing this site serves — 142 KB gzipped — and it
// is needed on exactly two occasions: creating a channel, and opening the scanner.
// Neither is on the first screen. It used to be a <script type="module"> in <head>, so
// every first visit paid for it up front. What has to keep holding: it is not in the
// shells, app-boot still fetches it, esbuild has not quietly inlined it back into the
// critical bundle, and the scanner can still start if someone opens it early.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

const site = JSON.parse(read('locales/site.json'));
const shells = ['index.html', ...site.locales.filter((c) => c !== site.defaultLocale).map((c) => `${c}/index.html`)];

for (const shell of shells) {
    const html = read(shell);
    // Comments are allowed to mention it; a <script src> is not.
    const tags = [...html.matchAll(/<script[^>]*src="([^"]*)"/g)].map((m) => m[1]);
    assert.equal(tags.some((src) => src.includes('qr-local')), false,
        `${shell} loads the QR bundle up front — it belongs behind app-boot's idle fetch`);
    assert.equal(tags.some((src) => src.includes('QRScanner')), false,
        `${shell} still loads QRScanner.js, which registers a window.QRScanner nothing reads`);
}

// app-boot must actually fetch it, and only after the app has mounted.
{
    const boot = read('src/scripts/app-boot.js');
    assert.match(boot, /import\(\s*['"]\/dist\/qr-local\.js['"]\s*\)/,
        'app-boot.js no longer imports the QR bundle — nothing else does either');
    assert.ok(boot.includes('scheduleQrBundle()'), 'app-boot.js never schedules the QR fetch');
    assert.ok(boot.includes('securebit:qr-ready'),
        'app-boot.js must announce the bundle, or a scanner opened early never starts');

    // The import has to stay a runtime fetch. If esbuild ever resolves and inlines it,
    // the bundle grows by the whole QR library and this change silently undoes itself.
    const bundle = read('dist/app-boot.js');
    assert.ok(bundle.includes('import("/dist/qr-local.js")'),
        'dist/app-boot.js lost the dynamic import — esbuild may have inlined the QR bundle');
    assert.equal(bundle.includes('Html5Qrcode'), false,
        'the QR library ended up inside dist/app-boot.js, which is what deferring it was for');
}

// The scanner starts from an effect guarded on window.Html5Qrcode. With the bundle
// arriving late that guard can fail on first run, so the effect has to re-run when it
// lands — otherwise opening the modal early leaves a black viewfinder for good.
{
    const app = read('src/app.jsx');
    assert.ok(app.includes("window.addEventListener('securebit:qr-ready'"),
        'app.jsx does not listen for the QR bundle, so an early scanner never recovers');
    assert.match(app, /\}, \[showQRScannerModal, qrBundleReady\]\);/,
        'the scanner effect must depend on the QR bundle having arrived');
}

console.log('qr-bundle-deferred.test.mjs: all assertions passed');
