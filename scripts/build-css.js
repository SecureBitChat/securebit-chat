/**
 * build-css.js — concatenates every render-blocking stylesheet into one file.
 *
 * The page used to link eight of them: the Tailwind build, the Inter @font-face
 * declarations, five hand-written sheets, and pwa.css at the end of <body>. Together
 * they are about 21 KB compressed, which is nothing — but each one is a separate
 * request that has to complete before the browser paints, and on a throttled mobile
 * connection each cost between 400 and 900 ms of latency for a file of 1 to 7 KB.
 * GTmetrix put the whole thing at 441 ms of render-blocking time, spent almost
 * entirely on round trips rather than bytes.
 *
 * Order is the one thing this must not get wrong. The sheets are written to argue with
 * each other on source order: components.css settles layout, apple-motion.css then
 * overrides press feedback and reduced-motion behaviour on top of it, and rtl.css has
 * to win over everything because its rules only apply under [dir="rtl"]. Concatenating
 * in the same sequence the <link> tags had preserves that exactly — the cascade cannot
 * tell the difference between eight files and one.
 *
 * The only rewriting done here is url(): inter.css refers to its woff2 files relatively,
 * and those paths are resolved against the sheet's own directory before it moves.
 */

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const OUT = path.join(ROOT, 'assets', 'app.css');

// The exact sequence the <link> tags had, head first and pwa.css last.
const SHEETS = [
    'assets/tailwind.css',
    // Font Awesome, cut to the 82 icons this interface draws (scripts/subset-icons.py).
    // The full sheet was 102 KB and loaded asynchronously to keep it off the critical
    // path; at 7 KB it is cheaper to have it here than to spend a request on it, and
    // icons stop arriving a beat after the text.
    'assets/fontawesome/css/subset.css',
    'assets/fonts/inter/inter.css',
    'src/styles/main.css',
    'src/styles/animations.css',
    'src/styles/components.css',
    'src/styles/apple-motion.css',
    'src/styles/rtl.css',
    'src/styles/pwa.css',
];

/**
 * Make every relative url() root-absolute, resolved against the sheet it came from.
 * Absolute paths, full URLs and data: URIs are already correct and left alone.
 */
function absolutizeUrls(css, sheetPath) {
    const dir = path.posix.dirname(`/${sheetPath}`);
    return css.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/g, (whole, quote, target) => {
        if (/^([a-z][a-z0-9+.-]*:|\/|#)/i.test(target.trim())) return whole;
        return `url(${quote}${path.posix.join(dir, target.trim())}${quote})`;
    });
}

function build() {
    const parts = [];
    for (const sheet of SHEETS) {
        const file = path.join(ROOT, sheet);
        if (!fs.existsSync(file)) {
            throw new Error(`stylesheet listed in build-css.js is missing: ${sheet}`);
        }
        parts.push(`/* ${sheet} */\n${absolutizeUrls(fs.readFileSync(file, 'utf8'), sheet)}`);
    }

    const combined = parts.join('\n\n');
    // esbuild minifies from stdin so nothing intermediate has to be written to disk.
    const minified = execFileSync(
        'npx',
        ['--no-install', 'esbuild', '--loader=css', '--minify'],
        { input: combined, encoding: 'utf8', cwd: ROOT, maxBuffer: 32 * 1024 * 1024 }
    );

    fs.writeFileSync(OUT, minified, 'utf8');
    return { bytes: Buffer.byteLength(minified), sheets: SHEETS.length };
}

if (require.main === module) {
    try {
        const { bytes, sheets } = build();
        console.log('🎨 Bundling stylesheets...');
        console.log(`   ✅ assets/app.css — ${sheets} sheets, ${bytes.toLocaleString('en-US')} bytes`);
    } catch (error) {
        console.error('❌ css build failed:', error.message);
        process.exit(1);
    }
}

module.exports = { build, SHEETS };
