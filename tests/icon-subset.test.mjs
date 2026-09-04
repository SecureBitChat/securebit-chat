// The icon fonts are subset to what this interface draws: 82 of Font Awesome's 2468,
// which took 299 KB of woff2 down to 12 KB. The saving comes with a failure mode that
// is completely silent — add an icon to a component and it renders as an empty box,
// with no error anywhere, because the glyph is simply not in the shipped font.
//
// So the manifest scripts/subset-icons.py writes is checked against the source here.
// A new icon fails the build with the name of the icon and the command to run.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync, existsSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

const manifest = JSON.parse(read('assets/fontawesome/subset-icons.json'));
const covered = new Set(manifest.icons);
const notIcons = new Set(manifest.notIcons);

// Every fa- class the interface names, from the same files the subsetter reads.
function sourceFiles(dir) {
    const out = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = path.join(dir, entry.name);
        if (entry.isDirectory()) out.push(...sourceFiles(full));
        else if (/\.(js|jsx|css|html)$/.test(entry.name)) out.push(full);
    }
    return out;
}

const used = new Set();
for (const file of [...sourceFiles(path.join(ROOT, 'src')), path.join(ROOT, 'index.html')]) {
    for (const match of readFileSync(file, 'utf8').matchAll(/\bfa-([a-z0-9-]+)/g)) {
        if (!notIcons.has(match[1])) used.add(match[1]);
    }
}

const missing = [...used].filter((name) => !covered.has(name)).sort();
assert.deepEqual(missing, [],
    `these icons are used but not in the subset, so they render as empty boxes: ${missing.join(', ')}\n` +
    '    fix: pip install fonttools brotli && python3 scripts/subset-icons.py && npm run build');

// The subset fonts and the stylesheet that names them have to exist and be small — the
// point of the exercise is the size, and a regenerate that quietly fell back to the full
// font would still pass every assertion above.
const bundle = read('assets/app.css');
for (const family of ['fa-solid-900', 'fa-regular-400', 'fa-brands-400']) {
    const rel = `assets/fontawesome/webfonts/${family}.subset.woff2`;
    assert.ok(existsSync(path.join(ROOT, rel)), `${rel} is missing — run scripts/subset-icons.py`);
    const size = statSync(path.join(ROOT, rel)).size;
    assert.ok(size < 40_000, `${rel} is ${size} B — that is the full font, not a subset`);
    assert.ok(bundle.includes(`${family}.subset.woff2`), `assets/app.css does not use the ${family} subset`);
}

// And the full stylesheet must not come back: it is 102 KB for icons that are not here.
assert.equal(bundle.includes('/assets/fontawesome/css/all.min.css'), false,
    'the full Font Awesome stylesheet is being loaded again alongside the subset');
for (const shell of ['index.html', 'ru/index.html']) {
    assert.equal(read(shell).includes('fontawesome/css/all.min.css'), false,
        `${shell} still links the full Font Awesome stylesheet`);
}

console.log(`icon-subset.test.mjs: ${used.size} icons used, all covered by the subset`);
