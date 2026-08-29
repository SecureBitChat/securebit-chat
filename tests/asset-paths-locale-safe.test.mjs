// Every locale is served from its own subdirectory, so a relative asset path silently
// changes meaning depending on which page you are on: 'logo/aegis.png' is /logo/aegis.png
// from the English page and /de/logo/aegis.png — a 404 — from the German one. The
// partner logos shipped exactly that bug, and it is invisible in development, where
// only the root page is ever open.
//
// The CSP sets base-uri 'none', so a <base href> cannot rescue relative paths either.
// Root-absolute is the only option, and this test is what keeps it that way.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));

// Directories that exist at the site root. A reference to one of them from inside a
// locale page has to start with a slash.
const ROOT_DIRS = ['logo', 'assets', 'libs', 'dist', 'config', 'src'];

const files = execFileSync('git', ['ls-files', 'src'], { cwd: ROOT, encoding: 'utf8' })
    .trim().split('\n')
    .filter((f) => /\.(js|jsx)$/.test(f) && f !== 'src/i18n/generated.js');

const offenders = [];
for (const file of files) {
    const text = readFileSync(path.join(ROOT, file), 'utf8');
    text.split('\n').forEach((line, i) => {
        // A quoted path that starts with a root directory name and no leading slash.
        for (const match of line.matchAll(new RegExp(`['"](?:${ROOT_DIRS.join('|')})/[A-Za-z0-9_./-]+\\.(png|jpe?g|svg|gif|webp|ico|css|mp3|mp4|webm|woff2?)['"]`, 'g'))) {
            // An ES import specifier is resolved by the bundler at build time, not by the
            // browser against the page URL, so it is not affected.
            if (/\b(import|from|require)\b/.test(line)) continue;
            offenders.push(`${file}:${i + 1}  ${match[0]}`);
        }
    });
}

assert.deepEqual(
    offenders, [],
    'these asset paths are relative and will 404 from a locale subdirectory — prefix them with "/":\n' +
    offenders.join('\n')
);

console.log(`asset-paths-locale-safe.test.mjs: ${files.length} source files checked, no relative asset paths`);
