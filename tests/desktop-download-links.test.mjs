// Desktop download links must actually download something.
//
// They have broken twice, both times the same way:
//
//   1. The version is written in more than one place — a `DOWNLOADS` table in
//      app.jsx and a `DownloadApps` component — so bumping one left the other
//      behind, and nobody noticed because the stale link still *looked* valid.
//
//   2. Links used /releases/latest/download/<file>. GitHub resolves `latest` by
//      redirecting to the newest tag, so once 0.3.0 shipped, a link written for
//      0.1.0 turned into
//         /releases/download/v0.3.0/SecureBit.Chat_0.1.0_x64-setup.exe
//      — a file that never existed under that tag. The button navigated to
//      GitHub and downloaded nothing.
//
// So: one version across every file, tags pinned, and — unless SKIP_NETWORK=1 —
// every generated URL is fetched to prove the asset is really there.
//
// Run with:  node tests/desktop-download-links.test.mjs

import fs from 'fs';
import path from 'path';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(ROOT, p), 'utf8');

const SOURCES = ['src/app.jsx', 'src/components/ui/DownloadApps.jsx'];

// ---------- every source agrees on one version ----------
const versions = SOURCES.map((f) => {
  const m = /(?:SB_)?DESKTOP_VERSION\s*=\s*'([^']+)'/.exec(read(f));
  assert.ok(m, `${f} must declare a DESKTOP_VERSION constant instead of inlining the version`);
  return { file: f, version: m[1] };
});

const unique = [...new Set(versions.map((v) => v.version))];
assert.equal(
  unique.length, 1,
  `every source must use the same desktop version, found: ${versions.map((v) => `${v.file}=${v.version}`).join(', ')}`
);

const VERSION = unique[0];
assert.match(VERSION, /^\d+\.\d+\.\d+$/, 'desktop version must be semver');

// ---------- no source may resolve through /latest/ ----------
// Comments explain *why* these forms are avoided and would otherwise match, so
// check the code only.
const stripComments = (src) =>
  src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n')
    .map((line) => line.replace(/(^|\s)\/\/.*$/, '$1'))
    .join('\n');

for (const f of SOURCES) {
  const code = stripComments(read(f));
  assert.doesNotMatch(
    code, /releases\/latest\/download/,
    `${f} must pin the release tag: a stale /latest/ link resolves to the newest tag ` +
    'with an old filename and 404s'
  );
  // And the version must never be written into a URL by hand.
  const hardcoded = code.match(/SecureBit\.Chat_\d+\.\d+\.\d+_/g);
  assert.equal(
    hardcoded, null,
    `${f} hardcodes a version in a filename (${hardcoded && hardcoded[0]}); build it from the constant`
  );
}

// ---------- the URLs the app will actually open ----------
const urls = [
  `https://github.com/SecureBitChat/securebit-desktop/releases/download/v${VERSION}/SecureBit.Chat_${VERSION}_x64.dmg`,
  `https://github.com/SecureBitChat/securebit-desktop/releases/download/v${VERSION}/SecureBit.Chat_${VERSION}_x64-setup.exe`,
  `https://github.com/SecureBitChat/securebit-desktop/releases/download/v${VERSION}/SecureBit.Chat_${VERSION}_amd64.AppImage`
];

if (process.env.SKIP_NETWORK === '1') {
  console.log(`Desktop download link tests passed (v${VERSION}, network checks skipped)`);
  process.exit(0);
}

let failed = 0;
for (const url of urls) {
  try {
    // Range keeps it to a few bytes: we only care that the asset resolves.
    const res = await fetch(url, { headers: { Range: 'bytes=0-99' }, redirect: 'follow' });
    const ok = res.status === 200 || res.status === 206;
    if (!ok) failed++;
    console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${res.status}  ${url.split('/').pop()}`);
  } catch (err) {
    failed++;
    console.log(`  FAIL ${url.split('/').pop()} — ${err.message}`);
  }
}

assert.equal(
  failed, 0,
  'every desktop download link must resolve to a real release asset; ' +
  'publish the release before bumping the version, or set SKIP_NETWORK=1 to skip this check'
);

console.log(`Desktop download link tests passed (v${VERSION}, ${urls.length} assets reachable)`);
