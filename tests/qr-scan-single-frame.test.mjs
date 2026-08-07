// An SBQ2 invitation is one QR frame. The scanner must treat it as complete on
// sight.
//
// This test exists because of a real bug. The chunk assembler in handleQRScan
// was written for SB1, which the generator always cuts into exactly four frames,
// so the expected count is hard-coded to 4. Its fallback branch claims *any*
// non-JSON string longer than 100 characters — and an `SB2:` payload is 151 to
// 170 characters. A single, complete invitation was therefore filed as chunk 1
// of 4, and the scanner sat waiting for three frames that do not exist.
//
// The assertions are structural rather than behavioural: handleQRScan lives
// inside a 5,900-line JSX component and cannot be invoked in isolation, but the
// ordering that makes it correct can still be pinned.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const src = readFileSync(new URL('../src/app.jsx', import.meta.url), 'utf8');

const scanIdx = src.indexOf('const handleQRScan = async (scannedData) => {');
assert.notEqual(scanIdx, -1, 'handleQRScan must exist in src/app.jsx');

// Everything from the start of the handler to the end of the file is enough:
// what matters is the order of the branches inside it.
const body = src.slice(scanIdx);

const sbq2Idx = body.indexOf("scannedData.startsWith('SB2:')");
assert.notEqual(sbq2Idx, -1, 'handleQRScan must recognise an SB2 payload');

// The raw-byte form must be recognised too — the two families never collide,
// since any SB1 payload begins with ASCII 'S'.
assert.ok(/scannedData\.charCodeAt\(0\) === 0x02/.test(body.slice(sbq2Idx, sbq2Idx + 400)),
    'the raw-byte SBQ2 form must be recognised alongside the text form');

// The SBQ2 branch must come before BOTH chunk-assembly branches: the explicit
// SB1:bin: one and the "long non-JSON string" fallback that actually caught it.
const binChunkIdx = body.indexOf("scannedData.startsWith('SB1:bin:')");
const lengthHeuristicIdx = body.indexOf('scannedData.length > 100');
assert.notEqual(binChunkIdx, -1, 'the SB1 chunk branch must still exist');
assert.notEqual(lengthHeuristicIdx, -1, 'the long-string fallback must still exist');
assert.ok(sbq2Idx < binChunkIdx,
    'SBQ2 must be handled before the SB1:bin chunk assembler');
assert.ok(sbq2Idx < lengthHeuristicIdx,
    'SBQ2 must be handled before the "long non-JSON string" fallback, which a ' +
    '151-character SB2 payload otherwise matches');

// The branch must terminate the scan rather than fall through into assembly.
const sbq2Branch = body.slice(sbq2Idx, binChunkIdx);
assert.ok(/setShowQRScannerModal\(false\)/.test(sbq2Branch),
    'capturing a single-frame invitation must close the scanner');
assert.ok(/return Promise\.resolve\(true\)/.test(sbq2Branch),
    'the SBQ2 branch must report completion, not "waiting for more"');
assert.ok(/qrChunksBufferRef\.current = \{ id: null/.test(sbq2Branch),
    'any partial chunk buffer must be cleared, so a stray earlier frame cannot ' +
    'be spliced onto a complete invitation');

// Both destinations must be fed, because the same scanner serves both steps.
assert.ok(/setAnswerInput\(scannedData\)/.test(sbq2Branch) &&
          /setOfferInput\(scannedData\)/.test(sbq2Branch),
    'the scanned code must reach the answer field on the offering side and the ' +
    'offer field on the joining side');

// The hard-coded four must stay explicitly tied to SB1, so it is not read as a
// general rule the next time the format changes.
for (const m of body.matchAll(/total: 4,/g)) {
    const context = body.slice(Math.max(0, m.index - 400), m.index);
    assert.ok(/SB1/.test(context),
        'a hard-coded frame count must say which format it belongs to');
}

console.log('qr-scan-single-frame: all assertions passed');
