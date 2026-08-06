// Voice notes are the only transfer accepted without asking the user. The flag
// that grants that exemption, `isVoice`, is set by the SENDER and sits outside
// the signed fileHash on purpose — so it is the receiver's job to decide whether
// a transfer has actually earned the exemption.

import assert from 'node:assert/strict';

globalThis.window = {};

const { EnhancedSecureFileTransfer } = await import('../src/transfer/EnhancedSecureFileTransfer.js');

const makeTransfer = () => new EnhancedSecureFileTransfer({
    dataChannel: { readyState: 'open', send() {} },
    encryptionKey: null,
    macKey: null,
    onProgress() {},
    onFileReceived() {},
    onError() {}
});

const metadataFor = (over = {}) => ({
    fileId: 'f1',
    fileName: 'voice-message.webm',
    fileSize: 48_000,
    fileType: 'audio/webm',
    totalChunks: 3,
    chunkSize: 16 * 1024,
    salt: Array.from({ length: 32 }, (_, i) => i),
    isVoice: true,
    ...over
});

const ft = makeTransfer();

// ── a genuine voice note still skips the consent card ────────────────────────
{
    const v = ft.validateIncomingMetadata(metadataFor());
    assert.equal(v.isValid, true, v.errors.join('; '));
    assert.equal(v.isVoice, true, 'a real voice note must keep auto-accept');
    assert.equal(v.voiceRejection, null);
}

// ── an arbitrary blob wearing an allowed extension must not ──────────────────
// This was the actual hole: `.mp4` is in the voice extension list and
// application/octet-stream counts as a "generic" MIME for ordinary uploads, so a
// 20 MB blob claiming isVoice was downloaded and rendered with no prompt at all.
{
    const v = ft.validateIncomingMetadata(metadataFor({
        fileName: 'payload.mp4',
        fileType: 'application/octet-stream',
        fileSize: 20 * 1024 * 1024
    }));
    assert.equal(v.isVoice, false, 'a generic-MIME blob must not auto-accept');
    assert.match(v.voiceRejection, /not an audio MIME type/);
}

// ── an absent MIME is not a free pass either ─────────────────────────────────
{
    const v = ft.validateIncomingMetadata(metadataFor({ fileType: '' }));
    assert.equal(v.isVoice, false);
    assert.match(v.voiceRejection, /not an audio MIME type/);
}

// ── audio, but not an audio type we actually support ─────────────────────────
{
    const v = ft.validateIncomingMetadata(metadataFor({ fileType: 'audio/x-made-up' }));
    assert.equal(v.isVoice, false);
    assert.match(v.voiceRejection, /unsupported audio MIME type/);
}

// ── size ceiling: a voice note is minutes of speech, not a payload channel ───
{
    const v = ft.validateIncomingMetadata(metadataFor({
        fileSize: ft.MAX_AUTO_ACCEPT_VOICE_SIZE + 1
    }));
    assert.equal(v.isVoice, false);
    assert.match(v.voiceRejection, /too large to auto-accept/);

    // Right at the ceiling is still fine.
    const ok = ft.validateIncomingMetadata(metadataFor({
        fileSize: ft.MAX_AUTO_ACCEPT_VOICE_SIZE
    }));
    assert.equal(ok.isVoice, true, 'the limit itself must be accepted');
}

// ── a per-session budget bounds the total, not just each one ─────────────────
{
    const budgeted = makeTransfer();
    budgeted.autoAcceptedVoiceBytes = budgeted.MAX_AUTO_ACCEPT_VOICE_SESSION_BYTES - 1000;

    const v = budgeted.validateIncomingMetadata(metadataFor({ fileSize: 48_000 }));
    assert.equal(v.isVoice, false, 'the session budget must eventually stop auto-accept');
    assert.match(v.voiceRejection, /budget/);
}

// ── a rejected voice claim is a downgrade, not a drop ────────────────────────
// The peer may be sending something perfectly legitimate that simply does not
// qualify; it must still reach the user through the normal consent card.
{
    const v = ft.validateIncomingMetadata(metadataFor({
        fileName: 'report.pdf',
        fileType: 'application/pdf',
        fileSize: 100_000
    }));
    assert.equal(v.isValid, true, 'the transfer itself stays valid');
    assert.equal(v.isVoice, false, 'but it does not skip consent');
}

// ── files that never claimed to be voice are unaffected ──────────────────────
{
    const v = ft.validateIncomingMetadata(metadataFor({
        fileName: 'photo.png', fileType: 'image/png', isVoice: undefined
    }));
    assert.equal(v.isValid, true, v.errors.join('; '));
    assert.equal(v.isVoice, false);
    assert.equal(v.voiceRejection, null, 'no rejection reason for something that never asked');
}

console.log('voice-auto-accept.test.mjs: all assertions passed');
