import assert from 'node:assert/strict';

// No DOM needed: we mock the incoming-chat sanitizer so DOMPurify/window are
// not required, and exercise the transport/meta plumbing directly.
globalThis.window = globalThis.window || {};

const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');
const P = EnhancedSecureWebRTCManager.prototype;
const T = EnhancedSecureWebRTCManager.MESSAGE_TYPES;

// ── _sanitizeMessageMeta: whitelist + bounds ────────────────────────────────
{
    const ok = P._sanitizeMessageMeta.call({}, { mid: 'm_1-a', once: true, onceTtl: 15, ttl: 300, code: true });
    assert.deepEqual(ok, { mid: 'm_1-a', code: true, once: true, onceTtl: 15, ttl: 300 });

    // onceTtl is clamped to [1, 3600]; out-of-range is dropped.
    assert.equal(P._sanitizeMessageMeta.call({}, { once: true, onceTtl: 99999 }).onceTtl, undefined);
    assert.equal(P._sanitizeMessageMeta.call({}, { once: true, onceTtl: 30 }).onceTtl, 30);

    // Junk and out-of-range values are stripped; with no valid keys -> null.
    assert.equal(P._sanitizeMessageMeta.call({}, { foo: 1 }), null);
    assert.equal(P._sanitizeMessageMeta.call({}, null), null);
    assert.equal(P._sanitizeMessageMeta.call({}, { ttl: 999999 }), null); // above 24h cap
    assert.equal(P._sanitizeMessageMeta.call({}, { ttl: 1 }), null);      // below 5s floor
    assert.equal(P._sanitizeMessageMeta.call({}, { once: 'yes' }), null); // must be exactly true
    assert.deepEqual(P._sanitizeMessageMeta.call({}, { mid: 'bad id!@#' }), { mid: 'badid' }); // sanitized
}

// ── deliverMessageToUI forwards sanitized meta to onMessage ──────────────────
{
    const calls = [];
    const manager = {
        _debugMode: false,
        _secureLog() {},
        _sanitizeIncomingChatMessage: (m) => m, // bypass DOMPurify in test
        _sanitizeMessageMeta: P._sanitizeMessageMeta,
        onMessage: (message, type, meta) => calls.push({ message, type, meta })
    };
    P.deliverMessageToUI.call(manager, 'hello', 'received', { once: true, ttl: 30, mid: 'm1', junk: 9 });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].message, 'hello');
    assert.equal(calls[0].type, 'received');
    assert.deepEqual(calls[0].meta, { mid: 'm1', once: true, ttl: 30 });

    // No meta -> onMessage gets undefined (backward compatible).
    calls.length = 0;
    P.deliverMessageToUI.call(manager, 'plain', 'received');
    assert.equal(calls[0].meta, undefined);
}

// ── processMessage routes message_delete to onMessageDelete ──────────────────
{
    const deleted = [];
    const manager = {
        _secureLog() {},
        onMessageDelete: (id) => deleted.push(id)
    };
    await P.processMessage.call(
        manager,
        JSON.stringify({ type: T.MESSAGE_DELETE, data: { messageId: 'm_42' } })
    );
    assert.deepEqual(deleted, ['m_42']);
}

// ── live enhanced-message path delivers metadata to the UI ───────────────────
// This is the path real chat uses (dataChannel.onmessage -> _processEnhancedMessageWithoutMutex).
{
    const envelope = JSON.stringify({ type: 'message', data: 'hi there', meta: { mid: 'm7', once: true, ttl: 30 } });
    globalThis.window.EnhancedSecureCryptoUtils = {
        decryptMessage: async () => ({ message: envelope })
    };
    const calls = [];
    const manager = {
        encryptionKey: {}, macKey: {}, metadataKey: {},
        _secureLog() {},
        _checkInboundRateLimit: () => true,
        _sanitizeIncomingChatMessage: (m) => m,
        _sanitizeMessageMeta: P._sanitizeMessageMeta,
        onMessage: (message, type, meta) => calls.push({ message, type, meta }),
        deliverMessageToUI: P.deliverMessageToUI
    };
    await P._processEnhancedMessageWithoutMutex.call(manager, { type: 'enhanced_message', data: 'enc' });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].message, 'hi there');
    assert.deepEqual(calls[0].meta, { mid: 'm7', once: true, ttl: 30 });
}

// ── sendMessageDelete emits a well-formed control message ────────────────────
{
    const sent = [];
    const manager = { sendSystemMessage: (m) => { sent.push(m); return true; } };
    const result = P.sendMessageDelete.call(manager, 'm_99');
    assert.equal(result, true);
    assert.deepEqual(sent, [{ type: T.MESSAGE_DELETE, messageId: 'm_99' }]);

    // Invalid ids are rejected without emitting anything.
    sent.length = 0;
    assert.equal(P.sendMessageDelete.call(manager, ''), false);
    assert.equal(sent.length, 0);
}

console.log('Secure chat features tests passed');
