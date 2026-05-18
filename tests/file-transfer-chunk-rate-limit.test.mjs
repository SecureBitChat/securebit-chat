import assert from 'node:assert/strict';
import { EnhancedSecureFileTransfer } from '../src/transfer/EnhancedSecureFileTransfer.js';

function createSystem() {
    const manager = {
        dataChannel: { onmessage: null, send() {}, readyState: 'open' },
        isVerified: true,
        fileTransferSystem: null,
        isConnected: () => true,
        connectionId: 'peer-1'
    };
    const system = new EnhancedSecureFileTransfer(manager);
    system.sendSecureMessage = async () => {};
    system._storeReceivedFileBuffer = () => {};
    system.calculateFileHashFromData = async () => 'hash';
    return system;
}

async function createReceivingState(fileId = 'file_1', totalChunks = 10) {
    const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 128 }, false, ['encrypt', 'decrypt']);
    return {
        fileId,
        fileName: 'report.pdf',
        fileSize: totalChunks,
        fileType: 'application/pdf',
        fileHash: 'hash',
        totalChunks,
        receivedChunks: new Map(),
        receivedCount: 0,
        sessionKey: key,
        salt: new Array(32).fill(1),
        startTime: Date.now()
    };
}

async function encryptedChunk(system, receivingState, chunkIndex) {
    const nonce = new Uint8Array(12);
    nonce[11] = chunkIndex;
    const plaintext = new Uint8Array([chunkIndex + 1]);
    const encrypted = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonce },
        receivingState.sessionKey,
        plaintext
    );
    return {
        fileId: receivingState.fileId,
        chunkIndex,
        nonce: Array.from(nonce),
        encryptedData: Array.from(new Uint8Array(encrypted)),
        chunkSize: plaintext.byteLength
    };
}

// Normal transfer pace is accepted.
{
    const system = createSystem();
    const state = await createReceivingState('normal');
    system.receivingTransfers.set(state.fileId, state);
    await system.handleFileChunk(await encryptedChunk(system, state, 0));
    assert.equal(state.receivedCount, 1);
    assert.equal(system.receivingTransfers.has(state.fileId), true);
}

// Per-transfer floods are rejected and cleaned up.
{
    const system = createSystem();
    system.MAX_INCOMING_CHUNKS_PER_TRANSFER_PER_MINUTE = 1;
    const state = await createReceivingState('per-transfer');
    system.receivingTransfers.set(state.fileId, state);
    await system.handleFileChunk(await encryptedChunk(system, state, 0));
    await system.handleFileChunk(await encryptedChunk(system, state, 1));
    assert.equal(system.receivingTransfers.has(state.fileId), false);
    assert.equal(system.incomingTransferChunkLimiters.has(state.fileId), false);
}

// Aggregate floods across transfers are rejected and clean only the affected transfer.
{
    const system = createSystem();
    system.incomingChunkLimiter.maxRequests = 1;
    const first = await createReceivingState('aggregate-a');
    const second = await createReceivingState('aggregate-b');
    system.receivingTransfers.set(first.fileId, first);
    system.receivingTransfers.set(second.fileId, second);
    await system.handleFileChunk(await encryptedChunk(system, first, 0));
    await system.handleFileChunk(await encryptedChunk(system, second, 0));
    assert.equal(system.receivingTransfers.has(first.fileId), true);
    assert.equal(system.receivingTransfers.has(second.fileId), false);
}

// Consent flow still rejects pre-acceptance chunks without allocating buffers.
{
    const system = createSystem();
    await system.handleFileChunk({ fileId: 'not-accepted', chunkIndex: 0 });
    assert.equal(system.pendingChunks.size, 0);
    assert.equal(system.incomingTransferChunkLimiters.has('not-accepted'), false);
}

console.log('File transfer chunk rate limit tests passed');
