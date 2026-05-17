import assert from 'node:assert/strict';
import { EnhancedSecureFileTransfer } from '../src/transfer/EnhancedSecureFileTransfer.js';

function createSystem() {
    const manager = {
        dataChannel: { onmessage: null, send() {}, readyState: 'open' },
        isVerified: true,
        fileTransferSystem: null,
        isConnected: () => true
    };
    return new EnhancedSecureFileTransfer(manager);
}

// cleanupTransfer rejects pending sender consent immediately and clears its timeout.
{
    const system = createSystem();
    let rejectionMessage = null;
    const timer = setTimeout(() => {}, 10_000);
    system.activeTransfers.set('file_waiting', {
        consentTimeout: timer,
        rejectConsent(error) { rejectionMessage = error.message; },
        resolveConsent() {}
    });
    system.sessionKeys.set('file_waiting', {});
    system.transferNonces.set('file_waiting', 1);

    system.cleanupTransfer('file_waiting');

    assert.equal(system.activeTransfers.has('file_waiting'), false);
    assert.equal(system.sessionKeys.has('file_waiting'), false);
    assert.equal(system.transferNonces.has('file_waiting'), false);
    assert.equal(rejectionMessage, 'Transfer cancelled during cleanup or disconnect');
    assert.equal(system.activeTransfers.size, 0);
}

// global cleanup does not leave pending consent promises alive until timeout.
{
    const system = createSystem();
    let rejected = false;
    const timer = setTimeout(() => {}, 10_000);
    system.activeTransfers.set('file_waiting', {
        consentTimeout: timer,
        rejectConsent() { rejected = true; },
        resolveConsent() {}
    });
    system.cleanup();
    assert.equal(rejected, true);
    assert.equal(system.activeTransfers.size, 0);
}

// receivedFileBuffers is bounded and evicts the oldest retained buffer.
{
    const system = createSystem();
    system.MAX_RETAINED_RECEIVED_FILE_BUFFERS = 2;
    system._storeReceivedFileBuffer('a', { buffer: new Uint8Array([1]).buffer });
    system._storeReceivedFileBuffer('b', { buffer: new Uint8Array([2]).buffer });
    system._storeReceivedFileBuffer('c', { buffer: new Uint8Array([3]).buffer });
    assert.equal(system.receivedFileBuffers.size, 2);
    assert.equal(system.receivedFileBuffers.has('a'), false);
    assert.equal(system.receivedFileBuffers.has('b'), true);
    assert.equal(system.receivedFileBuffers.has('c'), true);
}

// Evicted received buffers fail gracefully for old download closures.
{
    const system = createSystem();
    system.MAX_RETAINED_RECEIVED_FILE_BUFFERS = 1;
    let fileData = null;
    system.onFileReceived = data => { fileData = data; };
    system.calculateFileHashFromData = async () => 'hash';
    system.sendSecureMessage = async () => {};
    const receivingState = {
        fileId: 'old',
        fileName: 'old.pdf',
        fileSize: 1,
        fileType: 'application/pdf',
        fileHash: 'hash',
        totalChunks: 1,
        receivedChunks: new Map([[0, new Uint8Array([1]).buffer]]),
        startTime: Date.now()
    };
    await system.assembleFile(receivingState);
    system._storeReceivedFileBuffer('new', { buffer: new Uint8Array([2]).buffer });
    await assert.rejects(
        () => fileData.getObjectURL(),
        /no longer available for download/i
    );
}

console.log('File transfer cleanup tests passed');
