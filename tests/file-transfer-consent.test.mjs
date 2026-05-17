import assert from 'node:assert/strict';
import { EnhancedSecureFileTransfer } from '../src/transfer/EnhancedSecureFileTransfer.js';

function createSystem(onIncomingFileRequest = () => {}) {
    const manager = {
        dataChannel: { onmessage: null, send() {}, readyState: 'open' },
        isVerified: true,
        fileTransferSystem: null,
        isConnected: () => true
    };
    const system = new EnhancedSecureFileTransfer(manager, null, null, null, null, onIncomingFileRequest);
    system.sendSecureMessage = async () => {};
    return system;
}

function validMetadata(overrides = {}) {
    return {
        type: 'file_transfer_start',
        fileId: 'file_1',
        fileName: 'report.pdf',
        fileSize: 1024,
        fileType: 'application/pdf',
        fileHash: 'abc',
        totalChunks: 1,
        chunkSize: 1024,
        salt: new Array(32).fill(1),
        ...overrides
    };
}

// Metadata is validated before a consent prompt is shown.
{
    const system = createSystem();
    assert.equal(system.validateIncomingMetadata(validMetadata()).isValid, true);
    assert.equal(system.validateIncomingMetadata(validMetadata({ fileName: '../evil.pdf' })).isValid, false);
    assert.equal(system.validateIncomingMetadata(validMetadata({ fileSize: 200 * 1024 * 1024 })).isValid, false);
}

// No receiving state or chunk buffers are allocated before explicit acceptance.
{
    let prompted = null;
    const system = createSystem(request => { prompted = request; });
    await system.handleFileTransferStart(validMetadata());
    assert.equal(prompted.fileName, 'report.pdf');
    assert.equal(system.pendingIncomingTransfers.size, 1);
    assert.equal(system.receivingTransfers.size, 0);

    await system.handleFileChunk({ fileId: 'file_1', chunkIndex: 0 });
    assert.equal(system.pendingChunks.size, 0);
}

// Incoming request spam is bounded.
{
    const system = createSystem();
    for (let index = 0; index < system.MAX_PENDING_INCOMING_TRANSFERS; index += 1) {
        await system.handleFileTransferStart(validMetadata({ fileId: `file_${index}` }));
    }
    await system.handleFileTransferStart(validMetadata({ fileId: 'file_overflow' }));
    assert.equal(system.pendingIncomingTransfers.size, system.MAX_PENDING_INCOMING_TRANSFERS);
}

console.log('File transfer consent tests passed');
