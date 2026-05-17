import assert from 'node:assert/strict';

globalThis.window = { EnhancedSecureCryptoUtils: {} };
const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

{
    const oldProgress = () => {};
    const manager = {
        fileTransferSystem: {
            onProgress: oldProgress,
            onFileReceived: oldProgress,
            onError: oldProgress,
            onIncomingFileRequest: oldProgress
        }
    };

    EnhancedSecureWebRTCManager.prototype.setFileTransferCallbacks.call(
        manager,
        null,
        null,
        null,
        null
    );

    assert.equal(manager.fileTransferSystem.onProgress, null);
    assert.equal(manager.fileTransferSystem.onFileReceived, null);
    assert.equal(manager.fileTransferSystem.onError, null);
    assert.equal(manager.fileTransferSystem.onIncomingFileRequest, null);
}

console.log('File transfer callback propagation tests passed');
