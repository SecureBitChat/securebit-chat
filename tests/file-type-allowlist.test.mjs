import assert from 'node:assert/strict';
import { EnhancedSecureFileTransfer } from '../src/transfer/EnhancedSecureFileTransfer.js';

function createSystem() {
    const manager = {
        dataChannel: { onmessage: null, send() {}, readyState: 'open' },
        isVerified: true,
        fileTransferSystem: null,
        isConnected: () => true
    };
    return new EnhancedSecureFileTransfer(manager, null, null, null, null, null);
}

function file(name, type, size = 1024) {
    return { name, type, size };
}

const system = createSystem();

// Allowed files
assert.equal(system.validateFile(file('photo.png', 'image/png')).isValid, true);
assert.equal(system.validateFile(file('report.pdf', 'application/pdf')).isValid, true);
assert.equal(system.validateFile(file('notes.txt', 'text/plain')).isValid, true);
assert.equal(system.validateFile(file('bundle.zip', 'application/zip')).isValid, true);

// Explicitly blocked extensions
for (const name of ['run.exe', 'boot.bat', 'shell.sh', 'payload.js', 'page.html', 'vector.svg']) {
    assert.equal(system.validateFile(file(name, 'application/octet-stream')).isValid, false, name);
}

// MIME spoofing: safe extension with unsafe MIME and unsafe extension with safe MIME are blocked.
assert.equal(system.validateFile(file('photo.png', 'application/x-msdownload')).isValid, false);
assert.equal(system.validateFile(file('payload.exe', 'image/png')).isValid, false);

// Missing MIME is unsafe.
assert.equal(system.validateFile(file('photo.png', '')).isValid, false);

// Uppercase extension bypass is blocked.
assert.equal(system.validateFile(file('PAYLOAD.EXE', 'application/octet-stream')).isValid, false);

console.log('File type allowlist tests passed');
