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

// Allowed files (canonical MIME types)
assert.equal(system.validateFile(file('photo.png', 'image/png')).isValid, true);
assert.equal(system.validateFile(file('report.pdf', 'application/pdf')).isValid, true);
assert.equal(system.validateFile(file('notes.txt', 'text/plain')).isValid, true);
assert.equal(system.validateFile(file('bundle.zip', 'application/zip')).isValid, true);

// MIME is advisory: a safe extension is accepted when the MIME is missing,
// generic, or a cross-OS/browser variant of an allowed type.
assert.equal(system.validateFile(file('photo.png', '')).isValid, true);
assert.equal(system.validateFile(file('photo.png', 'application/octet-stream')).isValid, true);
assert.equal(system.validateFile(file('photo.jpg', 'image/jpg')).isValid, true);
assert.equal(system.validateFile(file('bundle.zip', 'application/x-zip-compressed')).isValid, true);

// Explicitly blocked extensions are always rejected, whatever the MIME claims.
for (const name of ['run.exe', 'boot.bat', 'shell.sh', 'payload.js', 'page.html', 'vector.svg']) {
    assert.equal(system.validateFile(file(name, 'application/octet-stream')).isValid, false, name);
}

// Spoofing is still blocked: a blatantly foreign MIME on a safe extension is
// rejected, and an unsafe extension with a safe MIME is rejected.
assert.equal(system.validateFile(file('photo.png', 'application/x-msdownload')).isValid, false);
assert.equal(system.validateFile(file('payload.exe', 'image/png')).isValid, false);

// Unsupported (but not dangerous) extensions are rejected even with empty MIME.
assert.equal(system.validateFile(file('movie.mp4', 'video/mp4')).isValid, false);
assert.equal(system.validateFile(file('archive.rar', '')).isValid, false);

// Uppercase extension bypass is blocked.
assert.equal(system.validateFile(file('PAYLOAD.EXE', 'application/octet-stream')).isValid, false);

console.log('File type allowlist tests passed');
