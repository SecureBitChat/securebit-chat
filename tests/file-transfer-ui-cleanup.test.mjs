import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const effects = [];
const setterCalls = [];
let stateIndex = 0;
const callbackCalls = [];

const context = {
    window: {},
    React: {
        useState(initialValue) {
            const index = stateIndex++;
            return [initialValue, value => setterCalls.push({ index, value })];
        },
        useRef(initialValue) {
            return { current: initialValue };
        },
        useEffect(effect) {
            effects.push(effect);
        },
        createElement() {
            return null;
        }
    }
};

const source = fs.readFileSync(new URL('../src/components/ui/FileTransfer.jsx', import.meta.url), 'utf8');
vm.runInNewContext(source, context);

const manager = {
    fileTransferSystem: {
        onProgress: () => {},
        onFileReceived: () => {},
        onError: () => {},
        onIncomingFileRequest: () => {}
    },
    setFileTransferCallbacks(...args) {
        callbackCalls.push(args);
        this.onFileProgress = args[0];
        this.onFileReceived = args[1];
        this.onFileError = args[2];
        this.onIncomingFileRequest = args[3];
        if (this.fileTransferSystem) {
            this.fileTransferSystem.onProgress = args[0];
            this.fileTransferSystem.onFileReceived = args[1];
            this.fileTransferSystem.onError = args[2];
            this.fileTransferSystem.onIncomingFileRequest = args[3];
        }
    },
    getFileTransfers() {
        return { sending: [], receiving: [] };
    },
    isConnected() {
        return false;
    },
    isVerified: false
};

context.window.FileTransferComponent({ webrtcManager: manager, isConnected: false });
const cleanups = effects.map(effect => effect()).filter(Boolean);

assert.ok(setterCalls.some(call => call.index === 2 && Array.isArray(call.value) && call.value.length === 0));
assert.ok(setterCalls.some(call => call.index === 3 && Array.isArray(call.value) && call.value.length === 0));
assert.ok(setterCalls.some(call => call.index === 1 && call.value.sending.length === 0 && call.value.receiving.length === 0));

cleanups.forEach(cleanup => cleanup());
assert.deepEqual(callbackCalls.at(-1), [null, null, null, null]);
assert.equal(manager.fileTransferSystem.onProgress, null);
assert.equal(manager.fileTransferSystem.onFileReceived, null);
assert.equal(manager.fileTransferSystem.onError, null);
assert.equal(manager.fileTransferSystem.onIncomingFileRequest, null);

console.log('File transfer UI cleanup tests passed');
