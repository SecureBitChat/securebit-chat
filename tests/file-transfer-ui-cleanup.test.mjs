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

// Component no longer manages callbacks — consent is handled by the parent (app.jsx).
// pendingIncomingFiles and onIncomingDecision are passed as props.
context.window.FileTransferComponent({ webrtcManager: manager, isConnected: false, pendingIncomingFiles: [], onIncomingDecision: null });
const cleanups = effects.map(effect => effect()).filter(Boolean);

// State index 0 = dragOver, index 1 = transfers.
// Transfers state should be reset to empty on disconnect.
assert.ok(setterCalls.some(call => call.index === 1 && call.value.sending.length === 0 && call.value.receiving.length === 0));

// Component must NOT call setFileTransferCallbacks — that is the parent's responsibility.
assert.equal(callbackCalls.length, 0, 'FileTransferComponent must not register its own callbacks');

// Cleanup effects must not null-out the manager's callbacks either.
cleanups.forEach(cleanup => cleanup());
assert.equal(callbackCalls.length, 0, 'cleanup must not call setFileTransferCallbacks');

// fileTransferSystem callbacks are untouched by the component.
assert.equal(typeof manager.fileTransferSystem.onProgress, 'function');
assert.equal(typeof manager.fileTransferSystem.onFileReceived, 'function');
assert.equal(typeof manager.fileTransferSystem.onError, 'function');
assert.equal(typeof manager.fileTransferSystem.onIncomingFileRequest, 'function');

console.log('File transfer UI cleanup tests passed');
