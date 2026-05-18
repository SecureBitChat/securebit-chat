import assert from 'node:assert/strict';

const { installDebugWindowHooks, isSecureBitDebugEnabled } = await import('../src/utils/debugWindowHooks.js');

// Production mode does not expose debug/control globals.
{
    const targetWindow = {};
    const managerRef = { current: { disconnect() {} } };
    const cleanup = installDebugWindowHooks({
        targetWindow,
        webrtcManagerRef: managerRef,
        onClearData() {}
    });

    assert.equal(isSecureBitDebugEnabled(targetWindow), false);
    assert.equal('forceCleanup' in targetWindow, false);
    assert.equal('clearLogs' in targetWindow, false);
    assert.equal('webrtcManagerRef' in targetWindow, false);
    cleanup();
}

// Debug mode exposes hooks only when explicitly requested.
{
    let clearDataCalls = 0;
    let disconnectCalls = 0;
    let clearLogCalls = 0;
    const targetWindow = { SECUREBIT_DEBUG: true };
    const managerRef = {
        current: {
            disconnect() {
                disconnectCalls += 1;
            }
        }
    };
    const cleanup = installDebugWindowHooks({
        targetWindow,
        webrtcManagerRef: managerRef,
        onClearData() {
            clearDataCalls += 1;
        },
        clearConsole() {
            clearLogCalls += 1;
        }
    });

    assert.equal(isSecureBitDebugEnabled(targetWindow), true);
    assert.equal(targetWindow.webrtcManagerRef, managerRef);
    targetWindow.forceCleanup();
    targetWindow.clearLogs();
    assert.equal(clearDataCalls, 1);
    assert.equal(disconnectCalls, 1);
    assert.equal(clearLogCalls, 1);

    cleanup();
    assert.equal('forceCleanup' in targetWindow, false);
    assert.equal('clearLogs' in targetWindow, false);
    assert.equal('webrtcManagerRef' in targetWindow, false);
}

// Normal cleanup remains available through the app-owned callback path.
{
    let clearDataCalls = 0;
    const onClearData = () => {
        clearDataCalls += 1;
    };
    installDebugWindowHooks({
        targetWindow: {},
        webrtcManagerRef: { current: null },
        onClearData
    });
    onClearData();
    assert.equal(clearDataCalls, 1);
}

console.log('Debug window hook tests passed');
