function isSecureBitDebugEnabled(targetWindow = globalThis.window) {
    return targetWindow?.SECUREBIT_DEBUG === true;
}

function installDebugWindowHooks({
    targetWindow = globalThis.window,
    webrtcManagerRef,
    onClearData,
    clearConsole = () => {
        if (typeof console.clear === 'function') {
            console.clear();
        }
    }
}) {
    if (!isSecureBitDebugEnabled(targetWindow)) {
        return () => {};
    }

    targetWindow.forceCleanup = () => {
        onClearData();
        if (webrtcManagerRef.current) {
            webrtcManagerRef.current.disconnect();
        }
    };
    targetWindow.clearLogs = clearConsole;
    targetWindow.webrtcManagerRef = webrtcManagerRef;

    return () => {
        delete targetWindow.forceCleanup;
        delete targetWindow.clearLogs;
        delete targetWindow.webrtcManagerRef;
    };
}

export { installDebugWindowHooks, isSecureBitDebugEnabled };
