import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const { window } = new JSDOM('<!doctype html><html><body></body></html>', {
    url: 'http://localhost/'
});
globalThis.window = window;

const { EnhancedSecureCryptoUtils } = await import('../src/crypto/EnhancedSecureCryptoUtils.js');
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
const { EnhancedSecureWebRTCManager } = await import('../src/network/EnhancedSecureWebRTCManager.js');

const P = EnhancedSecureWebRTCManager.prototype;

function ctx() {
    return {
        _inputValidationLimits: {
            maxStringLength: 10000,
            maxObjectDepth: 10,
            maxArrayLength: 1000,
            maxMessageSize: 1_000_000
        },
        _secureLog() {},
        _sanitizeInputString: P._sanitizeInputString,
        _sanitizeInputObject: P._sanitizeInputObject
    };
}

function validate(input) {
    return P._validateInputData.call(ctx(), input, 'sendSecureMessage');
}

// Legitimate plain-text messages that the old keyword blocklist rejected must
// now be accepted unchanged. The real XSS boundary is the receive-side
// DOMPurify pass, not a guess-the-keyword filter on outgoing content.
for (const msg of [
    'the constructor pattern is great',
    'global warming is real',
    'I will fetch (groceries) later',
    'see document.pdf and check window.location',
    'javascript: is harmless as plain text',
    'discussing <script> tags and prototype chains',
    'localStorage vs sessionStorage tradeoffs'
]) {
    const r = validate(msg);
    assert.equal(r.isValid, true, `should accept: ${msg}`);
    assert.equal(r.sanitizedData, msg, `should not mangle: ${msg}`);
}

// Multi-line content and indentation must survive (previously collapsed to one
// line by replace(/\s+/g, ' ')).
{
    const multiline = 'line one\nline two\nline three';
    const r = validate(multiline);
    assert.equal(r.isValid, true);
    assert.equal(r.sanitizedData, multiline, 'newlines must be preserved');
}
{
    const code = 'function f() {\n    return 42;\n}';
    const r = validate(code);
    assert.equal(r.isValid, true);
    assert.equal(r.sanitizedData, code, 'code indentation must be preserved');
}

// Control characters (null byte, bell, etc.) are still stripped, while tabs and
// newlines are kept.
{
    const r = validate('a\u0000b\u0007c\td\ne');
    assert.equal(r.isValid, true);
    assert.equal(r.sanitizedData, 'abc\td\ne', 'control chars stripped, tab/newline kept');
}

// Excessive blank lines are collapsed but content stays intact.
{
    const r = validate('top\n\n\n\n\nbottom');
    assert.equal(r.isValid, true);
    assert.equal(r.sanitizedData, 'top\n\nbottom', '3+ blank lines collapse to two');
}

// Oversized input is still rejected (availability / DoS guard intact).
{
    const huge = 'a'.repeat(10001);
    const r = validate(huge);
    assert.equal(r.isValid, false, 'over-limit strings are rejected');
}

console.log('Outgoing message integrity tests passed');
