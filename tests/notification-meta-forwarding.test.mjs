import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

// NotificationIntegration wraps webrtcManager.onMessage and .deliverMessageToUI.
// Regression: those wrappers must forward the 3rd argument (per-message `meta`)
// to the originals, otherwise view-once / disappearing / unsend break ONLY when
// notifications are enabled (which is exactly how it shipped broken).

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
// Minimal Notification stub so init() does not throw.
globalThis.Notification = dom.window.Notification = class { static permission = 'granted'; static requestPermission() { return Promise.resolve('granted'); } close() {} };

await import('../src/notifications/NotificationIntegration.js');
const NotificationIntegration = window.NotificationIntegration;

const received = [];
const delivered = [];
const manager = {
    onMessage: (message, type, meta) => received.push({ message, type, meta }),
    onStatusChange: () => {},
    deliverMessageToUI: (message, type, meta) => delivered.push({ message, type, meta })
};

const integration = new NotificationIntegration(manager);
await integration.init();

// After init, the manager's callbacks are the wrappers. Calling them with meta
// must forward meta to the originals.
manager.onMessage('hi', 'received', { mid: 'm1', once: true });
manager.deliverMessageToUI('yo', 'received', { mid: 'm2', ttl: 30 });

assert.equal(received.length, 1, 'original onMessage called once');
assert.deepEqual(received[0].meta, { mid: 'm1', once: true }, 'meta forwarded through onMessage wrapper');

assert.equal(delivered.length, 1, 'original deliverMessageToUI called once');
assert.deepEqual(delivered[0].meta, { mid: 'm2', ttl: 30 }, 'meta forwarded through deliverMessageToUI wrapper');

console.log('Notification meta-forwarding tests passed');
