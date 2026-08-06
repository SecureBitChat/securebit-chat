// A view-once or disappearing message must never have its text handed to the
// operating system. Notifications only fire while the tab is backgrounded — so
// in practice onto a lock screen — and once the OS holds the text it persists in
// the notification centre, in device backups and on the user's other synced
// devices, where the app can no longer delete it. The message the UI destroys
// after 30 seconds would outlive itself indefinitely.

import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://localhost/' });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
globalThis.Notification = dom.window.Notification = class {
    static permission = 'granted';
    static requestPermission() { return Promise.resolve('granted'); }
    close() {}
};

await import('../src/notifications/NotificationIntegration.js');
const NotificationIntegration = window.NotificationIntegration;

const SECRET = 'the account password is hunter2';

const setup = async () => {
    const manager = {
        onMessage: () => {},
        onStatusChange: () => {},
        deliverMessageToUI: () => {}
    };
    const integration = new NotificationIntegration(manager);
    await integration.init();

    const notified = [];
    integration.notificationManager.notify = (senderName, text, options) => {
        notified.push({ senderName, text, options });
        return true;
    };
    // The real manager suppresses notifications while the tab is focused; these
    // assertions are about what it is ASKED to show, so bypass that.
    integration.notificationManager.isTabActive = false;
    return { manager, integration, notified };
};

// ── ephemeral messages: the OS learns that something arrived, not what ───────
for (const [label, meta] of [
    ['view-once', { mid: 'm1', once: true, onceTtl: 15 }],
    ['disappearing', { mid: 'm2', ttl: 30 }],
    ['both', { mid: 'm3', once: true, onceTtl: 15, ttl: 30 }]
]) {
    const { manager, notified } = await setup();
    manager.onMessage(SECRET, 'received', meta);

    assert.equal(notified.length, 1, `${label}: a notification must still be shown`);
    assert.equal(
        notified[0].text.includes('hunter2'), false,
        `${label}: the message text must not reach the OS notification`
    );
    assert.ok(notified[0].text.length > 0, `${label}: but the user must still be told something arrived`);
}

// ── ordinary messages keep their preview ─────────────────────────────────────
// Suppressing everything would be the easy fix and the wrong one: it would make
// notifications useless and invite someone to revert this.
{
    const { manager, notified } = await setup();
    manager.onMessage(SECRET, 'received', { mid: 'm4', ts: Date.now() });
    assert.equal(notified.length, 1);
    assert.ok(notified[0].text.includes('hunter2'), 'a normal message keeps its preview');
}

// ── a message with no meta at all is treated as ordinary ─────────────────────
{
    const { manager, notified } = await setup();
    manager.onMessage(SECRET, 'received');
    assert.equal(notified.length, 1);
    assert.ok(notified[0].text.includes('hunter2'));
}

// ── the deliverMessageToUI wrapper must apply the same rule ──────────────────
// It is a second, independent entry point into the same notification path; the
// original bug existed on both.
{
    const { manager, notified } = await setup();
    manager.deliverMessageToUI(SECRET, 'received', { mid: 'm5', once: true });
    assert.equal(notified.length, 1);
    assert.equal(notified[0].text.includes('hunter2'), false,
        'deliverMessageToUI must suppress ephemeral previews too');
}

console.log('notification-ephemeral-privacy.test.mjs: all assertions passed');
