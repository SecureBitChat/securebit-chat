import { EnhancedSecureCryptoUtils } from '../crypto/EnhancedSecureCryptoUtils.js';
import { EnhancedSecureWebRTCManager } from '../network/EnhancedSecureWebRTCManager.js';
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';
import { NotificationIntegration } from '../notifications/NotificationIntegration.js';

// Import UI components (side-effect: they attach themselves to window.*)
import '../components/ui/Header.jsx';
import '../components/ui/LanguageSwitcher.jsx';
import '../components/ui/DownloadApps.jsx';
import '../components/ui/BecomePartner.jsx';
import '../components/ui/UniqueFeatureSlider.jsx';
import '../components/ui/Roadmap.jsx';
import '../components/ui/CommunityCTA.jsx';
import '../components/ui/FileTransfer.jsx';
import '../components/ui/IceServerSettings.jsx';
import '../components/ui/CallUI.jsx';

// Expose to global for legacy usage inside app code
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;
window.NotificationIntegration = NotificationIntegration;

// Earlier releases had an unused QR flow that persisted session invitation data
// under `qr_offer_<id>` and never removed it. The writer is gone, but records it
// already left on disk are not, and they outlive a disconnect and the in-app
// "clear data". Purge them once on startup, so updating actually clears what was
// stored rather than only stopping new entries.
const purgeLegacyOfferRecords = () => {
    try {
        const stale = [];
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key && key.startsWith('qr_offer_')) stale.push(key);
        }
        for (const key of stale) {
            try { localStorage.removeItem(key); } catch (_) {}
        }
    } catch (_) {
        // Private mode / disabled storage: nothing to purge.
    }
};

/**
 * QR generation and scanning live in their own bundle — 142 KB gzipped, the third
 * largest thing this site serves. It used to be a <script type="module"> in <head>,
 * which meant every first visit paid for it before the app was interactive, on a
 * screen that has no QR on it: the scanner only exists behind a button, and the
 * generator only runs once a channel is being created.
 *
 * So it is fetched after the app has mounted and the browser is idle. Every call site
 * already checks `typeof window.<fn> === 'function'` before using it, so arriving late
 * is not an error condition — but the scanner effect in app.jsx keys off this event to
 * start the camera for anyone who opened the modal in the meantime.
 */
const loadQrBundle = () => {
    if (window.__qrReady) return window.__qrReady;
    window.__qrReady = import('/dist/qr-local.js')
        .then(() => {
            window.dispatchEvent(new Event('securebit:qr-ready'));
        })
        .catch((error) => {
            console.warn('QR bundle failed to load:', error && error.message);
            // Let a later attempt retry rather than caching the rejection forever.
            window.__qrReady = null;
        });
    return window.__qrReady;
};

const scheduleQrBundle = () => {
    if (typeof window.requestIdleCallback === 'function') {
        window.requestIdleCallback(loadQrBundle, { timeout: 3000 });
    } else {
        setTimeout(loadQrBundle, 1200);
    }
};

// Mount application once DOM and modules are ready
const start = () => {
    purgeLegacyOfferRecords();
  if (typeof window.initializeApp === 'function') {
    window.initializeApp();
  } else if (window.DEBUG_MODE) {
    console.error('initializeApp is not defined on window');
  }
  scheduleQrBundle();
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
