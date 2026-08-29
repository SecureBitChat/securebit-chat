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

// Mount application once DOM and modules are ready
const start = () => {
    purgeLegacyOfferRecords();
  if (typeof window.initializeApp === 'function') {
    window.initializeApp();
  } else if (window.DEBUG_MODE) {
    console.error('initializeApp is not defined on window');
  }
};

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', start);
} else {
  start();
}
