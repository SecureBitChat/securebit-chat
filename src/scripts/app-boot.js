import { EnhancedSecureCryptoUtils } from '../crypto/EnhancedSecureCryptoUtils.js';
import { EnhancedSecureWebRTCManager } from '../network/EnhancedSecureWebRTCManager.js';
import { PayPerSessionManager } from '../session/PayPerSessionManager.js';
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';

// Import UI components (side-effect: they attach themselves to window.*)
import '../components/ui/SessionTimer.jsx';
import '../components/ui/Header.jsx';
import '../components/ui/SessionTypeSelector.jsx';
import '../components/ui/LightningPayment.jsx';
import '../components/ui/PaymentModal.jsx';
import '../components/ui/DownloadApps.jsx';
import '../components/ui/FileTransfer.jsx';

// Expose to global for legacy usage inside app code
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
window.PayPerSessionManager = PayPerSessionManager;
window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;

// Mount application once DOM and modules are ready
const start = () => {
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
