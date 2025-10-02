import { EnhancedSecureCryptoUtils } from '../crypto/EnhancedSecureCryptoUtils.js';
import { EnhancedSecureWebRTCManager } from '../network/EnhancedSecureWebRTCManager.js';
import { EnhancedSecureFileTransfer } from '../transfer/EnhancedSecureFileTransfer.js';

// Import UI components (side-effect: they attach themselves to window.*)
import '../components/ui/SessionTimer.jsx';
import '../components/ui/Header.jsx';
import '../components/ui/DownloadApps.jsx';
import '../components/ui/UniqueFeatureSlider.jsx';
import '../components/ui/SecurityFeatures.jsx';
import '../components/ui/Testimonials.jsx';
import '../components/ui/ComparisonTable.jsx';
import '../components/ui/Roadmap.jsx';
import '../components/ui/FileTransfer.jsx';

// Expose to global for legacy usage inside app code
window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
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
