// Bootstrap that loads modules using dynamic ESM imports.
// This approach is CSP-compliant and doesn't use eval().
(async () => {
  try {
    const timestamp = Date.now();
    const [cryptoModule, webrtcModule, fileTransferModule] = await Promise.all([
      import(`../crypto/EnhancedSecureCryptoUtils.js?v=${timestamp}`),
      import(`../network/EnhancedSecureWebRTCManager.js?v=${timestamp}`),
      import(`../transfer/EnhancedSecureFileTransfer.js?v=${timestamp}`),
    ]);

    const { EnhancedSecureCryptoUtils } = cryptoModule;
    window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
    const { EnhancedSecureWebRTCManager } = webrtcModule;
    window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
    const { EnhancedSecureFileTransfer } = fileTransferModule;
    window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;

    // Load React components using dynamic imports instead of eval
    const componentModules = await Promise.all([
      import(`../components/ui/Header.jsx?v=${timestamp}`),
      import(`../components/ui/DownloadApps.jsx?v=${timestamp}`),
      import(`../components/ui/ComparisonTable.jsx?v=${timestamp}`),
      import(`../components/ui/UniqueFeatureSlider.jsx?v=${timestamp}`),
      import(`../components/ui/SecurityFeatures.jsx?v=${timestamp}`),
      import(`../components/ui/Testimonials.jsx?v=${timestamp}`),
      import(`../components/ui/Roadmap.jsx?v=${timestamp}`),
      import(`../components/ui/FileTransfer.jsx?v=${timestamp}`),
    ]);

    // Components are automatically registered on window by their respective modules
    console.log('✅ All React components loaded successfully');

    if (typeof window.initializeApp === 'function') {
      window.initializeApp();
    } else {
      console.error('❌ Function initializeApp not found');
    }
  } catch (error) {
    console.error('❌ Module loading error:', error);
  }
})();


