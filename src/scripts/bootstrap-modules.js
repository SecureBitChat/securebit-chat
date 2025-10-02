// Temporary bootstrap that still uses eval for JSX components fetched as text.
// Next step is to replace this with proper ESM imports of prebuilt JS.
(async () => {
  try {
    const timestamp = Date.now();
    const [cryptoModule, webrtcModule, paymentModule, fileTransferModule] = await Promise.all([
      import(`../crypto/EnhancedSecureCryptoUtils.js?v=${timestamp}`),
      import(`../network/EnhancedSecureWebRTCManager.js?v=${timestamp}`),
      import(`../session/PayPerSessionManager.js?v=${timestamp}`),
      import(`../transfer/EnhancedSecureFileTransfer.js?v=${timestamp}`),
    ]);

    const { EnhancedSecureCryptoUtils } = cryptoModule;
    window.EnhancedSecureCryptoUtils = EnhancedSecureCryptoUtils;
    const { EnhancedSecureWebRTCManager } = webrtcModule;
    window.EnhancedSecureWebRTCManager = EnhancedSecureWebRTCManager;
    const { PayPerSessionManager } = paymentModule;
    window.PayPerSessionManager = PayPerSessionManager;
    const { EnhancedSecureFileTransfer } = fileTransferModule;
    window.EnhancedSecureFileTransfer = EnhancedSecureFileTransfer;

    async function loadReactComponent(path) {
      const response = await fetch(`${path}?v=${timestamp}`);
      if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      const code = await response.text();
      // eslint-disable-next-line no-eval
      eval(code);
    }

    await Promise.all([
      loadReactComponent('../components/ui/SessionTimer.jsx'),
      loadReactComponent('../components/ui/Header.jsx'),
      loadReactComponent('../components/ui/SessionTypeSelector.jsx'),
      loadReactComponent('../components/ui/LightningPayment.jsx'),
      loadReactComponent('../components/ui/PaymentModal.jsx'),
      loadReactComponent('../components/ui/DownloadApps.jsx'),
      loadReactComponent('../components/ui/ComparisonTable.jsx'),
      loadReactComponent('../components/ui/UniqueFeatureSlider.jsx'),
      loadReactComponent('../components/ui/SecurityFeatures.jsx'),
      loadReactComponent('../components/ui/Testimonials.jsx'),
      loadReactComponent('../components/ui/Roadmap.jsx'),
      loadReactComponent('../components/ui/FileTransfer.jsx'),
    ]);

    if (typeof window.initializeApp === 'function') {
      window.initializeApp();
    } else {
      console.error('❌ Function initializeApp not found');
    }
  } catch (error) {
    console.error('❌ Module loading error:', error);
  }
})();


