// PWA Service Worker Registration
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      const registration = await navigator.serviceWorker.register('./sw.js', {
        scope: './',
      });

      console.log('✅ PWA: Service Worker registered successfully');
      console.log('📡 SW Scope:', registration.scope);

      // Store registration for use in other modules
      window.swRegistration = registration;

      // Listen for updates
      registration.addEventListener('updatefound', () => {
        console.log('🔄 PWA: Service Worker update found');
        const newWorker = registration.installing;

        newWorker.addEventListener('statechange', () => {
          if (newWorker.state === 'installed' && navigator.serviceWorker.controller) {
            console.log('🆕 PWA: New version available');

            const isPWAInstalled =
              window.matchMedia('(display-mode: standalone)').matches ||
              window.navigator.standalone === true ||
              (window.pwaInstallPrompt && window.pwaInstallPrompt.isInstalled);

            if (isPWAInstalled) {
              // If this is PWA, show update notification
              if (typeof window.showUpdateNotification === 'function') {
                window.showUpdateNotification();
              }
            } else {
              // If this is browser, show install prompt
              if (window.pwaInstallPrompt && !window.pwaInstallPrompt.isInstalled) {
                setTimeout(() => {
                  window.pwaInstallPrompt.showInstallOptions();
                }, 2000);
              }
            }
          }
        });
      });
    } catch (error) {
      console.error('❌ PWA: Service Worker registration failed:', error);
      if (window.DEBUG_MODE) {
        setTimeout(() => {
          if (typeof window.showServiceWorkerError === 'function') {
            window.showServiceWorkerError(error);
          }
        }, 2000);
      }
    }
  });
}

if ('serviceWorker' in navigator) {
  navigator.serviceWorker.ready.then((registration) => {
    console.log('🎯 PWA: Service Worker ready');

    const isPWAInstalled =
      window.matchMedia('(display-mode: standalone)').matches ||
      window.navigator.standalone === true;

    console.log('🔍 PWA Installation Status:', {
      isStandalone: isPWAInstalled,
      displayMode: window.matchMedia('(display-mode: standalone)').matches,
      iosStandalone: window.navigator.standalone === true,
    });

    if (window.pwaInstallPrompt && window.pwaInstallPrompt.setServiceWorkerRegistration) {
      window.pwaInstallPrompt.setServiceWorkerRegistration(registration);
      if (isPWAInstalled && !window.pwaInstallPrompt.isInstalled) {
        console.log('✅ PWA already installed, updating status');
        window.pwaInstallPrompt.isInstalled = true;
        window.pwaInstallPrompt.hideInstallPrompts();
      }
    }

    if (window.pwaOfflineManager && window.pwaOfflineManager.setServiceWorkerRegistration) {
      window.pwaOfflineManager.setServiceWorkerRegistration(registration);
    }
  });

  // Listen to Service Worker messages
  navigator.serviceWorker.addEventListener('message', (event) => {
    console.log('📨 Message from Service Worker:', event.data);
    if (event.data && event.data.type === 'SW_ACTIVATED') {
      console.log('🔄 Service Worker activated, checking for updates...');

      const isPWAInstalled =
        window.matchMedia('(display-mode: standalone)').matches ||
        window.navigator.standalone === true ||
        (window.pwaInstallPrompt && window.pwaInstallPrompt.isInstalled);

      if (isPWAInstalled) {
        setTimeout(() => {
          if (typeof window.showUpdateNotification === 'function') {
            window.showUpdateNotification();
          }
        }, 1000);
      } else {
        if (window.pwaInstallPrompt && !window.pwaInstallPrompt.isInstalled) {
          setTimeout(() => {
            window.pwaInstallPrompt.showInstallOptions();
          }, 2000);
        }
      }
    }
  });
}
