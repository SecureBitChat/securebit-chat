window.forceUpdateHeader = () => {
  const event = new CustomEvent('force-header-update', {
    detail: { timestamp: Date.now() },
  });
  document.dispatchEvent(event);
};

document.addEventListener('session-activated', (event) => {
  if (window.forceUpdateHeader) {
    window.forceUpdateHeader();
  }
  if (window.webrtcManager && window.webrtcManager.handleSessionActivation) {
    if (window.DEBUG_MODE) {
      console.log('🔐 Notifying WebRTC Manager about session activation');
    }
    window.webrtcManager.handleSessionActivation({
      sessionId: event.detail.sessionId,
      sessionManager: window.sessionManager,
    });
  }
});

if (window.DEBUG_MODE) {
  console.log('✅ Global timer management functions loaded');
}

// Inline onclick replacement for update notification button
function attachUpdateNotificationHandlers(container) {
  const btn = container.querySelector('[data-action="reload"]');
  if (btn) {
    btn.addEventListener('click', () => window.location.reload());
  }
  const dismissBtn = container.querySelector('[data-action="dismiss-notification"]');
  if (dismissBtn) {
    dismissBtn.addEventListener('click', () => {
      const host = dismissBtn.closest('div');
      if (host && host.parentElement) host.parentElement.remove();
    });
  }
}

window.showUpdateNotification = function showUpdateNotification() {
  if (window.DEBUG_MODE) console.log('🆕 Showing update notification for PWA');
  const notification = document.createElement('div');
  notification.className = 'fixed top-4 left-1/2 transform -translate-x-1/2 bg-blue-500 text-white p-4 rounded-lg shadow-lg z-50 max-w-sm';
  notification.innerHTML = `
        <div class="flex items-center space-x-3">
            <i class="fas fa-download text-lg"></i>
            <div class="flex-1">
                <div class="font-medium">Update Available</div>
                <div class="text-sm opacity-90">SecureBit.chat v4.4.18 - ECDH + DTLS + SAS is ready</div>
            </div>
            <button data-action="reload" class="bg-white/20 hover:bg-white/30 px-3 py-1 rounded text-sm font-medium transition-colors">
                Update
            </button>
        </div>`;
  document.body.appendChild(notification);
  attachUpdateNotificationHandlers(notification);
  setTimeout(() => {
    if (notification.parentElement) notification.remove();
  }, 30000);
};

window.showServiceWorkerError = function showServiceWorkerError(error) {
  console.warn('⚠️ Service Worker error:', error);
};
