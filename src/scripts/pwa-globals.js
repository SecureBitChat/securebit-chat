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

// Format a version (build timestamp -> date, or pass through a semver string)
function formatUpdateVersion(v) {
  if (!v) return null;
  if (/^\d+$/.test(String(v))) {
    return new Date(parseInt(v, 10)).toLocaleString('en-US', {
      year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
    });
  }
  return String(v);
}

// Update notification — translated from the Claude Design component
// (Update Notification.dc.html). Centered modal with version comparison.
window.showUpdateNotification = function showUpdateNotification() {
  if (window.DEBUG_MODE) console.log('🆕 Showing update notification for PWA');

  // Avoid stacking duplicates if the SW fires more than once.
  const existing = document.getElementById('pwa-update-modal');
  if (existing) existing.remove();

  if (!document.getElementById('pwa-update-modal-kf')) {
    const style = document.createElement('style');
    style.id = 'pwa-update-modal-kf';
    style.textContent =
      '@keyframes unPop{from{opacity:0;transform:scale(.96) translateY(10px)}to{opacity:1;transform:scale(1) translateY(0)}}' +
      '@keyframes unFade{from{opacity:0}to{opacity:1}}' +
      '@keyframes unSpin{to{transform:rotate(360deg)}}';
    document.head.appendChild(style);
  }

  let currentVersion = null;
  try { currentVersion = localStorage.getItem('app_version'); } catch (e) {}
  const currentStr = formatUpdateVersion(currentVersion) || 'Installed build';

  const modal = document.createElement('div');
  modal.id = 'pwa-update-modal';
  modal.style.cssText = "position:fixed; inset:0; z-index:9999; display:flex; align-items:center; justify-content:center; padding:24px; background:rgba(8,8,10,0.55); backdrop-filter:blur(3px); -webkit-backdrop-filter:blur(3px); animation:unFade .3s ease; font-family:'Manrope',system-ui,-apple-system,sans-serif;";

  modal.innerHTML = `
    <div style="position:relative; width:440px; max-width:calc(100vw - 48px); border-radius:22px; background:#121214; border:1px solid rgba(255,255,255,0.08); padding:36px 32px 28px; text-align:center; box-shadow:0 30px 70px rgba(0,0,0,0.6); animation:unPop .32s cubic-bezier(.2,.7,.3,1);">
      <div style="display:inline-flex; width:64px; height:64px; border-radius:50%; align-items:center; justify-content:center; background:rgba(240,137,42,0.12); border:1px solid rgba(240,137,42,0.3); margin-bottom:20px;">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="#f0892a" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="animation:unSpin 6s linear infinite;"><path d="M21 8a8.5 8.5 0 0 0-15.6-2.5M3 4v4h4"/><path d="M3 16a8.5 8.5 0 0 0 15.6 2.5M21 20v-4h-4"/></svg>
      </div>
      <h2 style="margin:0 0 9px; font-size:26px; font-weight:800; letter-spacing:-0.7px; color:#f4f4f6;">Update available</h2>
      <p style="margin:0 0 24px; font-size:14.5px; line-height:1.55; color:#9a9aa2;">A newer version of SecureBit has been detected.</p>

      <div style="border-radius:14px; background:#0c0c0e; border:1px solid rgba(255,255,255,0.06); padding:16px 18px; margin-bottom:24px; text-align:left;">
        <div style="display:flex; align-items:center; justify-content:space-between; gap:14px; padding:5px 0;">
          <span style="font-size:13.5px; font-weight:500; color:#8a8a92;">Current version</span>
          <span class="cur-ver" style="font-family:'JetBrains Mono',ui-monospace,Menlo,monospace; font-size:13px; font-weight:500; color:#9a9aa2; white-space:nowrap;">${currentStr}</span>
        </div>
        <div style="height:1px; background:rgba(255,255,255,0.05); margin:4px 0;"></div>
        <div style="display:flex; align-items:center; justify-content:space-between; gap:14px; padding:5px 0;">
          <span style="display:inline-flex; align-items:center; gap:8px; font-size:13.5px; font-weight:600; color:#e8e8eb;"><span style="width:6px; height:6px; border-radius:50%; background:#f0892a;"></span>New version</span>
          <span class="new-ver" style="font-family:'JetBrains Mono',ui-monospace,Menlo,monospace; font-size:13px; font-weight:700; color:#f0892a; white-space:nowrap;">Latest</span>
        </div>
      </div>

      <div style="display:flex; align-items:center; gap:12px;">
        <button class="upd-now" type="button" style="flex:1; display:inline-flex; align-items:center; justify-content:center; gap:10px; padding:15px 20px; border-radius:13px; border:none; background:#f0892a; color:#1a0f04; font-family:inherit; font-size:15.5px; font-weight:700; letter-spacing:-0.2px; cursor:pointer; box-shadow:0 8px 24px rgba(240,137,42,0.28); transition:all .2s cubic-bezier(.2,.7,.3,1);">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M12 3v11"/><path d="M7.5 10.5L12 15l4.5-4.5"/><path d="M5 20h14"/></svg>
          Update now
        </button>
        <button class="upd-later" type="button" title="Later" style="flex:none; width:50px; height:50px; border-radius:13px; display:grid; place-items:center; border:1px solid rgba(255,255,255,0.1); background:rgba(255,255,255,0.025); color:#9a9aa2; cursor:pointer; transition:all .18s cubic-bezier(.2,.7,.3,1);">
          <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round" style="pointer-events:none;"><path d="M6 6l12 12M18 6L6 18"/></svg>
        </button>
      </div>
    </div>`;

  const updNow = modal.querySelector('.upd-now');
  updNow.addEventListener('mouseenter', () => { updNow.style.background = '#ff9637'; updNow.style.transform = 'translateY(-2px)'; });
  updNow.addEventListener('mouseleave', () => { updNow.style.background = '#f0892a'; updNow.style.transform = 'none'; });
  updNow.addEventListener('click', () => window.location.reload());

  const updLater = modal.querySelector('.upd-later');
  updLater.addEventListener('mouseenter', () => { updLater.style.color = '#e5727a'; updLater.style.borderColor = 'rgba(229,114,122,0.4)'; });
  updLater.addEventListener('mouseleave', () => { updLater.style.color = '#9a9aa2'; updLater.style.borderColor = 'rgba(255,255,255,0.1)'; });
  updLater.addEventListener('click', () => modal.remove());

  document.body.appendChild(modal);

  // Fill in the new version once meta.json is fetched (best-effort).
  fetch('/meta.json?t=' + Date.now(), { cache: 'no-store' })
    .then((r) => r.json())
    .then((meta) => {
      const label = meta.appVersion
        ? ('v' + meta.appVersion)
        : (formatUpdateVersion(meta.version || meta.buildVersion) || 'Latest');
      const el = modal.querySelector('.new-ver');
      if (el) el.textContent = label;
    })
    .catch(() => {});
};

window.showServiceWorkerError = function showServiceWorkerError(error) {
  console.warn('⚠️ Service Worker error:', error);
};
