// Global logging and function settings
window.DEBUG_MODE = true;

// Fake function settings (for stability)
window.DISABLE_FAKE_TRAFFIC = false; // Set true to disable fake messages
window.DISABLE_DECOY_CHANNELS = false; // Set true to disable decoy channels

// Enhanced icon loading fallback
document.addEventListener('DOMContentLoaded', function () {
  // Check if Font Awesome loaded properly
  function checkFontAwesome() {
    const testIcon = document.createElement('i');
    testIcon.className = 'fas fa-shield-halved';
    testIcon.style.position = 'absolute';
    testIcon.style.left = '-9999px';
    testIcon.style.visibility = 'hidden';
    document.body.appendChild(testIcon);

    const computedStyle = window.getComputedStyle(testIcon, '::before');
    const content = computedStyle.content;
    const fontFamily = computedStyle.fontFamily;

    document.body.removeChild(testIcon);

    if (!content || content === 'none' || content === 'normal' || (!fontFamily.includes('Font Awesome') && !fontFamily.includes('fa-solid'))) {
      console.warn('Font Awesome not loaded properly, using fallback icons');
      document.body.classList.add('fa-fallback');
      return false;
    }

    if (window.DEBUG_MODE) {
      console.log('Font Awesome loaded successfully');
    }
    return true;
  }

  if (!checkFontAwesome()) {
    setTimeout(function () {
      if (!checkFontAwesome()) {
        console.warn('Font Awesome still not loaded, using fallback icons');
        document.body.classList.add('fa-fallback');
      }
    }, 2000);
  }
});


