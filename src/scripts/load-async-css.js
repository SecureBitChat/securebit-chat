// Loads non-render-critical stylesheets asynchronously so they don't block first
// paint. This runs from a deferred <script> (after the document is parsed), and only
// appends <link rel="stylesheet"> elements — no inline event handlers — so it stays
// within the page CSP (script-src 'self', style-src 'self' 'unsafe-inline').
//
// Deferred here (decorative / non-layout, not needed for the initial paint):
//   - Prism (tiny): syntax-highlighting theme, only used inside code blocks in chat.
//
// FontAwesome used to be the reason this file existed: 102 KB of stylesheet for 2468
// icons, of which the interface draws 82. Subset to those, it is 7 KB and rides in the
// main bundle instead, so the icons are styled from the first paint rather than a beat
// after it. See scripts/subset-icons.py.
(function () {
  var sheets = [
    '/libs/prism/prism.css'
  ];
  for (var i = 0; i < sheets.length; i++) {
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = sheets[i];
    document.head.appendChild(link);
  }
})();
