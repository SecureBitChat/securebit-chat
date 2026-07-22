// Loads non-render-critical stylesheets asynchronously so they don't block first
// paint. This runs from a deferred <script> (after the document is parsed), and only
// appends <link rel="stylesheet"> elements — no inline event handlers — so it stays
// within the page CSP (script-src 'self', style-src 'self' 'unsafe-inline').
//
// Deferred here (decorative / non-layout, not needed for the initial paint):
//   - FontAwesome (~102KB): icon glyphs. Their webfonts are still <link rel=preload>ed
//     in index.html, so they download in parallel and apply as soon as this CSS lands.
//   - Prism (tiny): syntax-highlighting theme, only used inside code blocks in chat.
(function () {
  var sheets = [
    '/assets/fontawesome/css/all.min.css',
    '/libs/prism/prism.css'
  ];
  for (var i = 0; i < sheets.length; i++) {
    var link = document.createElement('link');
    link.rel = 'stylesheet';
    link.href = sheets[i];
    document.head.appendChild(link);
  }
})();
