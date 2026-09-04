// The theme has to be decided before the first pixel, not after React mounts.
//
// A stylesheet cannot read localStorage, so the stored preference can only be applied
// by script — and if that script runs late, the page paints in the default (dark) and
// then repaints, which is the white/black flash every themed site is judged on. So this
// is a classic, blocking <script> in <head>, ahead of the stylesheet: it stamps
// data-theme on <html> while the parser is still inside <head>, and the CSS that
// arrives afterwards is matched against the right selector on the very first paint.
//
// It cannot be inline — the page's CSP is `script-src 'self'` with no hash or nonce —
// and it deliberately does not import anything, because a module is deferred and
// deferred is too late. Everything it needs is in this file.
//
// Three settings, not two. "system" is the default and means: follow the OS, and keep
// following it if the OS changes while the page is open. "light" and "dark" are the
// user overriding that, which is why the resolved value is stamped as data-theme rather
// than leaving CSS to answer prefers-color-scheme itself — a media query cannot be
// overridden by a preference, and someone who wants a light page on a dark laptop is
// exactly who a theme switch is for.
(function () {
    if (window.SecureBitTheme) return;

    var STORAGE_KEY = 'securebit-theme';
    var MODES = ['system', 'light', 'dark'];
    // Kept in step with --sb-bg in src/styles/theme.css. This paints the browser UI
    // around the page (Android's address bar, the iOS status bar area in a PWA), and a
    // dark strip above a light page is more obviously wrong than a slightly-off shade.
    var BAR_COLOR = { dark: '#0f0f11', light: '#f6f7f8' };

    var root = document.documentElement;
    var listeners = [];
    var query = null;

    try {
        query = window.matchMedia ? window.matchMedia('(prefers-color-scheme: light)') : null;
    } catch (e) {
        query = null;
    }

    // Storage throws rather than returning null in a few real situations — Safari in
    // private browsing, and any browser set to block site data — and a theme is not
    // worth breaking the page's first paint over.
    function readStored() {
        try {
            var value = window.localStorage.getItem(STORAGE_KEY);
            return MODES.indexOf(value) === -1 ? 'system' : value;
        } catch (e) {
            return 'system';
        }
    }

    function writeStored(mode) {
        try {
            window.localStorage.setItem(STORAGE_KEY, mode);
        } catch (e) {
            /* preference is not persisted; the session still honours it */
        }
    }

    var mode = readStored();

    function resolve(m) {
        if (m === 'light' || m === 'dark') return m;
        return query && query.matches ? 'light' : 'dark';
    }

    function paint(resolved) {
        root.setAttribute('data-theme', resolved);
        // The document ships two theme-color tags carrying prefers-color-scheme media
        // queries, so the browser has an answer before this script exists and a client
        // with no script keeps one. From here on the answer is ours: the media
        // attributes come off — a media query cannot express "light on a dark system",
        // which is the whole point of an explicit choice — and both tags are set to the
        // resolved colour. Setting content while leaving media in place would do
        // nothing on the tag whose query does not match.
        //
        // The tags may not exist yet on the very first run: this script sits above them
        // in <head> so that data-theme is stamped before the stylesheet lands. The
        // DOMContentLoaded pass below catches them, and every later switch finds them.
        var metas = document.querySelectorAll('meta[name="theme-color"]');
        for (var i = 0; i < metas.length; i++) {
            metas[i].removeAttribute('media');
            metas[i].setAttribute('content', BAR_COLOR[resolved] || BAR_COLOR.dark);
        }
    }

    function apply(animated) {
        var resolved = resolve(mode);
        if (animated && root.getAttribute('data-theme') !== resolved) {
            // The cross-fade is opt-in per switch rather than a standing rule, so a
            // page load never animates and a click always does. See theme.css.
            root.classList.add('sb-theme-switching');
            window.setTimeout(function () {
                root.classList.remove('sb-theme-switching');
            }, 260);
        }
        paint(resolved);
        for (var i = 0; i < listeners.length; i++) {
            try {
                listeners[i](mode, resolved);
            } catch (e) {
                /* one bad subscriber must not stop the rest */
            }
        }
        return resolved;
    }

    // First paint. Runs while <head> is still parsing, before the stylesheet lands.
    apply(false);

    // The OS theme changing mid-session only matters in "system" mode; in the other two
    // the user has already said what they want. The listener stays attached either way
    // so switching back to "system" picks up the current OS value with no extra wiring.
    if (query) {
        var onSystemChange = function () {
            if (mode === 'system') apply(true);
        };
        if (typeof query.addEventListener === 'function') {
            query.addEventListener('change', onSystemChange);
        } else if (typeof query.addListener === 'function') {
            query.addListener(onSystemChange); // Safari < 14
        }
    }

    // A second document in the same browser — another tab, or the PWA alongside a tab —
    // should not disagree with this one about the theme.
    window.addEventListener('storage', function (event) {
        if (event.key !== STORAGE_KEY) return;
        var next = MODES.indexOf(event.newValue) === -1 ? 'system' : event.newValue;
        if (next === mode) return;
        mode = next;
        apply(true);
    });

    // theme-color is written again once the parser has passed the <meta> tags.
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () { paint(resolve(mode)); });
    }

    window.SecureBitTheme = {
        MODES: MODES.slice(),
        /** 'system' | 'light' | 'dark' — what the user chose. */
        get: function () { return mode; },
        /** 'light' | 'dark' — what that currently resolves to. */
        resolved: function () { return resolve(mode); },
        set: function (next) {
            if (MODES.indexOf(next) === -1) return resolve(mode);
            mode = next;
            writeStored(next);
            return apply(true);
        },
        /** Returns an unsubscribe function. Called with (mode, resolved). */
        subscribe: function (fn) {
            if (typeof fn !== 'function') return function () {};
            listeners.push(fn);
            return function () {
                var i = listeners.indexOf(fn);
                if (i !== -1) listeners.splice(i, 1);
            };
        }
    };
})();
