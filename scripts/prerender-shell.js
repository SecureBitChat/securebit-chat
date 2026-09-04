/**
 * prerender-shell.js — the static landing that ships inside <div id="root">.
 *
 * Why this exists: everything on the site is drawn by React after ~800 KB of JS has
 * downloaded and run, so until now a crawler fetching / got a <head> full of correct
 * metadata wrapped around an empty div. Search Console shows exactly what that costs —
 * the site ranks for the spelling of its domain (chatbit, chatyourbit, keepbit) rather
 * than for anything it does, and twelve of the thirteen localized pages have never been
 * shown to anyone, because a page whose only difference from the English one is its
 * <meta> tags gives Google no reason to swap it in.
 *
 * So each page is built carrying its own text: the same strings the app renders, from
 * the same locales/<code>.json, in real headings and paragraphs.
 *
 * It is never shown to a visitor who has JavaScript. The block defaults to display:none
 * and only a <noscript> stylesheet turns it back on, which means a browser that is going
 * to run the app never paints it for even one frame — an earlier version left it visible
 * until React mounted, and what that produced was a plain wall of English text on screen
 * for as long as the bundles took to arrive. Doing this in CSS rather than with a script
 * is deliberate: a script would have to be inline to beat first paint, and the page's CSP
 * allows no inline script.
 *
 * What a visitor does see is the mark, and only the mark. Hiding the text left nothing on
 * screen at all until React mounted, and "nothing" is not a first paint: Lighthouse put
 * First Contentful Paint at 6.3 s on mobile, because the first contentful thing was the
 * app itself. The shield below is the same one the header shows, inline so it costs no
 * request, and it is contentful the moment the stylesheet lands. React empties the
 * container on mount, so it leaves without being told to.
 *
 * What still reads it: every crawler that does not execute JavaScript, which is Bing,
 * Yandex, DuckDuckGo, the social unfurlers and the AI crawlers, plus Google's own first
 * pass over the raw HTML before it queues the page for rendering. Google's renderer sees
 * the same text a second time anyway, because the app itself draws these sections once
 * it mounts. Nothing here is hidden from a reader that is not also shown to them: the
 * block is a fallback for clients that cannot run the app, not a second version of the
 * page. Styling is inline and self-contained so it is carried away with the markup when
 * React empties the container, instead of lingering in the stylesheet.
 */

/** Escape for HTML *text*, not attributes — build-i18n's attr() covers those. */
const esc = (value) =>
    String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');

// Hidden first, shown only under <noscript>. Everything after that is scoped under
// .sb-pre so nothing here can reach the app, and the whole subtree — rules included —
// is removed when React empties the container. Spacing is logical (-inline-) so the
// Arabic, Hebrew, Farsi and Urdu builds mirror correctly off the dir already on <html>.
const STYLE = `<style>
.sb-pre{display:none}
.sb-boot{display:flex;align-items:center;justify-content:center;min-height:100vh;min-height:100svh;margin:0;background:#0f0f11}
.sb-boot svg{width:62px;height:auto;display:block;animation:sbBootPulse 1.8s ease-in-out infinite}
@keyframes sbBootPulse{0%,100%{opacity:.32;transform:scale(.97)}50%{opacity:1;transform:scale(1)}}
@media (prefers-reduced-motion:reduce){.sb-boot svg{animation:none;opacity:.75}}
</style>
<noscript><style>
.sb-pre{display:block}
.sb-boot{display:none}
</style></noscript>
<style>
.sb-pre{background:#0f0f11;color:#e8e8eb;font-family:Inter,system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.6;padding:56px 24px 72px;margin:0}
.sb-pre .sb-pre-in{max-width:940px;margin:0 auto;display:flex;flex-direction:column;gap:56px}
.sb-pre .sb-pre-brand{font-size:13px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#f0892a;margin:0 0 18px}
.sb-pre h1{font-size:clamp(28px,5vw,40px);font-weight:800;letter-spacing:-1.1px;line-height:1.12;color:#f4f4f6;margin:0 0 14px}
.sb-pre h2{font-size:23px;font-weight:700;letter-spacing:-.5px;color:#f4f4f6;margin:0 0 8px}
.sb-pre h3{font-size:17px;font-weight:700;letter-spacing:-.2px;color:#e8e8eb;margin:0 0 6px}
.sb-pre p{margin:0 0 10px;color:#8a8a92;font-size:15px;max-width:62ch}
.sb-pre .sb-pre-lead{font-size:16px;color:#a6a6ae;max-width:52ch}
.sb-pre .sb-pre-eyebrow{font-size:11px;font-weight:700;letter-spacing:.13em;text-transform:uppercase;color:#6b6b73;margin:0 0 6px}
.sb-pre .sb-pre-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:18px;margin-top:22px;padding:0;list-style:none}
.sb-pre .sb-pre-card{background:#141417;border:1px solid rgba(255,255,255,.07);border-radius:10px;padding:18px 20px}
.sb-pre .sb-pre-tags{margin:10px 0 0;padding:0;list-style:none;display:flex;flex-wrap:wrap;gap:6px}
.sb-pre .sb-pre-tags li{font-size:11.5px;color:#3ecf8e;background:rgba(62,207,142,.09);border:1px solid rgba(62,207,142,.18);border-radius:4px;padding:2px 7px}
.sb-pre .sb-pre-steps{margin:22px 0 0;padding:0;list-style:none;display:flex;flex-direction:column;gap:2px}
.sb-pre .sb-pre-steps li{border-top:1px solid rgba(255,255,255,.06);padding:13px 0;display:flex;flex-wrap:wrap;gap:2px 14px;align-items:baseline}
.sb-pre .sb-pre-steps h3{margin:0;font-size:15.5px}
.sb-pre .sb-pre-steps .sb-pre-when{font-size:12px;color:#6b6b73;margin-inline-start:auto;white-space:nowrap}
.sb-pre .sb-pre-steps p{flex:1 1 100%;margin:2px 0 0;font-size:14px}
.sb-pre .sb-pre-docs{margin:14px 0 0;padding:0;list-style:none;display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:2px 24px}
.sb-pre .sb-pre-docs li{padding:8px 0;border-top:1px solid rgba(255,255,255,.06);font-size:14.5px}
.sb-pre a{color:#f0892a;text-underline-offset:2px}
@media (prefers-reduced-motion:reduce){.sb-pre *{animation:none!important;transition:none!important}}
</style>`;

/**
 * Build the block for one locale.
 *
 * Strings are read through a lookup that falls back to the default locale and then to
 * nothing: a locale that gains a key before its translation lands should render one
 * English line, not an empty heading or the literal key.
 */
function prerenderShell(site, code, docs = []) {
    const ui = site.byCode[code].ui || {};
    const fallback = site.byCode[site.defaultLocale].ui || {};
    const s = (key) => {
        const value = ui[key] !== undefined ? ui[key] : fallback[key];
        return typeof value === 'string' ? value : '';
    };
    const list = (key) => {
        const value = ui[key] !== undefined ? ui[key] : fallback[key];
        return Array.isArray(value) ? value : [];
    };

    const out = [];

    // Hero. One <h1> per page, carrying the product's own claim rather than its name —
    // the name is already in <title>, the claim is what a category query matches.
    const headline = [s('hero.headlineTop'), s('hero.headlineBottom')].filter(Boolean);
    out.push(
        '  <header>',
        `    <p class="sb-pre-brand">${esc(site.siteName)}</p>`,
        `    <h1>${headline.map(esc).join('<br>')}</h1>`,
        `    <p class="sb-pre-lead">${esc(s('hero.subheading'))}</p>`,
        '  </header>'
    );

    // What the product is, in its own terms. These five cards are the densest piece of
    // vocabulary the site owns — ECDH, DTLS, forward secrecy, packet padding — and the
    // only place a category search has anything to match on.
    const cards = ['s1', 's2', 's3', 's4', 's5']
        .map((id) => {
            const title = [s(`unique.${id}.titleTop`), s(`unique.${id}.titleBottom`)].filter(Boolean).join(' ');
            const desc = s(`unique.${id}.desc`);
            if (!title && !desc) return '';
            const tags = list(`unique.${id}.tags`);
            return [
                '      <li class="sb-pre-card">',
                title ? `        <h3>${esc(title)}</h3>` : '',
                desc ? `        <p>${esc(desc)}</p>` : '',
                tags.length
                    ? `        <ul class="sb-pre-tags">${tags.map((tag) => `<li>${esc(tag)}</li>`).join('')}</ul>`
                    : '',
                '      </li>',
            ].filter(Boolean).join('\n');
        })
        .filter(Boolean);

    if (cards.length) {
        out.push(
            '  <section>',
            `    <p class="sb-pre-eyebrow">${esc(s('unique.eyebrow'))}</p>`,
            `    <h2>${esc(s('unique.heading'))}</h2>`,
            '    <ul class="sb-pre-grid">',
            ...cards,
            '    </ul>',
            '  </section>'
        );
    }

    // The roadmap is a genuine timeline, so it is a numbered list and nothing else is.
    // Feature bullets are left to the app: thirteen releases of them would triple this
    // block's weight to say what the titles already say.
    const releases = [];
    for (let i = 1; i <= 40; i += 1) {
        const title = s(`roadmap.r${i}.title`);
        if (!title) break;
        const when = s(`roadmap.r${i}.date`);
        const sub = s(`roadmap.r${i}.sub`);
        releases.push(
            [
                '      <li>',
                `        <h3>${esc(title)}</h3>`,
                when ? `        <span class="sb-pre-when">${esc(when)}</span>` : '',
                sub ? `        <p>${esc(sub)}</p>` : '',
                '      </li>',
            ].filter(Boolean).join('\n')
        );
    }

    if (releases.length) {
        out.push(
            '  <section>',
            `    <p class="sb-pre-eyebrow">${esc(s('roadmap.eyebrow'))}</p>`,
            `    <h2>${esc(s('roadmap.heading'))}</h2>`,
            `    <p>${esc(s('roadmap.subheading'))}</p>`,
            '    <ol class="sb-pre-steps">',
            ...releases,
            '    </ol>',
            '  </section>'
        );
    }

    // Internal links to the documentation. A sitemap tells Google the pages exist; a
    // link from the site's most-crawled page is what actually gets them fetched and
    // gives them anchor text to be ranked on. The whole block is marked lang="en"
    // because the documents are English on every locale — an untagged English list
    // inside a German page is a quality signal working against itself.
    if (docs.length) {
        out.push(
            '  <section lang="en" dir="ltr">',
            '    <p class="sb-pre-eyebrow">Documentation</p>',
            '    <ul class="sb-pre-docs">',
            ...docs.map((doc) =>
                `      <li><a href="${esc(doc.url)}" hreflang="en">${esc(doc.title)}</a></li>`),
            '    </ul>',
            '  </section>'
        );
    }

    // One outbound link, to the repository. It is the site's only real corroboration —
    // the thing a reader checks when a privacy claim needs backing.
    out.push(
        '  <section>',
        `    <h2>${esc(s('community.title'))}</h2>`,
        `    <p>${esc(s('community.description'))}</p>`,
        `    <p><a href="${esc(site.repository)}" rel="noopener">${esc(s('community.github'))}</a></p>`,
        '  </section>'
    );

    // The mark, and nothing else — logo/securebit-mark.svg, the same one the header
    // shows, inlined so it costs no request and is contentful the moment the stylesheet
    // lands. Its gradient ids are prefixed here: an inline <svg> puts them in the page's
    // id namespace, and the app has SVGs of its own.
    // aria-hidden because it says nothing a screen reader needs; the page it stands in
    // for announces itself once it is there.
    const boot = `<div class="sb-boot" aria-hidden="true">
  <svg viewBox="276 240 700 760" xmlns="http://www.w3.org/2000/svg" focusable="false">
    <defs>
      <linearGradient id="sbBootSilver" x1="0" y1="0" x2="0.35" y2="1"><stop offset="0" stop-color="#fdfdff"/><stop offset="0.20" stop-color="#e7e7ec"/><stop offset="0.46" stop-color="#c4c4cb"/><stop offset="0.72" stop-color="#a4a4ac"/><stop offset="1" stop-color="#86868d"/></linearGradient>
      <linearGradient id="sbBootOrange" x1="0" y1="0" x2="0.25" y2="1"><stop offset="0" stop-color="#ffb84d"/><stop offset="0.27" stop-color="#ff9a33"/><stop offset="0.58" stop-color="#fb7d16"/><stop offset="1" stop-color="#db5d04"/></linearGradient>
    </defs>
    <path fill="url(#sbBootSilver)" fill-rule="nonzero" d="m 835.26446,352.56633 102.39051,-103.90366 -418.64101,1.00877 c 0,0 -171.69323,1.22309 -222.43455,167.96079 -52.34251,171.99925 77.67556,253.20215 77.67556,253.20215 0,0 35.54922,23.82856 79.77792,31.68982 15.73869,2.39372 79.16695,1.09532 79.16695,1.09532 54.47377,-10.08773 41.40629,-81.22528 -10.65516,-77.67557 C 492.06451,630.5166 372.5156,615.45079 386.86464,469.07968 415.02639,353.31661 520.52712,353.57511 520.52712,353.57511 Z"/>
    <path fill="url(#sbBootOrange)" fill-rule="nonzero" d="m 289.24744,881.29522 95.22696,-95.94027 369.13823,1.06997 C 873.15229,774.31964 863.51011,647.63259 863.51011,647.63259 846.7608,546.1216 749.51871,545.49427 749.51871,545.49427 l -232.01791,0.25219 c -37.80546,-8.91638 -37.85435,-49.4299 -37.85435,-49.4299 0,0 -1.56131,-38.07813 40.52401,-46.63785 l 260.62023,-0.7745 c 170.83788,24.60922 185.61432,187.63187 185.61432,187.63187 0,0 18.85523,117.07655 -90.63794,200.89054 l -0.62454,154.4184 -144.79052,-110.68137 z"/>
    <path fill="url(#sbBootOrange)" d="m 658.38568,658.74237 a 27.462458,27.462458 0 0 1 -27.43073,27.46244 27.462458,27.462458 0 0 1 -27.49412,-27.39898 27.462458,27.462458 0 0 1 27.36719,-27.52575 27.462458,27.462458 0 0 1 27.55736,27.33536 z"/>
    <path fill="url(#sbBootOrange)" d="m 748.42871,659.07971 a 27.462458,27.462458 0 0 1 -27.43073,27.46244 27.462458,27.462458 0 0 1 -27.49412,-27.39898 27.462458,27.462458 0 0 1 27.36719,-27.52575 27.462458,27.462458 0 0 1 27.55736,27.33537 z"/>
  </svg>
</div>`;

    return `${STYLE}
${boot}
<div class="sb-pre">
  <div class="sb-pre-in">
${out.join('\n')}
  </div>
</div>`;
}

module.exports = { prerenderShell };
