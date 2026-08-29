// Two decisions in the switcher are easy to undo by accident, and both are quiet:
//
//  - Links, not buttons. Every locale is a separate document at its own URL. A control
//    that re-rendered strings in place would put all languages on one URL, which is
//    exactly the arrangement that cannot be indexed, shared, or opened in a new tab.
//  - Landing only. Switching locale navigates, and a navigation during a session drops
//    the peer connection. Offering it inside the chat invites someone to end their own
//    call by reaching for the language menu.

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (rel) => readFileSync(new URL(`../${rel}`, import.meta.url), 'utf8');
const switcher = read('src/components/ui/LanguageSwitcher.jsx');
const header = read('src/components/ui/Header.jsx');
const boot = read('src/scripts/app-boot.js');

// Links, not buttons.
assert.match(switcher, /React\.createElement\('a',/,
    'the switcher must render anchors — a crawler cannot follow a click handler');
// One button is allowed and only one: the control that opens the menu. Every entry that
// selects a language must still be an anchor — a button there would leave all locales
// sharing a single URL.
{
    const buttons = switcher.match(/React\.createElement\('button'/g) || [];
    assert.equal(buttons.length, 1,
        'the only button may be the menu trigger; language entries must be links');
    assert.match(switcher, /'aria-haspopup': 'menu'/, 'the trigger must announce that it opens a menu');
    assert.equal(/React\.createElement\('button'[\s\S]{0,400}href:/.test(switcher), false,
        'no button may carry an href — that is an anchor pretending to be a button');
}

// The entries stay in the DOM when the menu is shut, so the links remain followable and
// nothing depends on the menu having been opened.
assert.match(switcher, /display: open \? 'block' : 'none'/,
    'the menu must be hidden visually, not removed from the document');
assert.match(switcher, /href: link\.href/, 'each entry needs a real href');
assert.match(switcher, /hrefLang: link\.hrefLang/, 'hreflang on the link tells crawlers what it points at');

// The click must not be intercepted: the target locale is a different document.
assert.equal(/preventDefault/.test(switcher), false,
    'intercepting the click would keep the visitor on the current document');

// Accessibility: the current language is announced, not only styled.
assert.match(switcher, /'aria-current': link\.isCurrent \? 'page' : undefined/);
assert.match(switcher, /'aria-label': t\('language\.label'\)/, 'the nav needs a label');

// It must disappear entirely while the site is single-locale.
assert.match(switcher, /if \(SUPPORTED_LOCALES\.length < 2\) return null;/,
    'a one-language site must not show a language switcher');

// Landing only.
assert.match(header, /onLanding && React\.createElement\(LanguageSwitcher/,
    'the switcher must be gated on the landing page — navigating mid-session drops the connection');
assert.match(header, /import \{ LanguageSwitcher \} from '\.\/LanguageSwitcher\.jsx';/,
    'import it directly rather than through window, so load order cannot matter');

// And it has to actually reach the bundle.
assert.match(boot, /import '\.\.\/components\/ui\/LanguageSwitcher\.jsx';/);

console.log('language-switcher.test.mjs: all assertions passed');
