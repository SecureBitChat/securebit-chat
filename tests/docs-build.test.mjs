// The documentation is the only text on this site written to answer a question someone
// actually types. It spent its life as raw Markdown behind Disallow: /doc/, which is a
// large part of why every category query lands on page three. What has to keep holding
// once it is published: one page per document, each one addressable, describable and
// reachable — a page Google cannot find a link to, or cannot tell apart from another,
// is back where it started.

import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdirSync, readFileSync, existsSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const read = (rel) => readFileSync(path.join(ROOT, rel), 'utf8');

// Regenerate first, so the committed pages are checked as *output* and a stale docs/
// fails here rather than shipping.
execFileSync('node', [path.join(ROOT, 'scripts/build-docs.js')], { stdio: 'pipe' });

const sources = readdirSync(path.join(ROOT, 'doc')).filter((f) => f.endsWith('.md'));
assert.ok(sources.length >= 2, 'doc/ should hold the documentation this test is about');

const urlFor = (file) =>
    file === 'README.md' ? '/docs/' : `/docs/${path.basename(file, '.md').toLowerCase()}/`;
const fileFor = (url) => path.join('docs', url.slice('/docs/'.length), 'index.html');

const titles = new Set();
const descriptions = new Set();

for (const source of sources) {
    const url = urlFor(source);
    const rel = fileFor(url);
    assert.ok(existsSync(path.join(ROOT, rel)), `${source} has no page at ${url}`);
    const html = read(rel);

    // Every page must be addressable as itself. A shared canonical would collapse all
    // nine into one result, which is the failure this whole exercise is undoing.
    assert.ok(html.includes(`<link rel="canonical" href="https://securebit.chat${url}">`),
        `${rel}: canonical must point at ${url}`);

    const title = html.match(/<title>([\s\S]*?)<\/title>/);
    assert.ok(title, `${rel}: no <title>`);
    assert.ok(!titles.has(title[1]), `${rel}: duplicate <title> ${title[1]}`);
    titles.add(title[1]);

    const description = html.match(/<meta name="description" content="([^"]*)">/);
    assert.ok(description && description[1].length > 40, `${rel}: description is missing or too thin`);
    assert.ok(description[1].length <= 170,
        `${rel}: description is ${description[1].length} chars — Google truncates near 155`);
    assert.ok(!descriptions.has(description[1]), `${rel}: duplicate description`);
    descriptions.add(description[1]);

    assert.ok(html.includes('<h1'), `${rel}: no <h1>`);

    // Links carried over from Markdown must have been rewritten. A surviving .md href
    // is a 404 for a reader and a dead end for a crawler.
    const dangling = [...html.matchAll(/href="([^"]*\.md[^"]*)"/g)]
        .map((m) => m[1])
        .filter((href) => !href.startsWith('https://github.com/'));
    assert.deepEqual(dangling, [], `${rel}: unrewritten Markdown links`);

    // Nothing may reference an asset relatively: /docs/cryptography/ + "logo/x.png"
    // resolves under the document's own directory and 404s.
    const relative = [...html.matchAll(/\b(?:src|href)="(?!https?:|data:|mailto:|#|\/)([^"]+)"/g)];
    assert.deepEqual(relative.map((m) => m[1]), [], `${rel}: relative asset path`);

    assert.ok(html.includes('href="/docs/'), `${rel}: no link back into the documentation`);
    assert.ok(html.includes('href="/"'), `${rel}: no link back to the app`);
}

// The FAQ is the one document that is a list of questions, and the only one that may
// say so. An earlier version detected FAQ shape from "two or more <h2>", which every
// document here satisfies, and published ARCHITECTURE.md as a FAQPage — structured data
// describing a page as something it is not is worse than shipping none.
{
    const faq = read(fileFor('/docs/faq/'));
    const schemaOf = (html) => JSON.parse(html.match(/application\/ld\+json">([\s\S]*?)<\/script>/)[1]);
    const faqSchema = schemaOf(faq);
    assert.equal(faqSchema['@type'], 'FAQPage', 'the FAQ must be marked up as one');
    assert.ok(faqSchema.mainEntity.length >= 5, 'the FAQ schema lost its questions');
    for (const entry of faqSchema.mainEntity) {
        assert.equal(entry['@type'], 'Question');
        assert.ok(entry.name.length > 5 && entry.acceptedAnswer.text.length > 40,
            `FAQ entry "${entry.name}" is missing its question or answer`);
    }
    // Every question in the schema must be a heading a reader can actually see.
    for (const entry of faqSchema.mainEntity) {
        assert.ok(faq.includes(entry.name.replace(/&/g, '&amp;')),
            `FAQ schema claims a question the page does not show: ${entry.name}`);
    }
    for (const source of sources.filter((f) => f !== 'FAQ.md')) {
        assert.equal(schemaOf(read(fileFor(urlFor(source))))['@type'], 'TechArticle',
            `${source} must not be published as a FAQPage`);
    }
}

// Discoverability: the sitemap lists them, and the landing page links to them. The
// sitemap alone only says the pages exist; the link is what gets them crawled.
const sitemap = read('sitemap.xml');
const landing = read('index.html');
for (const source of sources) {
    const url = urlFor(source);
    assert.ok(sitemap.includes(`<loc>https://securebit.chat${url}</loc>`), `sitemap is missing ${url}`);
    assert.ok(landing.includes(`href="${url}"`), `the landing page does not link to ${url}`);
}
assert.ok(/<lastmod>\d{4}-\d{2}-\d{2}<\/lastmod>/.test(sitemap), 'sitemap entries need a lastmod');

// The raw Markdown must stay out of the index: same text, second address.
assert.ok(read('robots.txt').includes('Disallow: /doc/'),
    'the raw doc/*.md files must stay disallowed now that /docs/ carries the same text');

console.log(`docs-build.test.mjs: ${sources.length} documentation pages checked`);
