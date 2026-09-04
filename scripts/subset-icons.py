#!/usr/bin/env python3
"""
subset-icons.py — cut the FontAwesome webfonts down to the icons this app draws.

The full set is 2468 icons across three files, 299 KB of woff2, and fa-solid-900 alone
was 157 KB — the second largest thing on the page after the app bundle. The interface
uses 82 of them. Everything else was being downloaded so it could not be used.

Run this after adding or removing an icon:

    pip install fonttools brotli
    python3 scripts/subset-icons.py

It writes the subset fonts, a stylesheet carrying only the rules for the icons kept, and
a manifest of those names. tests/icon-subset.test.mjs reads the manifest and fails if a
`fa-` class appears in src/ that the subset does not cover — which is the failure this
whole approach risks, and it looks like an empty box rather than an error.

Kept as Python because that is what fontTools is. The Node build does not depend on it:
the outputs are committed, and this only has to run when the icon set changes.
"""

import json
import os
import re
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FA = os.path.join(ROOT, 'assets', 'fontawesome')
CSS = os.path.join(FA, 'css', 'all.min.css')
WEBFONTS = os.path.join(FA, 'webfonts')

# Where the interface names its icons. index.html is generated, but the prerendered
# landing could name one, so it is scanned too.
SOURCES = [os.path.join(ROOT, 'src'), os.path.join(ROOT, 'index.html')]

# fa- prefixed classes that select a family or an animation rather than a glyph.
NOT_ICONS = {'solid', 'regular', 'brands', 'light', 'thin', 'duotone', 'sharp',
             'spin', 'pulse', 'beat', 'fade', 'flip', 'shake', 'bounce',
             'fw', 'lg', 'xs', 'sm', 'border', 'pull-left', 'pull-right',
             'stack', 'inverse', 'li', 'ul', 'rotate', 'solid-900', 'fallback'}


def used_icon_names():
    names = set()
    for source in SOURCES:
        files = []
        if os.path.isfile(source):
            files = [source]
        else:
            for base, _, filenames in os.walk(source):
                files += [os.path.join(base, f) for f in filenames
                          if f.endswith(('.js', '.jsx', '.css', '.html'))]
        for path in files:
            with open(path, encoding='utf8', errors='ignore') as handle:
                for match in re.findall(r'\bfa-([a-z0-9-]+)', handle.read()):
                    if match not in NOT_ICONS:
                        names.add(match)
    return names


def icon_codepoints():
    """Every `.fa-name:before{content:"\\fXXX"}` rule in the shipped stylesheet."""
    with open(CSS, encoding='utf8') as handle:
        css = handle.read()
    mapping = {}
    for selectors, content in re.findall(r'((?:\.fa-[a-z0-9-]+(?:::?before)?,?)+)\{content:"([^"]+)"\}', css):
        points = [int(c, 16) for c in re.findall(r'\\([0-9a-fA-F]{2,6})', content)]
        if not points:
            continue
        for name in re.findall(r'\.fa-([a-z0-9-]+?)(?:::?before)?(?:,|$)', selectors):
            mapping.setdefault(name, points[0])
    return mapping


def font_family_faces():
    """The @font-face blocks, so the subset stylesheet can restate them verbatim."""
    with open(CSS, encoding='utf8') as handle:
        css = handle.read()
    return re.findall(r'@font-face\{[^}]*\}', css)


def main():
    try:
        from fontTools.ttLib import TTFont            # noqa: F401
    except ImportError:
        sys.exit('fontTools is not installed — run: pip install fonttools brotli')
    from fontTools.ttLib import TTFont

    mapping = icon_codepoints()
    used = used_icon_names()
    known = {name: mapping[name] for name in used if name in mapping}
    unknown = sorted(used - set(known))
    if unknown:
        print(f'   note: {len(unknown)} fa- classes are not icons in this build: {", ".join(unknown)}')

    wanted = set(known.values())
    kept_per_file = {}

    for filename in sorted(os.listdir(WEBFONTS)):
        if not filename.endswith('.woff2') or filename.endswith('.subset.woff2'):
            continue
        source = os.path.join(WEBFONTS, filename)
        with TTFont(source) as font:
            available = set(font.getBestCmap())
        keep = sorted(available & wanted)
        if not keep:
            print(f'   {filename}: no icons in use, not subset')
            continue

        target = source.replace('.woff2', '.subset.woff2')
        subprocess.run([
            sys.executable, '-m', 'fontTools.subset', source,
            '--unicodes=' + ','.join(f'U+{c:04X}' for c in keep),
            '--flavor=woff2',
            '--layout-features=',          # icon fonts need no shaping
            '--no-hinting',
            '--desubroutinize',
            '--output-file=' + target,
        ], check=True, capture_output=True)

        before, after = os.path.getsize(source), os.path.getsize(target)
        print(f'   {filename}: {len(keep)} icons, {before:,} → {after:,} B '
              f'({100 - after * 100 // before}% smaller)')
        kept_per_file[filename] = keep

    # A stylesheet with the faces and only the rules for the icons kept, so the 102 KB
    # original stops being fetched as well.
    #
    # The base rules are named here rather than sliced out of the minified original,
    # whose 81 KB preamble is 1505 selectors of sizing, rotation, stacking and animation
    # utilities this interface never uses. These are copied verbatim from all.min.css
    # (Font Awesome Free 6.5.1) — the families, and the two animations the app applies.
    covered = {cp for keep in kept_per_file.values() for cp in keep}
    rules = [f'.fa-{name}:before{{content:"\\{point:x}"}}'
             for name, point in sorted(known.items()) if point in covered]
    # Only the faces whose file was actually produced. fa-v4compatibility carries the
    # old v4 aliases and none of them are used here, so it is not subset — and a
    # @font-face pointing at a file that was never written is a 404 waiting for the
    # first glyph that asks for it.
    produced = {name.replace('.woff2', '.subset.woff2') for name in kept_per_file}
    faces = []
    for face in font_family_faces():
        face = face.replace('.woff2', '.subset.woff2')
        if not any(name in face for name in produced):
            continue
        # The upstream src also names a .ttf fallback, and this build ships none: only
        # woff2 is in webfonts/. No current browser would reach for it, but a src entry
        # pointing at a file that does not exist is a 404 waiting for the one that does.
        face = re.sub(r',\s*url\([^)]*\.ttf\)\s*format\(["\']truetype["\']\)', '', face)
        faces.append(face)

    base = (
        '.fa{font-family:var(--fa-style-family,"Font Awesome 6 Free");font-weight:var(--fa-style,900)}'
        '.fa,.fa-brands,.fa-regular,.fa-solid,.fab,.far,.fas{-moz-osx-font-smoothing:grayscale;'
        '-webkit-font-smoothing:antialiased;display:var(--fa-display,inline-block);font-style:normal;'
        'font-variant:normal;line-height:1;text-rendering:auto}'
        '.fa-regular,.fa-solid,.far,.fas{font-family:"Font Awesome 6 Free"}'
        '.fa-brands,.fab{font-family:"Font Awesome 6 Brands"}'
        '.fa-solid,.fas{font-weight:900}'
        '.fa-regular,.far{font-weight:400}'
        '.fa-brands,.fab{font-weight:400}'
        '.fa-spin{animation-name:fa-spin;animation-duration:var(--fa-animation-duration,2s);'
        'animation-iteration-count:var(--fa-animation-iteration-count,infinite);'
        'animation-timing-function:var(--fa-animation-timing,linear)}'
        '.fa-pulse,.fa-spin-pulse{animation-name:fa-spin;animation-duration:var(--fa-animation-duration,1s);'
        'animation-iteration-count:var(--fa-animation-iteration-count,infinite);'
        'animation-timing-function:var(--fa-animation-timing,steps(8))}'
        '@keyframes fa-spin{0%{transform:rotate(0deg)}to{transform:rotate(1turn)}}'
        '@media (prefers-reduced-motion:reduce){.fa-pulse,.fa-spin,.fa-spin-pulse{'
        'animation-delay:-1ms;animation-duration:1ms;animation-iteration-count:1}}'
    )

    out_css = os.path.join(FA, 'css', 'subset.css')
    with open(out_css, 'w', encoding='utf8') as handle:
        handle.write('/* Generated by scripts/subset-icons.py — do not edit by hand.\n'
                     '   Font Awesome Free 6.5.1 (CC BY 4.0 icons, SIL OFL 1.1 fonts, MIT code).\n'
                     '   The families and animations this app uses, plus only the icons it draws. */\n')
        handle.write(base)
        handle.write(''.join(faces))
        handle.write(''.join(rules))

    manifest = os.path.join(FA, 'subset-icons.json')
    with open(manifest, 'w', encoding='utf8') as handle:
        json.dump({'icons': sorted(known), 'notIcons': sorted(NOT_ICONS)}, handle, indent=2)
        handle.write('\n')

    print(f'   ✅ {len(known)} icons kept, stylesheet {os.path.getsize(out_css):,} B')


if __name__ == '__main__':
    main()
