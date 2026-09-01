// The geometry of a gallery view.
//
// Separated from the component because it is arithmetic, not rendering: it has
// no React in it, it is the part that was actually wrong when tiles came out
// tiny on a desktop, and it is the part worth pinning down in a test that does
// not need a browser to run.

/** Gap between tiles, and the shape each one holds. */
export const TILE_GAP = 10;
export const TILE_ASPECT = 16 / 9;
/** Below this a tile stops shrinking and the grid scrolls instead. */
export const MIN_TILE_W = 150;

/**
 * How big each tile should be, given the space there actually is.
 *
 * The first version of this picked a column count from the number of people and
 * let CSS divide the width. That is wrong in both directions and it showed:
 * capped, three people on a wide monitor got three small tiles adrift in empty
 * space; uncapped, they got three letterbox strips. Neither is what a call
 * looks like, because neither is looking at the window.
 *
 * So do what a gallery view does: try every column count, work out how large a
 * tile could be at that count — bounded by the width a column gets AND by the
 * height its row gets, since a tile has a fixed shape and the smaller of the two
 * wins — and keep whichever count makes the tiles biggest. Two people on a wide
 * screen come out side by side and enormous; six come out three by two; the same
 * six on a phone come out two by three, because there the height is what is
 * plentiful. Nothing is special-cased per device.
 *
 * Pure and exported so the arithmetic can be tested without a browser.
 *
 * @returns {{cols: number, rows: number, tileW: number, tileH: number}}
 */
export function gridLayout(count, width, height, {
    gap = TILE_GAP, aspect = TILE_ASPECT, minWidth = MIN_TILE_W,
} = {}) {
    if (count <= 0) return { cols: 0, rows: 0, tileW: 0, tileH: 0 };
    if (!(width > 0) || !(height > 0)) {
        // Not measured yet — first paint, or a container with no layout. Fall
        // back to a shape that is reasonable rather than to zero-sized tiles.
        const cols = Math.min(count, count <= 2 ? count : Math.ceil(Math.sqrt(count)));
        return { cols, rows: Math.ceil(count / cols), tileW: 0, tileH: 0 };
    }

    let best = { cols: 1, rows: count, tileW: 0, tileH: 0 };
    for (let cols = 1; cols <= count; cols++) {
        const rows = Math.ceil(count / cols);
        const perColumn = (width - gap * (cols - 1)) / cols;
        const perRow = (height - gap * (rows - 1)) / rows;
        if (perColumn <= 0 || perRow <= 0) continue;
        // A tile keeps its aspect ratio, so it is as large as the tighter of the
        // two constraints allows — never stretched to fill one of them.
        const tileW = Math.min(perColumn, perRow * aspect);
        if (tileW > best.tileW) best = { cols, rows, tileW, tileH: tileW / aspect };
    }

    if (best.tileW < minWidth) {
        // Too many people for the space. Stop shrinking and let the grid scroll:
        // tiles small enough to be unreadable are worse than a scrollbar.
        best.tileW = minWidth;
        best.tileH = minWidth / aspect;
    }
    return best;
}

/**
 * The spotlight arrangement: one large tile, the rest in a strip beneath it.
 *
 * A gallery is the right default — in a call of three or four everyone is worth
 * the same amount of screen. It stops being right the moment someone is
 * presenting, or the moment there are enough people that equal shares means
 * nobody is legible. So a tile can be pinned, and the stage splits: the pinned
 * person takes what is left after a strip of thumbnails, and the strip scrolls
 * sideways rather than shrinking further.
 *
 * The strip's height is a fraction of the stage, floored and capped, because a
 * proportion alone gives useless thumbnails on a phone and absurd ones on a
 * 4K monitor.
 *
 * @returns {{stageH: number, main: {w: number, h: number}, stripH: number, thumbW: number}}
 */
export function spotlightLayout(othersCount, width, height, {
    gap = TILE_GAP, aspect = TILE_ASPECT, minThumb = 92, maxThumb = 168,
} = {}) {
    if (!(width > 0) || !(height > 0)) {
        return { main: { w: 0, h: 0 }, stripH: 0, thumbW: 0 };
    }
    if (othersCount <= 0) {
        const w = Math.min(width, height * aspect);
        return { main: { w, h: w / aspect }, stripH: 0, thumbW: 0 };
    }

    const thumbW = Math.max(minThumb, Math.min(maxThumb, Math.round(height * 0.2 * aspect)));
    const stripH = thumbW / aspect;
    const mainH = height - stripH - gap;
    const mainW = Math.min(width, mainH * aspect);
    // Refuse to split a stage that cannot carry the split. The test is not
    // "does it fit" but "is it worth it": a main tile barely larger than the
    // thumbnails below it spotlights nobody, it just takes a gallery and makes
    // one cell slightly bigger. Below that the caller falls back to the gallery,
    // and is told so by a main tile of zero rather than a useless one.
    if (mainH <= 0 || mainW < thumbW * 2) {
        return { main: { w: 0, h: 0 }, stripH: 0, thumbW: 0 };
    }
    return { main: { w: mainW, h: mainW / aspect }, stripH, thumbW };
}
