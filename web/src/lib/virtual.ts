/**
 * The window of a virtualised list (UI_Design.md §5.1, §5.16). Only the rows
 * that are near the viewport are rendered, so a list of five thousand events
 * scrolls as smoothly as a short one.
 */

/** The estimated height of a row, in pixels, per kind. */
export const ROW_HEIGHTS: Record<string, number> = {
  chapter: 32,
  date: 28,
  'not-dated-separator': 28,
  gap: 32,
  event: 104,
  'not-dated': 104,
  group: 96,
}

/** The number of rows rendered above and below the viewport. */
export const OVERSCAN_ROWS = 6

export interface VirtualRange {
  /** The index of the first rendered row. */
  start: number
  /** The index after the last rendered row. */
  end: number
  /** The offset of the first rendered row, in pixels. */
  offsetTop: number
  /** The height of the whole list, in pixels. */
  totalHeight: number
}

/**
 * The window of the rows that are visible. The offsets and the heights are
 * given per row; a row that was measured replaces its estimate.
 */
export function computeVirtualRange(
  offsets: number[],
  heights: number[],
  scrollTop: number,
  viewportHeight: number,
  overscan: number = OVERSCAN_ROWS,
): VirtualRange {
  const count = offsets.length
  if (count === 0) return { start: 0, end: 0, offsetTop: 0, totalHeight: 0 }

  const top = Math.max(0, scrollTop)
  const bottom = top + Math.max(0, viewportHeight)

  let start = 0
  while (start < count - 1 && offsets[start + 1] < top) start += 1
  let end = start
  while (end < count && offsets[end] < bottom) end += 1

  start = Math.max(0, start - overscan)
  end = Math.min(count, end + overscan)

  return {
    start,
    end,
    offsetTop: offsets[start] ?? 0,
    totalHeight: (offsets[count - 1] ?? 0) + (heights[count - 1] ?? 0),
  }
}

/** The offsets of the rows from their heights. */
export function computeOffsets(heights: number[]): number[] {
  const offsets = new Array<number>(heights.length)
  let offset = 0
  for (let index = 0; index < heights.length; index += 1) {
    offsets[index] = offset
    offset += heights[index]
  }
  return offsets
}

/**
 * The row that holds a position of the viewport, with the distance from the
 * top of the row. It keeps the reading position when the list grows.
 */
export function findAnchor(
  offsets: number[],
  scrollTop: number,
): { index: number; delta: number } {
  if (offsets.length === 0) return { index: 0, delta: 0 }
  let index = 0
  while (index < offsets.length - 1 && offsets[index + 1] <= scrollTop) index += 1
  return { index, delta: scrollTop - offsets[index] }
}
