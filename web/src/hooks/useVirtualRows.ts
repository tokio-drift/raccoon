import { useEffect, useState, type RefObject } from 'react'

/**
 * The window of a virtualised table (UI_Design.md §14.6). A table with many
 * rows renders only the rows near the viewport, so a capture with thousands
 * of files opens as fast as one with a dozen.
 */

/** Below this number of rows the list is rendered as a whole. */
export const VIRTUAL_ROW_LIMIT = 200

/** The estimated height of a row, in pixels. */
export const ESTIMATED_ROW_HEIGHT = 48

/** The number of rows rendered above and below the viewport. */
export const VIRTUAL_OVERSCAN = 20

export interface VirtualRows {
  /** The index of the first rendered row. */
  start: number
  /** The index after the last rendered row. */
  end: number
  /** The height of the space above the rendered rows, in pixels. */
  topPad: number
  /** The height of the space below the rendered rows, in pixels. */
  bottomPad: number
  /** The list is virtualised; the spacers are in use. */
  virtualised: boolean
}

export interface UseVirtualRowsOptions {
  /** The number of rows in the whole list. */
  count: number
  /** The scroll container of the list. */
  containerRef: RefObject<HTMLElement | null>
  /** Below this number of rows the list is rendered as a whole. */
  limit?: number
  /** The estimated height of a row, in pixels. */
  rowHeight?: number
  /** The number of rows rendered above and below the viewport. */
  overscan?: number
}

/**
 * The rows of a long list that are near the viewport. The rows outside the
 * window are replaced by two spacers, so the scrollbar keeps the length of
 * the whole list.
 */
export function useVirtualRows({
  count,
  containerRef,
  limit = VIRTUAL_ROW_LIMIT,
  rowHeight = ESTIMATED_ROW_HEIGHT,
  overscan = VIRTUAL_OVERSCAN,
}: UseVirtualRowsOptions): VirtualRows {
  const [scrollTop, setScrollTop] = useState(0)
  const [viewport, setViewport] = useState(0)

  useEffect(() => {
    const element = containerRef.current
    if (!element) return
    const onScroll = () => setScrollTop(element.scrollTop)
    const measure = () => setViewport(element.clientHeight)
    onScroll()
    measure()
    element.addEventListener('scroll', onScroll, { passive: true })
    window.addEventListener('resize', measure)
    return () => {
      element.removeEventListener('scroll', onScroll)
      window.removeEventListener('resize', measure)
    }
  }, [containerRef])

  if (count <= limit) {
    return { start: 0, end: count, topPad: 0, bottomPad: 0, virtualised: false }
  }

  const height = viewport || 640
  const first = Math.max(0, Math.floor(scrollTop / rowHeight) - overscan)
  const last = Math.min(count, Math.ceil((scrollTop + height) / rowHeight) + overscan)

  return {
    start: first,
    end: last,
    topPad: first * rowHeight,
    bottomPad: Math.max(0, (count - last) * rowHeight),
    virtualised: true,
  }
}
