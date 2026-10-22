import { useCallback, useEffect, useState } from 'react'

/**
 * The width of a resizable pane (UI_Design.md §14.2). The width is kept in
 * the local storage, so the reader finds the panes as they left them.
 */

const PREFIX = 'raccoon.pane.'

export interface ResizablePane {
  /** The width of the pane in pixels; the fallback while it was never moved. */
  width: number
  /** Sets the width of the pane. */
  setWidth: (value: number) => void
  /** Returns the pane to the width of the layout. */
  reset: () => void
}

export interface UseResizablePaneOptions {
  /** The smallest width of the pane, in pixels. */
  min: number
  /** The largest width of the pane, in pixels. */
  max: number
  /** The width of the layout, used until the reader resizes the pane. */
  fallback: number
}

/** Reads a stored width and holds it between the limits of the pane. */
export function useResizablePane(key: string, options: UseResizablePaneOptions): ResizablePane {
  const { min, max, fallback } = options
  const [width, setWidthState] = useState<number | null>(null)

  useEffect(() => {
    if (typeof window === 'undefined') return
    const stored = window.localStorage.getItem(PREFIX + key)
    if (!stored) return
    const parsed = Number.parseInt(stored, 10)
    if (!Number.isFinite(parsed)) return
    setWidthState(Math.min(max, Math.max(min, parsed)))
  }, [key, min, max])

  const setWidth = useCallback(
    (value: number) => {
      const clamped = Math.min(max, Math.max(min, Math.round(value)))
      setWidthState(clamped)
      try {
        window.localStorage.setItem(PREFIX + key, String(clamped))
      } catch {
        // A browser that refuses to store the width keeps it for this session.
      }
    },
    [key, max, min],
  )

  const reset = useCallback(() => {
    setWidthState(null)
    try {
      window.localStorage.removeItem(PREFIX + key)
    } catch {
      // Nothing to clean up.
    }
  }, [key])

  return { width: width ?? fallback, setWidth, reset }
}
