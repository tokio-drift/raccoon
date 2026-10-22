import { useEffect, useState } from 'react'

/**
 * Watches a media query (UI_Design.md §6.1, §6.7). The detail pane of the
 * gallery sits beside the table from 1280 px and becomes a drawer below it.
 */
export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
    return window.matchMedia(query).matches
  })

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return
    const list = window.matchMedia(query)
    const update = () => setMatches(list.matches)
    update()
    if (typeof list.addEventListener === 'function') {
      list.addEventListener('change', update)
      return () => list.removeEventListener('change', update)
    }
    // Older browsers only know the deprecated listener API.
    list.addListener(update)
    return () => list.removeListener(update)
  }, [query])

  return matches
}

/** The width from which the detail pane sits beside the table (§6.1). */
export const WIDE_LAYOUT_QUERY = '(min-width: 1280px)'

/** True when the window is wide enough for the two-pane layout. */
export function useIsWide(): boolean {
  return useMediaQuery(WIDE_LAYOUT_QUERY)
}
