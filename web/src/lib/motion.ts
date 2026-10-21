/**
 * The motion preference of the reader (UI_Design.md §10.8). The design asks
 * for one bounce of the dropzone icon; under reduced motion it is skipped.
 */

/** True when the reader asked for less motion. */
export function prefersReducedMotion(): boolean {
  if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return false
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches
  } catch {
    return false
  }
}
