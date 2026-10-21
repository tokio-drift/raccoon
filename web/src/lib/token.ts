/**
 * The session token (docs/api.md, "Authentication").
 *
 * The token arrives in the dashboard URL as `?t=<token>`. It is kept in memory
 * only, removed from the address bar straight away, and never written to the
 * DOM, the page title, a log line or a diagnostic report.
 */

let sessionToken: string | null = null

/**
 * Reads `?t=` from the current URL, stores it in memory and removes it from
 * the address bar. Returns the token, or null when the URL carried none.
 */
export function captureTokenFromLocation(): string | null {
  if (typeof window === 'undefined') return null
  const params = new URLSearchParams(window.location.search)
  const token = params.get('t')
  if (!token) return null
  sessionToken = token
  params.delete('t')
  const query = params.toString()
  const url = `${window.location.pathname}${query ? `?${query}` : ''}${window.location.hash}`
  window.history.replaceState(window.history.state, '', url)
  return token
}

/** The token for API requests, or null when the session has no token. */
export function getSessionToken(): string | null {
  return sessionToken
}

/** Sets or clears the in-memory token. */
export function setSessionToken(token: string | null): void {
  sessionToken = token
}
