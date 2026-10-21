/**
 * Truncation rules (UI_Design.md §12.9). Truncation never changes what is
 * copied: the full value is always available in the detail pane and the copy
 * action always copies the exact string.
 */

/** Replaces the start of the text with an ellipsis, keeping the end. */
export function truncateStart(text: string, keepEnd: number): string {
  if (text.length <= keepEnd) return text
  return `…${text.slice(text.length - keepEnd)}`
}

/** Keeps the start of the text and marks the cut with an ellipsis. */
export function truncateEnd(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text
  return `${text.slice(0, maxLength)}…`
}

/** Keeps both ends and elides the middle. */
export function truncateMiddle(text: string, maxLength: number): string {
  if (text.length <= maxLength) return text
  const keep = Math.max(1, Math.floor((maxLength - 1) / 2))
  return `${text.slice(0, keep)}…${text.slice(text.length - keep)}`
}

/** Filenames keep their last 8 characters: "…report.pdf". */
export function truncateFilename(name: string): string {
  return truncateStart(name, 8)
}

/** URLs keep the scheme, the host and the last 24 characters. */
export function truncateUrl(url: string): string {
  if (url.length <= 48) return url
  const match = /^([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^/?#]*)(.*)$/.exec(url)
  if (!match) return truncateMiddle(url, 48)
  const [, prefix, rest] = match
  const tail = rest.slice(Math.max(0, rest.length - 24))
  return `${prefix}…${tail}`
}

/** User agents are cut at 80 characters. */
export function truncateUserAgent(userAgent: string): string {
  return truncateEnd(userAgent, 80)
}

/** IPv6 addresses keep their brackets and elide the middle. */
export function truncateIPv6(address: string): string {
  if (!address.includes(':')) return address
  const bracketed = address.startsWith('[') && address.endsWith(']')
  const inner = bracketed ? address.slice(1, -1) : address
  const shortened = truncateMiddle(inner, 24)
  return bracketed ? `[${shortened}]` : shortened
}

/** DNS names keep their last 20 characters. */
export function truncateDnsName(name: string): string {
  return truncateStart(name, 20)
}

/** Banners show their first 100 characters. */
export function truncateBanner(banner: string): string {
  return banner.slice(0, 100)
}

/** Usernames are cut at 32 characters. */
export function truncateUsername(name: string): string {
  return truncateEnd(name, 32)
}
