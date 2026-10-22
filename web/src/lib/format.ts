/**
 * Number, byte, time and hash formatting (UI_Design.md §12.4–§12.9).
 *
 * Capture times are always rendered from the capture clock, never relative to
 * the viewer's clock.
 */

const COUNT_FORMAT = new Intl.NumberFormat('en-US')

/** Formats an integer with thousands separators: 18230 → "18,230". */
export function formatCount(value: number): string {
  return COUNT_FORMAT.format(Math.trunc(value))
}

/**
 * Parses an API timestamp. The API emits nanosecond precision, which
 * `Date.parse` does not accept, so the fraction is trimmed to milliseconds.
 */
export function parseTimestamp(value: string): number {
  const trimmed = value.replace(/(\.\d{3})\d+/, '$1')
  const parsed = Date.parse(trimmed)
  return Number.isNaN(parsed) ? 0 : parsed
}

/** Formats a byte count with 1,024 steps: "142 B", "1.2 KB", "5.2 MB". */
export function formatBytes(value: number): string {
  const bytes = Math.max(0, Math.trunc(value))
  if (bytes < 1024) return `${formatCount(bytes)} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let size = bytes / 1024
  let unit = 0
  while (size >= 1024 && unit < units.length - 1) {
    size /= 1024
    unit += 1
  }
  return `${size.toFixed(1)} ${units[unit]}`
}

/** The exact byte count, used as the tooltip for a formatted size. */
export function formatBytesExact(value: number): string {
  return `${formatCount(value)} bytes`
}

/** The exact size in bytes, as "1,204 B" (§6.4). */
export function formatByteCount(value: number): string {
  return `${formatCount(value)} B`
}

/** Abbreviates large counts in the header strip only: 1_250_000 → "1.3M". */
export function formatCompactCount(value: number): string {
  if (value < 1_000_000) return formatCount(value)
  return `${(value / 1_000_000).toFixed(1)}M`
}

/** Formats a duration in milliseconds: "8.4 s", "41 s", "2 min 05 s", "1 h 03 min". */
export function formatDuration(ms: number): string {
  const totalSeconds = Math.max(0, ms) / 1000
  if (totalSeconds < 10) return `${totalSeconds.toFixed(1)} s`
  const whole = Math.round(totalSeconds)
  if (whole < 60) return `${whole} s`
  const minutes = Math.floor(whole / 60)
  const seconds = whole % 60
  if (minutes < 60) return `${minutes} min ${String(seconds).padStart(2, '0')} s`
  const hours = Math.floor(minutes / 60)
  return `${hours} h ${String(minutes % 60).padStart(2, '0')} min`
}

/** The exact duration used as a tooltip: "00:41.230". */
export function formatDurationExact(ms: number): string {
  const total = Math.max(0, ms)
  const minutes = Math.floor(total / 60000)
  const seconds = Math.floor((total % 60000) / 1000)
  const millis = Math.floor(total % 1000)
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}.${String(
    millis,
  ).padStart(3, '0')}`
}

/** Formats a whole percentage: 62 → "62%". */
export function formatPercent(value: number): string {
  return `${Math.round(value)}%`
}

export interface ClockOptions {
  /** Detail panes show microseconds; lists show milliseconds. */
  micro?: boolean
  /** "utc" (default) or "local". */
  basis?: 'utc' | 'local'
  /** The chip of the status bar shows seconds only. */
  seconds?: boolean
}

/** Formats a wall-clock time of day: "14:03:07.431". */
export function formatClock(timestampMs: number, options: ClockOptions = {}): string {
  const basis = options.basis ?? 'utc'
  const date = new Date(timestampMs)
  const hours = String(basis === 'utc' ? date.getUTCHours() : date.getHours()).padStart(2, '0')
  const minutes = String(basis === 'utc' ? date.getUTCMinutes() : date.getMinutes()).padStart(
    2,
    '0',
  )
  const seconds = String(basis === 'utc' ? date.getUTCSeconds() : date.getSeconds()).padStart(
    2,
    '0',
  )
  if (options.seconds) return `${hours}:${minutes}:${seconds}`
  const millis = String(date.getUTCMilliseconds()).padStart(3, '0')
  const base = `${hours}:${minutes}:${seconds}.${millis}`
  if (!options.micro) return base
  const micros = String(Math.floor((timestampMs % 1000) * 1000)).padStart(3, '0')
  return `${base}${micros}`
}

/** Formats elapsed time from the capture start: "+00:12.431". */
export function formatElapsed(elapsedMs: number): string {
  const total = Math.max(0, elapsedMs)
  const hours = Math.floor(total / 3600000)
  const minutes = Math.floor((total % 3600000) / 60000)
  const seconds = Math.floor((total % 60000) / 1000)
  const millis = Math.floor(total % 1000)
  const clock =
    hours > 0
      ? `${hours}:${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
      : `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
  return `+${clock}.${String(millis).padStart(3, '0')}`
}

/** Formats a short elapsed time for the processing view: "00:19". */
export function formatElapsedShort(elapsedMs: number): string {
  const total = Math.max(0, elapsedMs)
  const minutes = Math.floor(total / 60000)
  const seconds = Math.floor((total % 60000) / 1000)
  return `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`
}

/** Formats an ISO date: "2026-10-20". */export function formatDateISO(timestampMs: number, basis: 'utc' | 'local' = 'utc'): string {
  const date = new Date(timestampMs)
  const year = basis === 'utc' ? date.getUTCFullYear() : date.getFullYear()
  const month = String((basis === 'utc' ? date.getUTCMonth() : date.getMonth()) + 1).padStart(2, '0')
  const day = String(basis === 'utc' ? date.getUTCDate() : date.getDate()).padStart(2, '0')
  return `${year}-${month}-${day}`
}

/** Formats a date separator row: "Tue 20 Oct 2026 (UTC)". */
export function formatDateSeparator(timestampMs: number, basis: 'utc' | 'local' = 'utc'): string {
  const date = new Date(timestampMs)
  const weekday = new Intl.DateTimeFormat('en-GB', {
    weekday: 'short',
    timeZone: basis === 'utc' ? 'UTC' : undefined,
  }).format(date)
  const day = new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: basis === 'utc' ? 'UTC' : undefined,
  }).format(date)
  return basis === 'utc' ? `${weekday} ${day} (UTC)` : `${weekday} ${day}`
}

/** Formats a time range label: "00:12.0 – 00:41.3 elapsed". */
export function formatElapsedRange(startMs: number, endMs: number): string {
  const minutes = (value: number) => String(Math.floor(value / 60000)).padStart(2, '0')
  const seconds = (value: number) => (value % 60000) / 1000
  return `${minutes(startMs)}:${seconds(startMs).toFixed(1)} – ${minutes(endMs)}:${seconds(endMs).toFixed(1)} elapsed`
}

/** Formats a time range with wall-clock times: "14:03:07 – 14:03:36 UTC". */
export function formatClockRange(
  startMs: number,
  endMs: number,
  basis: 'utc' | 'local' = 'utc',
): string {
  const zone = basis === 'utc' ? 'UTC' : 'local'
  const clock = (value: number) => {
    const date = new Date(value)
    const hours = String(basis === 'utc' ? date.getUTCHours() : date.getHours()).padStart(2, '0')
    const minutes = String(basis === 'utc' ? date.getUTCMinutes() : date.getMinutes()).padStart(
      2,
      '0',
    )
    const seconds = String(basis === 'utc' ? date.getUTCSeconds() : date.getSeconds()).padStart(
      2,
      '0',
    )
    return `${hours}:${minutes}:${seconds}`
  }
  return `${clock(startMs)} – ${clock(endMs)} ${zone}`
}

/** The offset label shown in the status bar: "UTC" or "UTC+05:30". */
export function formatZoneLabel(basis: 'utc' | 'local'): string {
  if (basis === 'utc') return 'UTC'
  const offset = new Intl.DateTimeFormat('en-GB', { timeZoneName: 'shortOffset' })
    .formatToParts(new Date())
    .find((part) => part.type === 'timeZoneName')
  return offset?.value ?? 'local'
}

/** Formats a byte offset in hexadecimal for the hex pane: "0x0000A120". */
export function formatHexOffset(value: number): string {
  return `0x${Math.max(0, Math.trunc(value)).toString(16).toUpperCase().padStart(8, '0')}`
}

/** Formats a byte offset in decimal with separators: "41,248". */
export function formatDecimalOffset(value: number): string {
  return formatCount(value)
}

/** Formats a byte range: "bytes 1,204–6,498 (5,294 B)". */
export function formatOffsetRange(start: number, end: number): string {
  return `bytes ${formatCount(start)}–${formatCount(end)} (${formatBytes(end - start)})`
}

/** Shortens a hash for tables: "33a3fe8d…97b" (first 8, last 4). */
export function formatHashShort(hash: string): string {
  if (hash.length <= 13) return hash
  return `${hash.slice(0, 8)}…${hash.slice(-4)}`
}

/**
 * Formats a time relative to now: "3 minutes ago". It is only used for the
 * time a threat check ran, never for a capture time.
 */
export function formatRelativeTime(timestampMs: number, nowMs: number = Date.now()): string {
  const seconds = Math.round((nowMs - timestampMs) / 1000)
  if (seconds < 45) return 'just now'
  if (seconds < 90) return 'a minute ago'
  const minutes = Math.round(seconds / 60)
  if (minutes < 60) return `${minutes} minutes ago`
  if (minutes < 120) return 'an hour ago'
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} hours ago`
  if (hours < 48) return 'yesterday'
  const days = Math.round(hours / 24)
  return `${days} days ago`
}
