/**
 * The rules of the stream inspector (UI_Design.md §7).
 *
 * Everything in this file is pure: the byte decoding, the hex rows, the gap
 * and carved-range marks, the list model and the small formatters the view
 * needs. The view and the hook only arrange the data.
 */

import type { CarvedFile, CarvedRange, Direction, StreamSummary } from '../api/types'
import { formatBytes, formatCount, formatHexOffset } from './format'

/** The size of a byte window (UI_Design.md §7.9). */
export const WINDOW_SIZE = 4096

/** The size of a large window (UI_Design.md §7.9). */
export const LARGE_WINDOW_SIZE = 65536

/** The number of windows that are kept in memory (UI_Design.md §7.9). */
export const MAX_CACHED_WINDOWS = 3

/** The largest direction total that the Both mode can show (UI_Design.md §7.4). */
export const BOTH_MODE_LIMIT = 65536

/** The two directions of a stream and the label of the segment control. */
export const DIRECTION_LABELS: Record<Direction, string> = {
  c2s: 'Client → Server',
  s2c: 'Server → Client',
}

/** The words of the legend under the direction control (UI_Design.md §7.4). */
export const DIRECTION_LEGEND: Record<Direction, string> = {
  c2s: 'Client to server',
  s2c: 'Server to client',
}

/** The prefix chip of a run (UI_Design.md §7.4). */
export const DIRECTION_PREFIX: Record<Direction, string> = {
  c2s: 'C→S',
  s2c: 'S→C',
}

// ---------------------------------------------------------------------------
// The bytes
// ---------------------------------------------------------------------------

/** The kind of a run of the text pane (UI_Design.md §7.5). */
export type TextRunKind = 'text' | 'control' | 'token' | 'invalid' | 'newline' | 'tab'

/** A run of the text pane. */
export interface TextRun {
  kind: TextRunKind
  /** The characters to show. */
  text: string
  /** The offset of the first byte of the run in the stream. */
  offset: number
  /** The number of bytes the run covers. */
  length: number
}

/** The bytes of a window. */
export function base64ToBytes(base64: string): Uint8Array {
  if (!base64) return new Uint8Array(0)
  if (typeof atob !== 'function') {
    throw new Error('no base64 decoder')
  }
  const binary = atob(base64)
  const out = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    out[index] = binary.charCodeAt(index)
  }
  return out
}

/** The characters that are shown as a visible token (UI_Design.md §7.5). */
const VISIBLE_TOKENS = new Set([
  0x200b, 0x200c, 0x200d, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff,
])

/** The token of a character that is shown as `‹U+202E›`. */
export function visibleToken(codePoint: number): string {
  return `‹U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}›`
}

/** The escape of an invalid byte: `\xNN`. */
export function invalidByteToken(byte: number): string {
  return `\\x${byte.toString(16).toUpperCase().padStart(2, '0')}`
}

interface DecodedChar {
  codePoint: number
  length: number
}

/** Decodes one UTF-8 character at the given index, or null when it is invalid. */
function decodeUtf8At(bytes: Uint8Array, index: number): DecodedChar | null {
  const first = bytes[index]
  let length: number
  let codePoint: number
  if (first >= 0xc2 && first <= 0xdf) {
    length = 2
    codePoint = first & 0x1f
  } else if (first >= 0xe0 && first <= 0xef) {
    length = 3
    codePoint = first & 0x0f
  } else if (first >= 0xf0 && first <= 0xf4) {
    length = 4
    codePoint = first & 0x07
  } else {
    return null
  }
  if (index + length > bytes.length) return null
  for (let step = 1; step < length; step += 1) {
    const continuation = bytes[index + step]
    if ((continuation & 0xc0) !== 0x80) return null
    codePoint = (codePoint << 6) | (continuation & 0x3f)
  }
  if (length === 3 && codePoint < 0x800) return null
  if (length === 4 && codePoint < 0x10000) return null
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return null
  if (codePoint > 0x10ffff) return null
  return { codePoint, length }
}

/**
 * Decodes a window as UTF-8 (UI_Design.md §7.5). An invalid byte becomes a
 * muted `\xNN` pill and never the replacement character; a control character
 * becomes its picture; a bidirectional or zero-width character becomes a
 * visible token.
 */
export function decodeText(bytes: Uint8Array, baseOffset = 0): TextRun[] {
  const runs: TextRun[] = []
  const push = (kind: TextRunKind, text: string, offset: number, length: number): void => {
    const last = runs[runs.length - 1]
    if (last && last.kind === kind && last.offset + last.length === offset) {
      last.text += text
      last.length += length
      return
    }
    runs.push({ kind, text, offset, length })
  }

  let index = 0
  while (index < bytes.length) {
    const byte = bytes[index]
    const offset = baseOffset + index
    if (byte < 0x20 || byte === 0x7f) {
      if (byte === 0x0d) push('control', '␍', offset, 1)
      else if (byte === 0x0a) push('newline', '↵\n', offset, 1)
      else if (byte === 0x09) push('tab', '⇥    ', offset, 1)
      else push('control', String.fromCharCode(0x2400 + byte), offset, 1)
      index += 1
      continue
    }
    if (byte < 0x80) {
      push('text', String.fromCharCode(byte), offset, 1)
      index += 1
      continue
    }
    const decoded = decodeUtf8At(bytes, index)
    if (!decoded) {
      push('invalid', invalidByteToken(byte), offset, 1)
      index += 1
      continue
    }
    if (VISIBLE_TOKENS.has(decoded.codePoint)) {
      push('token', visibleToken(decoded.codePoint), offset, decoded.length)
    } else {
      push('text', String.fromCodePoint(decoded.codePoint), offset, decoded.length)
    }
    index += decoded.length
  }
  return runs
}

/** The escaped text of a window: what the text pane shows and what is copied. */
export function escapeBytes(bytes: Uint8Array, baseOffset = 0): string {
  return decodeText(bytes, baseOffset)
    .map((run) => run.text)
    .join('')
}

// ---------------------------------------------------------------------------
// The lines of the text pane
// ---------------------------------------------------------------------------

/** One line of the text pane. */
export interface TextLine {
  /** The byte offset of the first byte of the line. */
  offset: number
  /** The parts of the line, with their kind. */
  parts: { kind: TextRunKind; text: string }[]
  /** The escaped text of the line, without the line break. */
  text: string
  /** The line is a wrapped continuation of the line above. */
  continuation: boolean
}

/** The height of a line of the text pane, in pixels (UI_Design.md §7.5). */
export const TEXT_LINE_HEIGHT = 20

/** The height of a row of the hex pane, in pixels (UI_Design.md §7.6). */
export const HEX_ROW_HEIGHT = 22

/**
 * Builds the lines of the text pane (UI_Design.md §7.5). A line break ends a
 * line, and a line that is longer than the pane is split into wrapped
 * continuation lines.
 */
export function buildTextLines(runs: TextRun[], columns: number): TextLine[] {
  interface Char {
    kind: TextRunKind
    ch: string
    offset: number
    break: boolean
  }
  const chars: Char[] = []
  for (const run of runs) {
    const text = run.kind === 'newline' ? run.text.replace(/\n/g, '') : run.text
    for (const ch of text) {
      chars.push({ kind: run.kind, ch, offset: run.offset, break: false })
    }
    if (run.kind === 'newline') {
      const last = chars[chars.length - 1]
      if (last) last.break = true
    }
  }

  const lines: TextLine[] = []
  let parts: { kind: TextRunKind; text: string }[] = []
  let text = ''
  let offset = runs.length > 0 ? runs[0].offset : 0
  let used = 0

  const flush = (continuation: boolean): void => {
    if (parts.length === 0 && !continuation) return
    lines.push({ offset, parts, text, continuation })
    parts = []
    text = ''
    used = 0
  }

  for (const char of chars) {
    if (parts.length === 0) offset = char.offset
    if (columns > 0 && used >= columns) {
      flush(true)
      offset = char.offset
    }
    // The characters of the same kind stay in one part, so a line is a few
    // elements and not one element per byte.
    const last = parts[parts.length - 1]
    if (last && last.kind === char.kind) last.text += char.ch
    else parts.push({ kind: char.kind, text: char.ch })
    text += char.ch
    used += 1
    if (char.break) flush(false)
  }
  flush(false)
  return lines
}

/** The hex bytes of a window: "48 65 6C 6C 6F". */
export function hexBytesFormat(bytes: Uint8Array): string {
  const parts: string[] = []
  for (const byte of bytes) {
    parts.push(byte.toString(16).toUpperCase().padStart(2, '0'))
  }
  return parts.join(' ')
}

/** The continuous hex of a window: "48656C6C6F". */
export function hexContinuousFormat(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) {
    out += byte.toString(16).toUpperCase().padStart(2, '0')
  }
  return out
}

// ---------------------------------------------------------------------------
// The window
// ---------------------------------------------------------------------------

/** A segment of a direction, in the space of the delivered bytes. */
export interface WindowSegment {
  off: number
  len: number
  ts: string
  packetNo: number
}

/** A range of bytes that was never captured. */
export interface WindowGap {
  off: number
  len: number
}

/** One row of the hex pane. */
export interface HexRowModel {
  /** The offset of the row. */
  offset: number
  /** The bytes of the row. */
  bytes: number[]
  /** The packet number of the segment that starts in this row. */
  packetNo?: number
  /** The segment that starts in this row. */
  segment?: WindowSegment
  /** The row stands for a gap in the capture. */
  gap?: boolean
  /** The number of missing bytes. */
  missing?: number
  /** The row starts a carved range. */
  carvedStart?: boolean
  /** The row ends a carved range. */
  carvedEnd?: boolean
  /** The label of the carved range, for example "invoice.zip · 5.2 KB". */
  carvedLabel?: string
  /** The id of the carved file of the range. */
  carvedFileId?: number
  /** The carved range itself, with its first and last byte. */
  carvedRange?: CarvedRange
}

/** The model of a loaded window. */
export interface WindowModel {
  /** The offset of the first byte. */
  offset: number
  /** The bytes of the window. */
  bytes: Uint8Array
  /** The rows of the hex pane. */
  rows: HexRowModel[]
  /** The runs of the text pane. */
  runs: TextRun[]
  /** The total number of bytes in the direction. */
  total: number
  /** The segments that overlap the window. */
  segments: WindowSegment[]
  /** The gaps that overlap the window. */
  gaps: WindowGap[]
  /** The carved ranges that overlap the window. */
  carved: CarvedRange[]
}

export interface WindowInput {
  bytes: Uint8Array
  offset: number
  total: number
  segments: WindowSegment[]
  gaps: WindowGap[]
  carved: CarvedRange[]
  /** The carved files of the case, for the labels of the ranges. */
  files: CarvedFile[]
}

/** The label of a carved range: "invoice.zip · 5.2 KB". */
export function carvedRangeLabel(range: CarvedRange, files: CarvedFile[]): string {
  const file = files.find((item) => item.id === range.fileId)
  if (!file) return `File ${range.fileId}`
  const size = formatBytes(file.size)
  return size ? `${file.displayName} · ${size}` : file.displayName
}

/**
 * Builds the model of a window: the rows of the hex pane with the packet
 * gutters, the gap rows and the carved-range marks, and the runs of the text
 * pane. A gap is never zero-filled (UI_Design.md §7.7).
 */
export function buildWindowModel(input: WindowInput): WindowModel {
  const { bytes, offset, total, files } = input
  const segments = [...input.segments].sort((a, b) => a.off - b.off)
  const gaps = [...input.gaps].sort((a, b) => a.off - b.off)
  const carved = [...input.carved].sort((a, b) => a.start - b.start)

  const rowCount = Math.ceil(bytes.length / 16)
  const gapByRow = new Map<number, WindowGap>()
  for (const gap of gaps) {
    const start = Math.max(gap.off, offset)
    if (start >= offset + bytes.length) continue
    const row = Math.floor((start - offset) / 16)
    const existing = gapByRow.get(row)
    if (existing) {
      existing.len += gap.len
      continue
    }
    gapByRow.set(row, { off: gap.off, len: gap.len })
  }

  const rows: HexRowModel[] = []
  for (let row = 0; row < rowCount; row += 1) {
    const rowOffset = offset + row * 16
    const gap = gapByRow.get(row)
    if (gap) {
      rows.push({ offset: gap.off, bytes: [], gap: true, missing: gap.len })
    }
    const segment = segments.find((item) => item.off >= rowOffset && item.off < rowOffset + 16)
    const rowBytes: number[] = []
    for (let index = 0; index < 16; index += 1) {
      const byte = bytes[row * 16 + index]
      if (byte === undefined) break
      rowBytes.push(byte)
    }
    const model: HexRowModel = { offset: rowOffset, bytes: rowBytes }
    if (segment) {
      model.packetNo = segment.packetNo
      model.segment = segment
    }
    const start = carved.find((range) => range.start >= rowOffset && range.start < rowOffset + 16)
    const end = carved.find((range) => range.end > rowOffset && range.end <= rowOffset + 16)
    if (start) {
      model.carvedStart = true
      model.carvedLabel = carvedRangeLabel(start, files)
      model.carvedFileId = start.fileId
      model.carvedRange = start
    }
    if (end) model.carvedEnd = true
    rows.push(model)
  }

  return {
    offset,
    bytes,
    rows,
    runs: decodeText(bytes, offset),
    total,
    segments,
    gaps,
    carved,
  }
}

/** The text of the footer strip: "Showing 0–4,095 of 18,230 bytes (22%)". */
export function windowRangeText(offset: number, length: number, total: number): string {
  if (total <= 0) return 'No bytes in this direction'
  const end = Math.min(offset + length, total)
  const percent = Math.min(100, Math.round((end / total) * 100))
  return `Showing ${formatCount(offset)}–${formatCount(Math.max(offset, end - 1))} of ${formatCount(total)} bytes (${percent}%)`
}

/** The size of a stream in bytes and in human units: "18,230 bytes (17.8 KB)". */
export function totalBytesText(total: number): string {
  return `${formatCount(total)} bytes (${formatBytes(total)})`
}

/** The note of a large stream (UI_Design.md §7.9). */
export function largeStreamNote(total: number): string | null {
  if (total <= 1024 * 1024) return null
  return 'This is a large stream. Use Jump to… to reach a position quickly.'
}

// ---------------------------------------------------------------------------
// The list
// ---------------------------------------------------------------------------

/** The sort keys of the stream list (UI_Design.md §7.1). */
export type StreamSortKey = 'start' | 'bytes' | 'packets'

/** The options of the sort dropdown. */
export const STREAM_SORT_OPTIONS: { value: StreamSortKey; label: string }[] = [
  { value: 'start', label: 'Start time' },
  { value: 'bytes', label: 'Byte count' },
  { value: 'packets', label: 'Packet count' },
]

/** One row of the stream list. */
export interface StreamListRow {
  stream: StreamSummary
  /** The row is a child of another stream, for example an FTP data stream. */
  child: boolean
  /** The label of the parent, for example "FTP data · child of Stream 1". */
  childLabel?: string
  /** The row has children of its own. */
  hasChildren: boolean
  /** The row is a parent whose children are hidden. */
  collapsed: boolean
  /** The nesting depth; the children of a stream are indented by 16 px. */
  depth: number
}

/** The endpoint of a stream, with the brackets an IPv6 address needs. */
export function endpointText(ip: string, port: number): string {
  const host = ip.includes(':') ? `[${ip}]` : ip
  return `${host}:${port}`
}

/** The endpoints of a stream: "192.0.2.14:51822 → 192.0.2.50:21". */
export function streamEndpoints(stream: StreamSummary): string {
  return `${endpointText(stream.srcIp, stream.srcPort)} → ${endpointText(stream.dstIp, stream.dstPort)}`
}

/** The text the search field of the stream list looks at (UI_Design.md §7.1). */
export function streamSearchText(stream: StreamSummary): string {
  return `${stream.id} ${stream.proto} ${stream.srcIp} ${stream.srcPort} ${stream.dstIp} ${stream.dstPort}`
}

/** The number of bytes of a direction. */
export function directionTotal(stream: StreamSummary, dir: Direction): number {
  return dir === 'c2s' ? stream.bytesC2S : stream.bytesS2C
}

/** The number of bytes of both directions together. */
export function streamTotalBytes(stream: StreamSummary): number {
  return stream.bytesC2S + stream.bytesS2C
}

/** The Both mode needs two directions that are small enough (§7.4). */
export function bothModeAllowed(stream: StreamSummary): boolean {
  return stream.bytesC2S <= BOTH_MODE_LIMIT && stream.bytesS2C <= BOTH_MODE_LIMIT
}

/** The tooltip of the disabled Both button (UI_Design.md §7.4). */
export const BOTH_MODE_TOOLTIP =
  'Both directions can only be shown together for streams up to 64 KB per direction.'

/** Sorts the streams (UI_Design.md §7.1). */
export function sortStreams(streams: StreamSummary[], key: StreamSortKey): StreamSummary[] {
  const sorted = [...streams]
  sorted.sort((a, b) => {
    if (key === 'bytes') return streamTotalBytes(b) - streamTotalBytes(a) || a.id - b.id
    if (key === 'packets') return b.packets - a.packets || a.id - b.id
    return a.startTs.localeCompare(b.startTs) || a.id - b.id
  })
  return sorted
}

/** Filters the streams by the search field (UI_Design.md §7.1). */
export function searchStreams(streams: StreamSummary[], query: string): StreamSummary[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return streams
  return streams.filter((stream) => streamSearchText(stream).toLowerCase().includes(needle))
}

/**
 * Builds the rows of the stream list: the parents first and their children
 * directly below them (UI_Design.md §7.1).
 */
export function buildStreamRows(
  streams: StreamSummary[],
  collapsed: Set<number> = new Set(),
): StreamListRow[] {
  const byId = new Map(streams.map((stream) => [stream.id, stream]))
  const childrenOf = new Map<number, StreamSummary[]>()
  const roots: StreamSummary[] = []
  for (const stream of streams) {
    if (stream.parentId && byId.has(stream.parentId)) {
      const list = childrenOf.get(stream.parentId)
      if (list) list.push(stream)
      else childrenOf.set(stream.parentId, [stream])
    } else {
      roots.push(stream)
    }
  }

  const rows: StreamListRow[] = []
  for (const root of roots) {
    const children = childrenOf.get(root.id) ?? []
    rows.push({
      stream: root,
      child: false,
      hasChildren: children.length > 0,
      collapsed: collapsed.has(root.id),
      depth: 0,
    })
    if (collapsed.has(root.id)) continue
    for (const child of children) {
      rows.push({
        stream: child,
        child: true,
        childLabel: `FTP data · child of Stream ${root.id}`,
        hasChildren: false,
        collapsed: false,
        depth: 1,
      })
    }
  }
  return rows
}

// ---------------------------------------------------------------------------
// Jumping
// ---------------------------------------------------------------------------

/**
 * Parses the offset of the jump field: a decimal number or a `0x` hexadecimal
 * one (UI_Design.md §7.9). It returns null when the value is not a number.
 */
export function parseJumpOffset(text: string): number | null {
  const trimmed = text.trim()
  if (!trimmed) return null
  if (/^0x[0-9a-f]+$/i.test(trimmed)) {
    const parsed = Number.parseInt(trimmed.slice(2), 16)
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
  }
  if (/^\d+$/.test(trimmed)) {
    const parsed = Number.parseInt(trimmed, 10)
    return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
  }
  return null
}

/** The message of an offset beyond the end of the stream (UI_Design.md §7.9). */
export function jumpOutOfRangeText(total: number): string {
  return `That offset is beyond the end of this stream (${formatCount(total)} bytes).`
}

/** The offset of a packet, from the segments of a direction. */
export function offsetOfPacket(segments: WindowSegment[], packetNo: number): number | null {
  const segment = segments.find((item) => item.packetNo === packetNo)
  return segment ? segment.off : null
}

/** The hex offset of the hex pane: "0x0000A120". */
export { formatHexOffset }
