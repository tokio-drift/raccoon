/**
 * The rules of the artifact gallery (UI_Design.md §6). The helpers here are
 * pure: the view renders what they say, and the tests read them directly.
 *
 * Nothing in this file touches the file system, the network or the DOM. A
 * file name is always treated as text that a stranger wrote; it is never used
 * as a path.
 */

import type { CarvedFile, Direction, StreamSummary, VerdictStatus } from '../api/types'
import { formatEndpoint } from './events'
import { truncateFilename } from './truncate'

/* ------------------------------------------------------------------ format */

/** The friendly name of a detected format (§6.3). */
const FORMAT_LABELS: Record<string, string> = {
  PNG: 'PNG image',
  JPEG: 'JPEG image',
  JPG: 'JPEG image',
  GIF: 'GIF image',
  BMP: 'BMP image',
  WEBP: 'WebP image',
  PDF: 'PDF document',
  ZIP: 'ZIP archive',
  GZIP: 'Gzip archive',
  BZIP2: 'Bzip2 archive',
  XZ: 'XZ archive',
  TAR: 'TAR archive',
  ELF: 'ELF executable',
  PE: 'Windows executable',
  MACHO: 'Mach-O executable',
  CLASS: 'Java class file',
  PLAIN: 'Plain text',
  TEXT: 'Plain text',
  HTML: 'HTML page',
  XML: 'XML document',
  JSON: 'JSON data',
  CSV: 'CSV data',
  WAV: 'WAV audio',
  MP3: 'MP3 audio',
  AVI: 'AVI video',
  MP4: 'MP4 video',
  SQLITE: 'SQLite database',
}

/**
 * The format of a file with its extension: "PNG image · .png". An unknown
 * format keeps its own name; a file without an extension shows only the
 * format.
 */
export function formatLabel(format?: string, ext?: string): string {
  const name = (format ?? '').trim()
  const known = FORMAT_LABELS[name.toUpperCase()]
  const label = known ?? (name ? name.replace(/_/g, ' ') : '')
  const suffix = ext ? `.${ext.replace(/^\./, '')}` : ''
  if (!label) return suffix || 'Unknown format'
  return suffix ? `${label} · ${suffix}` : label
}

/** The icon of a format; the gallery never shows a preview (§6.1). */
export function formatIconName(format?: string): 'image' | 'archive' | 'executable' | 'file' {
  const name = (format ?? '').toUpperCase()
  if (['PNG', 'JPEG', 'JPG', 'GIF', 'BMP', 'WEBP'].includes(name)) return 'image'
  if (['ZIP', 'GZIP', 'BZIP2', 'XZ', 'TAR'].includes(name)) return 'archive'
  if (['ELF', 'PE', 'MACHO', 'CLASS'].includes(name)) return 'executable'
  return 'file'
}

/* --------------------------------------------------------------- the name */

/** True when the name carries path characters (§6.2). */
export function isPathLikeName(name: string): boolean {
  return name.includes('/') || name.includes('\\') || name.includes('..')
}

/**
 * The visible tokens of the control and bidirectional characters of a name
 * (§6.2): "‹U+202E›" and "‹0x1B›". The name itself is never altered.
 */
export function controlCharacterTokens(name: string): string[] {
  const tokens: string[] = []
  for (const char of name) {
    const code = char.codePointAt(0) ?? 0
    if (code === 0x202e || code === 0x2066 || code === 0x2067 || code === 0x2069) {
      tokens.push(`‹U+${code.toString(16).toUpperCase().padStart(4, '0')}›`)
      continue
    }
    if (code < 0x20 || code === 0x7f) {
      tokens.push(`‹0x${code.toString(16).toUpperCase().padStart(2, '0')}›`)
    }
  }
  return tokens
}

/** True when the name holds a character outside the ASCII range (§6.2). */
export function hasNonAscii(name: string): boolean {
  return Array.from(name).some((char) => (char.codePointAt(0) ?? 0) > 0x7f)
}

/**
 * The escaped form of a name: every character outside the ASCII range becomes
 * a `\u` escape, so a lookalike character cannot deceive the reader (§6.2).
 */
export function escapeUnicode(text: string): string {
  return Array.from(text)
    .map((char) => {
      const code = char.codePointAt(0) ?? 0
      if (code <= 0x7f) return char
      return `\\u${code.toString(16).toUpperCase().padStart(4, '0')}`
    })
    .join('')
}

/** The extension of a display name, lowercased and without the dot. */
export function nameExtension(name: string): string {
  const base = name.split(/[/\\]/).pop() ?? name
  const dot = base.lastIndexOf('.')
  if (dot <= 0 || dot === base.length - 1) return ''
  return base.slice(dot + 1).toLowerCase()
}

/**
 * True when the extension of the display name differs from the detected one
 * (§6.3). A name without an extension never mismatches.
 */
export function nameMismatch(name: string, detectedExt?: string): boolean {
  const ext = nameExtension(name)
  if (!ext || !detectedExt) return false
  return ext !== detectedExt.replace(/^\./, '').toLowerCase()
}

/** The name of a file that has none: "Unnamed file · PNG · file 4" (§6.2). */
export function unnamedFileLabel(file: CarvedFile): string {
  const format = (file.format ?? '').trim()
  const parts = ['Unnamed file']
  if (format) parts.push(format)
  parts.push(`file ${file.id}`)
  return parts.join(' · ')
}

/** The name of a file as it is shown, with the fallback of §6.2. */
export function displayName(file: CarvedFile): string {
  const name = (file.displayName ?? '').trim()
  if (name) return name
  return unnamedFileLabel(file)
}

/** The truncated name of the table cell: the last eight characters stay. */
export function tableName(file: CarvedFile): string {
  return truncateFilename(displayName(file))
}

/* -------------------------------------------------------------- extraction */

/** The label of the extraction status (§6.3). */
export const EXTRACTION_LABEL: Record<CarvedFile['status'], string> = {
  complete: 'Complete',
  truncated: 'Incomplete',
  corrupt: 'Corrupt',
}

/* ---------------------------------------------------------------- verdict */

/** The order of the verdicts, most serious first (§6.9). */
export const VERDICT_ORDER: VerdictStatus[] = [
  'malicious',
  'suspicious',
  'unknown',
  'not_checked',
  'no_detections',
]

/** The rank of a verdict in the order above; lower is more serious. */
export function verdictRank(status: VerdictStatus): number {
  const index = VERDICT_ORDER.indexOf(status)
  return index === -1 ? VERDICT_ORDER.length : index
}

/** The verdict of a file, or "not checked" when the file has none. */
export function fileVerdict(file: CarvedFile): VerdictStatus {
  return file.verdict?.status ?? 'not_checked'
}

/* ----------------------------------------------------------------- hashes */

/**
 * The neutral name a file is saved under (§6.8): the first twelve hex
 * characters of its SHA-256 and a `.bin` extension. The name the sender chose
 * is never used, so the file cannot arrive looking like an executable.
 */
export function neutralDownloadName(sha256: string): string {
  const hex = (sha256 ?? '').trim().toLowerCase()
  const clean = hex.replace(/[^0-9a-f]/g, '').slice(0, 12)
  return clean.length > 0 ? `${clean}.bin` : 'download.bin'
}

/** The magic bytes of a file as spaced hex pairs: "89 50 4E 47". */
export function magicBytesText(magicHex?: string): string {
  const hex = (magicHex ?? '').trim().toLowerCase()
  const pairs = hex.match(/.{1,2}/g) ?? []
  return pairs.map((pair) => pair.toUpperCase()).join(' ')
}

/* ------------------------------------------------------------- endpoints */

/** The label of a direction chip (§6.4). */
export function directionLabel(dir: Direction): string {
  return dir === 's2c' ? 'Sent to client' : 'Sent to server'
}

/**
 * The endpoints of a file, in the order the data travelled: a file carved
 * from the client-to-server direction shows the source first (§6.4).
 */
export function fileEndpointPair(
  file: CarvedFile,
  stream?: StreamSummary | null,
): { from: string; to: string } | null {
  if (!stream) return null
  const from = formatEndpoint(`${stream.srcIp}:${stream.srcPort}`)
  const to = formatEndpoint(`${stream.dstIp}:${stream.dstPort}`)
  if (!from || !to) return null
  return file.dir === 's2c' ? { from: to, to: from } : { from, to }
}

/**
 * The endpoints of a file, in the order the data travelled: a file carved
 * from the client-to-server direction shows the source first (§6.4).
 */
export function fileEndpoints(
  file: CarvedFile,
  stream?: StreamSummary | null,
): string | null {
  const pair = fileEndpointPair(file, stream)
  return pair ? `${pair.from} → ${pair.to}` : null
}

/* ----------------------------------------------------------------- search */

/** The text of a file that the search looks at (§3.7). */
export function fileSearchText(file: CarvedFile, stream?: StreamSummary | null): string {
  const parts = [
    file.displayName ?? '',
    file.path ?? '',
    file.format ?? '',
    file.ext ?? '',
    file.sha256 ?? '',
    file.md5 ?? '',
  ]
  const endpoints = fileEndpoints(file, stream)
  if (endpoints) parts.push(endpoints)
  return parts.join(' ').toLowerCase()
}

/* ------------------------------------------------------------------ sorts */

/** The columns the table can sort by (§6.9). */
export type FileSortKey =
  | 'verdict'
  | 'name'
  | 'format'
  | 'size'
  | 'extraction'
  | 'confidence'
  | 'order'

export const FILE_SORT_KEYS: FileSortKey[] = [
  'verdict',
  'name',
  'format',
  'size',
  'extraction',
  'confidence',
  'order',
]

const CONFIDENCE_RANK: Record<CarvedFile['confidence'], number> = {
  high: 0,
  medium: 1,
  low: 2,
}

/**
 * The files in the order of the reader (UI_Design.md §6.9). The default is
 * the verdict, most serious first, and the ties keep the order of the
 * capture.
 */
export function sortFiles(
  files: CarvedFile[],
  key: FileSortKey,
  descending = false,
): CarvedFile[] {
  const sorted = [...files]
  const direction = descending ? -1 : 1
  sorted.sort((left, right) => {
    let result = 0
    switch (key) {
      case 'name':
        result = displayName(left).localeCompare(displayName(right), 'en')
        break
      case 'format':
        result = (left.format ?? '').localeCompare(right.format ?? '', 'en')
        break
      case 'size':
        result = left.size - right.size
        break
      case 'extraction':
        result = left.status.localeCompare(right.status, 'en')
        break
      case 'confidence':
        result = CONFIDENCE_RANK[left.confidence] - CONFIDENCE_RANK[right.confidence]
        break
      case 'verdict':
        result = verdictRank(fileVerdict(left)) - verdictRank(fileVerdict(right))
        break
      case 'order':
      default:
        result = 0
        break
    }
    // The order of appearance in the capture breaks every tie.
    if (result === 0) return left.id - right.id
    return result * direction
  })
  return sorted
}

/* ------------------------------------------------------------- deep links */

/** Reads the sort of the deep link: "name" or "-name". */
export function sortFromParams(value?: string): { key: FileSortKey; descending: boolean } {
  if (!value) return { key: 'verdict', descending: false }
  const descending = value.startsWith('-')
  const name = descending ? value.slice(1) : value
  const key = (FILE_SORT_KEYS as string[]).includes(name) ? (name as FileSortKey) : 'verdict'
  return { key, descending }
}

/** Writes the sort of the deep link: "name" or "-name". */
export function sortToParams(key: FileSortKey, descending: boolean): string {
  return descending ? `-${key}` : key
}

/** The filters of the gallery (§3.2, §6.9). */
export interface FileFilters {
  /** The verdict statuses; empty means every status. */
  verdicts: VerdictStatus[]
  /** The formats; empty means every format. */
  formats: string[]
  /** The direction; null means both. */
  dir: Direction | null
  /** The extraction statuses; empty means every status. */
  extractions: CarvedFile['status'][]
  /** The free text of the search field. */
  query: string
  /** The low-confidence files are shown. */
  showLowConfidence: boolean
}

/** The filters a gallery starts with. */
export const EMPTY_FILE_FILTERS: FileFilters = {
  verdicts: [],
  formats: [],
  dir: null,
  extractions: [],
  query: '',
  showLowConfidence: false,
}

/** Reads the filters of the deep link (§3.2). */
export function filtersFromParams(params: Record<string, string>): FileFilters {
  const verdicts = splitList(params.verdict).filter((value): value is VerdictStatus =>
    (VERDICT_ORDER as string[]).includes(value),
  )
  const dir = params.dir === 'c2s' || params.dir === 's2c' ? params.dir : null
  return {
    verdicts,
    formats: splitList(params.format),
    dir,
    extractions: [],
    query: params.q ?? '',
    showLowConfidence: params.low === '1',
  }
}

/** The deep-link parameters of the filters (§3.2). */
export function filtersToParams(filters: FileFilters): Record<string, string> {
  const params: Record<string, string> = {}
  if (filters.verdicts.length > 0) params.verdict = filters.verdicts.join(',')
  if (filters.formats.length > 0) params.format = filters.formats.join(',')
  if (filters.dir) params.dir = filters.dir
  if (filters.query) params.q = filters.query
  if (filters.showLowConfidence) params.low = '1'
  return params
}

/** True when a filter is active, so the bar can show a chip for it. */
export function filtersActive(filters: FileFilters): boolean {
  return (
    filters.verdicts.length > 0 ||
    filters.formats.length > 0 ||
    filters.dir !== null ||
    filters.extractions.length > 0 ||
    filters.query.trim() !== '' ||
    filters.showLowConfidence
  )
}

/** Splits a comma-separated parameter into its parts. */
export function splitList(value?: string): string[] {
  if (!value) return []
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}
