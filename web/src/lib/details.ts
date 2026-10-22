import type { CaseEvent } from '../api/types'

/**
 * The typed details of an event (UI_Design.md §5.8–§5.9, §5.12). The known
 * keys of a protocol get their own rows; everything else is shown under
 * "Other details" as a two-column table.
 */

/** A value of a detail row. */
export type DetailValue =
  | { kind: 'text'; text: string; long?: boolean }
  | { kind: 'code'; text: string }
  | { kind: 'list'; items: string[]; overflow: number }
  | { kind: 'object'; entries: DetailEntry[] }
  | { kind: 'unreadable'; raw: string }

/** One row of a detail block. */
export interface DetailEntry {
  label: string
  value: DetailValue
  /** The value is a credential and stays masked. */
  masked?: boolean
}

/** A block of the details section. */
export interface DetailBlock {
  /** The name of the block, for example "FTP login". */
  title: string
  entries: DetailEntry[]
  /** A warning that belongs to the block. */
  note?: string
  /** The block starts with a code block, for example the request line. */
  lead?: DetailValue
}

/** The keys the design knows for a protocol; everything else is "other". */
const KNOWN_KEYS: Record<string, string[]> = {
  FTP_LOGIN_ATTEMPT: ['user', 'command', 'password', 'passwordPresent', 'reply'],
  FTP_LOGIN_SUCCESS: ['user', 'command', 'password', 'passwordPresent', 'reply'],
  FTP_LOGIN_FAILED: ['user', 'command', 'password', 'passwordPresent', 'reply'],
  FTP_COMMAND: ['command', 'arg', 'filename', 'reply'],
  FTP_FILE_TRANSFER: ['filename', 'direction', 'size', 'file_id'],
  HTTP_TRANSACTION: [
    'method',
    'url',
    'host',
    'status',
    'contentType',
    'bodyLen',
    'userAgent',
    'filename',
    'authUser',
    'passwordPresent',
    'password',
  ],
  DNS_QUERY: ['qname', 'qtype', 'rcode', 'answers', 'ttl'],
  TCP_ANOMALY: ['kind', 'gaps', 'gapBytes', 'explanation', 'why'],
  FILE_CARVED: ['file_id', 'format', 'ext', 'status', 'size', 'magicHex', 'sha256', 'sha'],
  THREAT_VERDICT: ['status', 'source', 'score', 'rules', 'verdict', 'sha256'],
  FINDING: ['technique', 'techniqueName', 'evidenceIds', 'evidenceCount', 'supportingEventIds'],
  GROUP: ['childCount', 'groupCount', 'highestSeverity'],
  STREAM_OPENED: ['midstream', 'packets', 'bytes'],
}

/** The depth a nested object is shown as key/value rows. */
export const MAX_NESTING_DEPTH = 3

/** The number of array items shown before the rest is folded away. */
export const MAX_LIST_ITEMS = 10

/** The result words of an FTP login (§5.9). */
export function ftpResultWord(type: string): string {
  if (type === 'FTP_LOGIN_SUCCESS') return 'Succeeded'
  if (type === 'FTP_LOGIN_FAILED') return 'Failed'
  return 'Attempt'
}

/**
 * Formats a time to live: 3600 → "3,600 s (1 h)". The seconds are always
 * shown, the human form is added.
 */
export function formatTtl(seconds: number): string {
  const total = Math.max(0, Math.trunc(seconds))
  const withSeparators = total.toLocaleString('en-US')
  if (total < 60) return `${withSeparators} s`
  if (total < 3600) {
    const minutes = Math.floor(total / 60)
    const rest = total % 60
    return `${withSeparators} s (${minutes} min${rest > 0 ? ` ${rest} s` : ''})`
  }
  if (total < 86400) {
    const hours = Math.floor(total / 3600)
    const minutes = Math.floor((total % 3600) / 60)
    return `${withSeparators} s (${hours} h${minutes > 0 ? ` ${minutes} min` : ''})`
  }
  const days = Math.floor(total / 86400)
  return `${withSeparators} s (${days} day${days === 1 ? '' : 's'})`
}

/** Turns a raw value into the value the detail pane renders. */
export function describeValue(value: unknown, depth = 0): DetailValue {
  if (value === null || value === undefined) return { kind: 'text', text: 'Not recorded' }
  if (typeof value === 'string') {
    return value.length > 160 ? { kind: 'code', text: value } : { kind: 'text', text: value }
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return { kind: 'text', text: String(value) }
  }
  if (Array.isArray(value)) {
    // The whole list is kept: the pane shows the first ten and lets the
    // reader open the rest (§5.12).
    const items = value.map((item) => stringify(item))
    return { kind: 'list', items, overflow: Math.max(0, items.length - MAX_LIST_ITEMS) }
  }
  if (typeof value === 'object') {
    if (depth >= MAX_NESTING_DEPTH) {
      return { kind: 'text', text: stringify(value) }
    }
    let entries: [string, unknown][]
    try {
      entries = Object.entries(value as Record<string, unknown>)
    } catch {
      // A value that cannot be read is shown as raw text, never as a crash.
      return { kind: 'unreadable', raw: String(value) }
    }
    return {
      kind: 'object',
      entries: entries
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => ({ label: key, value: describeValue(item, depth + 1) })),
    }
  }
  return { kind: 'unreadable', raw: String(value) }
}

/**
 * The text of a raw value. A value that cannot be serialised becomes its
 * escaped form, so the pane always shows text and never a crash (§5.12).
 */
export function stringify(value: unknown): string {
  if (value === null || value === undefined) return ''
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  try {
    return JSON.stringify(value) ?? String(value)
  } catch {
    return escapeValue(value)
  }
}

/** The escaped text of a value that cannot be serialised. */
export function escapeValue(value: unknown): string {
  try {
    return String(value)
  } catch {
    return '[unreadable value]'
  }
}

export interface DetailView {
  /** The typed blocks of the details section. */
  blocks: DetailBlock[]
  /** The rows of the "Other details" section. */
  other: DetailEntry[]
  /** The keys the event type does not know. */
  unknownType: boolean
}

/**
 * Builds the details of an event: the typed blocks of its protocol and the
 * rows of the keys the design does not know.
 */
export function buildDetailView(event: CaseEvent): DetailView {
  const details = event.details ?? {}
  const type = event.type ?? ''
  const known = KNOWN_KEYS[type] ?? []
  const blocks: DetailBlock[] = []
  const used = new Set<string>()

  const take = (key: string): unknown => {
    used.add(key)
    return details[key]
  }

  if (type.startsWith('FTP_LOGIN')) {
    const user = take('user')
    const password = take('password')
    const reply = take('reply')
    used.add('command')
    used.add('passwordPresent')
    const entries: DetailEntry[] = []
    if (user !== undefined) {
      entries.push({ label: 'Username', value: { kind: 'text', text: stringify(user) } })
    }
    if (password !== undefined) {
      entries.push({ label: 'Password', value: { kind: 'text', text: stringify(password) }, masked: true })
    }
    entries.push({ label: 'Result', value: { kind: 'text', text: ftpResultWord(type) } })
    if (reply !== undefined) {
      entries.push({ label: 'Reply', value: { kind: 'text', text: stringify(reply) } })
    }
    blocks.push({
      title: 'FTP login',
      entries,
      note:
        password !== undefined
          ? 'This password was sent in cleartext. Anyone watching the network could read it.'
          : undefined,
    })
  } else if (type === 'FTP_COMMAND') {
    const command = take('command')
    const arg = take('arg')
    const filename = take('filename')
    const reply = take('reply')
    const entries: DetailEntry[] = []
    if (arg !== undefined) {
      entries.push({ label: 'Argument', value: { kind: 'text', text: stringify(arg) } })
    }
    if (filename !== undefined) {
      entries.push({ label: 'File name', value: { kind: 'text', text: stringify(filename) } })
    }
    if (reply !== undefined) {
      entries.push({ label: 'Reply', value: { kind: 'text', text: stringify(reply) } })
    }
    blocks.push({
      title: 'FTP command',
      entries,
      lead: command === undefined ? undefined : { kind: 'code', text: stringify(command) },
    })
  } else if (type === 'FTP_FILE_TRANSFER') {
    const filename = take('filename')
    const direction = take('direction')
    const size = take('size')
    const entries: DetailEntry[] = []
    if (filename !== undefined) {
      entries.push({ label: 'File name', value: { kind: 'text', text: stringify(filename) } })
    }
    if (direction !== undefined) {
      entries.push({ label: 'Direction', value: { kind: 'text', text: stringify(direction) } })
    }
    if (size !== undefined) {
      entries.push({ label: 'Size', value: { kind: 'text', text: stringify(size) } })
    }
    blocks.push({ title: 'FTP transfer', entries })
  } else if (type === 'HTTP_TRANSACTION') {
    const method = take('method')
    const url = take('url')
    const host = take('host')
    const status = take('status')
    const contentType = take('contentType')
    const bodyLen = take('bodyLen')
    const userAgent = take('userAgent')
    const filename = take('filename')
    const authUser = take('authUser')
    const password = take('password')
    used.add('passwordPresent')
    const entries: DetailEntry[] = []
    if (host !== undefined) {
      entries.push({ label: 'Host', value: { kind: 'text', text: stringify(host) } })
    }
    if (status !== undefined) {
      entries.push({ label: 'Status', value: { kind: 'text', text: stringify(status) } })
    }
    if (contentType !== undefined) {
      entries.push({ label: 'Content type', value: { kind: 'text', text: stringify(contentType) } })
    }
    if (bodyLen !== undefined) {
      entries.push({ label: 'Body length', value: { kind: 'text', text: stringify(bodyLen) } })
    }
    if (userAgent !== undefined) {
      entries.push({ label: 'User agent', value: { kind: 'text', text: stringify(userAgent) } })
    }
    if (filename !== undefined) {
      entries.push({ label: 'File name', value: { kind: 'text', text: stringify(filename) } })
    }
    if (authUser !== undefined) {
      entries.push({ label: 'User', value: { kind: 'text', text: stringify(authUser) } })
    }
    if (password !== undefined) {
      entries.push({ label: 'Password', value: { kind: 'text', text: stringify(password) }, masked: true })
    }
    const line =
      method === undefined && url === undefined
        ? undefined
        : `${stringify(method)} ${stringify(url)}`.trim()
    blocks.push({
      title: 'HTTP request',
      entries,
      lead: line ? { kind: 'code', text: line } : undefined,
      note:
        password !== undefined
          ? 'This password was sent in cleartext. Anyone watching the network could read it.'
          : undefined,
    })
  } else if (type === 'DNS_QUERY') {
    const qname = take('qname')
    const qtype = take('qtype')
    const rcode = take('rcode')
    const answers = take('answers')
    const ttl = take('ttl')
    const entries: DetailEntry[] = []
    if (rcode !== undefined) {
      entries.push({ label: 'Response code', value: { kind: 'text', text: stringify(rcode) } })
    }
    if (ttl !== undefined && typeof ttl === 'number') {
      entries.push({ label: 'TTL', value: { kind: 'text', text: formatTtl(ttl) } })
    }
    const question =
      qname === undefined
        ? undefined
        : qtype === undefined
          ? stringify(qname)
          : `${stringify(qname)} (${stringify(qtype)})`
    const answerItems =
      answers === undefined
        ? []
        : (Array.isArray(answers) ? answers : [answers]).map((answer) => {
            if (answer && typeof answer === 'object') {
              const record = answer as Record<string, unknown>
              const name = stringify(record.name)
              const type = stringify(record.type)
              const data = stringify(record.data)
              return [name, type, data].filter((part) => part.length > 0).join(' · ')
            }
            return stringify(answer)
          })
    blocks.push({
      title: 'DNS',
      entries,
      lead: question ? { kind: 'code', text: question } : undefined,
    })
    if (answerItems.length > 0) {
      blocks.push({
        title: 'Answers',
        entries: [],
      })
      const answersBlock = blocks[blocks.length - 1]
      answersBlock.lead = { kind: 'list', items: answerItems, overflow: 0 }
    }
  } else if (type === 'TCP_ANOMALY') {
    const kind = take('kind')
    const gaps = take('gaps')
    const explanation = take('explanation')
    const why = take('why')
    const entries: DetailEntry[] = []
    if (kind !== undefined) {
      entries.push({ label: 'Anomaly', value: { kind: 'text', text: stringify(kind) } })
    }
    if (gaps !== undefined) {
      entries.push({ label: 'Packet gaps', value: describeValue(gaps) })
    }
    if (why !== undefined) {
      entries.push({ label: 'Why it matters', value: { kind: 'text', text: stringify(why) } })
    }
    blocks.push({
      title: 'TCP anomaly',
      entries,
      note: explanation === undefined ? undefined : stringify(explanation),
    })
  }

  const other: DetailEntry[] = Object.entries(details)
    .filter(([key]) => !used.has(key) && !known.includes(key))
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, value]) => ({ label: key, value: describeValue(value) }))

  return { blocks, other, unknownType: !known.includes(type) && blocks.length === 0 }
}
