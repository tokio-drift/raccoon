import type { CaseEvent, Severity } from '../api/types'

/**
 * The vocabulary of the storyboard (UI_Design.md §5.3–§5.5, §5.12). Every
 * label is derived from the data of the API; nothing is invented and nothing
 * is looked up outside the capture.
 */

/** The words that keep their capitals in a type label. */
const ACRONYMS = new Set([
  'ftp',
  'ftp-data',
  'http',
  'https',
  'dns',
  'tcp',
  'udp',
  'ssl',
  'tls',
  'ssh',
  'smb',
  'irc',
  'imap',
  'pop3',
  'icmp',
  'arp',
  'dnssec',
  'json',
  'xml',
  'html',
  'zip',
  'png',
  'jpeg',
  'exe',
  'ntlm',
  'kerberos',
  'ldap',
  'smtp',
  'rdp',
])

/** The phases of the design (§5.5), with the labels it shows. */
export const PHASE_LABELS: Record<string, string> = {
  recon: 'Reconnaissance',
  access: 'Access',
  action: 'Action',
  exfil: 'Exfiltration',
  c2: 'Command and control',
}

/** The protocols of the design (§5.3), with the labels it shows. */
export const PROTOCOL_LABELS: Record<string, string> = {
  ftp: 'FTP',
  'ftp-data': 'FTP data',
  http: 'HTTP',
  https: 'HTTPS',
  dns: 'DNS',
  tcp: 'TCP',
  udp: 'UDP',
  unknown: 'Other',
}

const SAFE_TYPE = /^[A-Za-z0-9_ .-]{1,40}$/

/**
 * The plain words of an event type: "FTP_LOGIN_FAILED" becomes "FTP login
 * failed". A type that does not look like a plain name is shown as
 * "Other event" and keeps its raw text for the detail pane (§5.12).
 */
export function typeLabel(type: string): string {
  if (!SAFE_TYPE.test(type)) return 'Other event'
  const words = type
    .split(/[_. -]+/)
    .filter((word) => word.length > 0)
    .map((word) => {
      const lower = word.toLowerCase()
      if (ACRONYMS.has(lower)) return lower.toUpperCase()
      if (/^\d+$/.test(word)) return word
      return lower
    })
  if (words.length === 0) return 'Other event'
  const [first, ...rest] = words
  const head = ACRONYMS.has(first.toLowerCase()) ? first : first.charAt(0).toUpperCase() + first.slice(1)
  return [head, ...rest].join(' ')
}

/** The protocol tag of a card: "FTP", "FTP data", "HTTP" or "Other" (§5.3). */
export function protocolLabel(proto: string): string {
  const known = PROTOCOL_LABELS[proto.toLowerCase()]
  if (known) return known
  if (!proto) return ''
  return SAFE_TYPE.test(proto) ? proto : 'Other'
}

/** The chapter label of a phase; an unknown phase keeps its own name (§5.5). */
export function phaseLabel(phase: string): string {
  if (!phase) return 'Unphased'
  const known = PHASE_LABELS[phase.toLowerCase()]
  if (known) return known
  return SAFE_TYPE.test(phase) ? phase : 'Unphased'
}

/** True when the phase is one of the phases the design names. */
export function isKnownPhase(phase: string): boolean {
  return phase.toLowerCase() in PHASE_LABELS
}

/**
 * The endpoint of a card: an IPv6 address is wrapped in brackets, an IPv4
 * address is never changed (§5.10).
 */
export function formatEndpoint(endpoint: string): string {
  const value = endpoint.trim()
  if (!value) return ''
  const separator = value.lastIndexOf(':')
  if (separator <= 0) return value
  const host = value.slice(0, separator)
  const port = value.slice(separator + 1)
  if (!/^\d*$/.test(port)) return value
  if (host.includes(':') && !host.startsWith('[')) return `[${host}]:${port}`
  return value
}

/** The endpoints of a card: "192.0.2.14:51822 → 192.0.2.50:21" (§5.10). */
export function formatEndpoints(src: string, dst: string): string | null {
  const from = formatEndpoint(src ?? '')
  const to = formatEndpoint(dst ?? '')
  if (!from && !to) return null
  if (!from) return to
  if (!to) return from
  return `${from} → ${to}`
}

/** The accessible reading of the endpoints: "from … to …" (§5.10). */
export function endpointsLabel(src: string, dst: string): string {
  const from = formatEndpoint(src ?? '')
  const to = formatEndpoint(dst ?? '')
  if (!from) return ''
  if (!to) return `from ${from}`
  return `from ${from} to ${to}`
}

/** The evidence chip of a packet range: "pkts 14–19" or "pkt 14" (§5.11). */
export function packetRangeLabel(packetNo: number, packetEnd: number): string | null {
  if (!packetNo || packetNo <= 0) return null
  if (!packetEnd || packetEnd <= packetNo) return `pkt ${packetNo}`
  return `pkts ${packetNo}–${packetEnd}`
}

/** The severity of an event; a missing severity is an info event (§5.12). */
export function eventSeverity(event: CaseEvent): Severity {
  return event.severity === 'critical' || event.severity === 'warning' ? event.severity : 'info'
}

/**
 * True when the event is a group that replaces a run of child events
 * (§5.6). A group is an event that has children, or a type that names one.
 */
export function isGroupEvent(event: CaseEvent, childCount: number): boolean {
  if (childCount > 0) return true
  return /group/i.test(event.type) && /group/i.test(event.title)
}

/** The number of supporting events of a finding, taken from its details. */
export function findingEvidenceCount(event: CaseEvent): number | null {
  const details = event.details ?? {}
  for (const key of ['evidenceCount', 'supportingEvents', 'eventCount', 'childCount']) {
    const value = details[key]
    if (typeof value === 'number' && Number.isFinite(value)) return value
  }
  const ids = details.evidenceIds ?? details.supportingEventIds
  if (Array.isArray(ids)) return ids.length
  return null
}

/** True when the event is a finding event (§5.7, §9.4). */
export function isFindingEvent(event: CaseEvent): boolean {
  return /finding/i.test(event.type) || findingEvidenceCount(event) !== null
}

/** The technique of a finding, for example "T1110 Brute Force" (§9.4). */
export function findingTechnique(event: CaseEvent): string | null {
  const details = event.details ?? {}
  const value = details.technique ?? details.attackTechnique ?? details.mitreTechnique
  if (typeof value !== 'string' || value.length === 0) return null
  const name = typeof details.techniqueName === 'string' ? details.techniqueName : null
  return name ? `${value} ${name}` : value
}

/** The ids of the supporting events of a finding (§9.4). */
export function findingEventIds(event: CaseEvent): number[] {
  const details = event.details ?? {}
  const ids = details.evidenceIds ?? details.supportingEventIds
  if (!Array.isArray(ids)) return []
  return ids.filter((id): id is number => typeof id === 'number')
}

/**
 * The text of an event that the search looks at: the title and the values of
 * the details. The search never reaches outside the capture.
 */
export function eventSearchText(event: CaseEvent): string {
  const details = event.details ?? {}
  const parts: string[] = []
  for (const [key, value] of Object.entries(details)) {
    parts.push(key)
    if (value === null || value === undefined) continue
    if (typeof value === 'string') parts.push(value)
    else if (typeof value === 'number' || typeof value === 'boolean') parts.push(String(value))
    else parts.push(JSON.stringify(value))
  }
  return `${event.title ?? ''} ${parts.join(' ')}`.toLowerCase()
}

/** A limitation of an event, shown on the card and in the detail pane (§5.13). */
export interface UncertaintyTag {
  label: string
  icon: 'gap' | 'flag' | 'bookmark' | 'info' | 'file' | 'lock'
  help: string
}

/**
 * The limitations of an event. They are shown on the card when they affect
 * that event, and in full in the detail pane. The UI never invents a
 * limitation: a tag appears only when the data carries it.
 */
export function uncertaintyTags(event: CaseEvent): UncertaintyTag[] {
  const details = event.details ?? {}
  const tags: UncertaintyTag[] = []
  const truthy = (value: unknown): boolean => value === true || value === 'true'

  if (truthy(details.midstream) || truthy(details.startedMidStream)) {
    tags.push({
      label: 'Started mid-stream',
      icon: 'flag',
      help: 'The capture began after this conversation had started, so its opening is missing.',
    })
  }
  if (truthy(details.hasGaps) || truthy(details.gaps) || truthy(details.packetGaps)) {
    tags.push({
      label: 'Gap in data',
      icon: 'gap',
      help: 'Some packets in this conversation are missing from the capture, so parts of it can’t be reconstructed.',
    })
  }
  if (truthy(details.overlap) || truthy(details.overlapping)) {
    tags.push({
      label: 'Overlapping data',
      icon: 'gap',
      help: 'Packets disagreed about some bytes. RACCOON used the earliest copy.',
    })
  }
  if (truthy(details.truncated)) {
    tags.push({
      label: 'Incomplete file',
      icon: 'file',
      help: 'Only part of this file was captured.',
    })
  }
  if (truthy(details.corrupt)) {
    tags.push({
      label: 'Corrupt',
      icon: 'file',
      help: 'The bytes were extracted but the file structure is damaged.',
    })
  }
  if (truthy(details.encrypted) || truthy(details.highEntropy)) {
    tags.push({
      label: 'Looks encrypted or compressed',
      icon: 'lock',
      help: 'This data looks random. It may be encrypted or compressed, so its content can’t be read.',
    })
  }
  if (details.confidence === 'low') {
    tags.push({
      label: 'Low confidence',
      icon: 'info',
      help: 'RACCOON isn’t sure this is really a file of this type.',
    })
  }
  return tags
}
