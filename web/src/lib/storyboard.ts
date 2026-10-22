import type { CaseEvent, Severity } from '../api/types'
import {
  eventSeverity,
  isFindingEvent,
  packetRangeLabel,
  phaseLabel,
  typeLabel,
} from './events'
import { formatDateSeparator, formatDuration, formatElapsedRange, parseTimestamp } from './format'

/**
 * The model of the storyboard feed (UI_Design.md §5.2, §5.5–§5.7): the
 * filters, the rows of the list and the counts of the brief band.
 */

/** The filters of the filter bar (§5.15). */
export interface StoryboardFilters {
  severities: Severity[]
  types: string[]
  protos: string[]
  phases: string[]
  query: string
  /** The time range in milliseconds since the epoch; null means no bound. */
  from: number | null
  to: number | null
  /** Shows the finding events only (§9.4). */
  findingsOnly: boolean
}

export const EMPTY_FILTERS: StoryboardFilters = {
  severities: [],
  types: [],
  protos: [],
  phases: [],
  query: '',
  from: null,
  to: null,
  findingsOnly: false,
}

/** The rows of the feed. Only the kinds the data supports are built (§9.1). */
export type StoryboardRow =
  | { kind: 'chapter'; key: string; phase: string; label: string; count: number; span: string }
  | { kind: 'date'; key: string; label: string }
  | { kind: 'gap'; key: string; label: string }
  | { kind: 'event'; key: string; event: CaseEvent; depth: number }
  | {
      kind: 'group'
      key: string
      event: CaseEvent
      children: CaseEvent[]
      /** The number of children the group has before the filters. */
      total: number
      depth: number
    }
  | { kind: 'not-dated'; key: string; event: CaseEvent; depth: number }

/** The minimum gap between two events that shows a marker, in milliseconds. */
export const MIN_GAP_MS = 5000

/** The share of the capture duration that also shows a gap marker. */
export const GAP_SHARE = 0.1

/** Sorts the events by the order of the server: (ts, id) ascending. */
export function sortEvents(events: CaseEvent[]): CaseEvent[] {
  return [...events].sort((a, b) => {
    const left = parseTimestamp(a.ts)
    const right = parseTimestamp(b.ts)
    if (left !== right) return left - right
    return a.id - b.id
  })
}

/** True when a filter narrows the list. */
export function filtersActive(filters: StoryboardFilters): boolean {
  return (
    filters.severities.length > 0 ||
    filters.types.length > 0 ||
    filters.protos.length > 0 ||
    filters.phases.length > 0 ||
    filters.query.trim().length > 0 ||
    filters.from !== null ||
    filters.to !== null ||
    filters.findingsOnly
  )
}

/** True when the event passes the filters. */
export function matchesFilters(
  event: CaseEvent,
  filters: StoryboardFilters,
  searchText?: (event: CaseEvent) => string,
): boolean {
  if (filters.findingsOnly && !isFindingEvent(event)) return false
  if (filters.severities.length > 0 && !filters.severities.includes(eventSeverity(event))) {
    return false
  }
  if (filters.types.length > 0 && !filters.types.includes(event.type)) return false
  if (filters.protos.length > 0 && !filters.protos.includes(event.proto)) return false
  if (filters.phases.length > 0 && !filters.phases.includes(event.phase)) return false
  const query = filters.query.trim().toLowerCase()
  if (query.length > 0) {
    const text = searchText ? searchText(event) : `${event.title ?? ''}`.toLowerCase()
    if (!text.includes(query)) return false
  }
  const ts = parseTimestamp(event.ts)
  if (filters.from !== null && ts < filters.from) return false
  if (filters.to !== null && ts > filters.to) return false
  return true
}

/** The counts of the brief band: the events per severity (§5.19). */
export function severityCounts(events: CaseEvent[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { info: 0, warning: 0, critical: 0 }
  for (const event of events) counts[eventSeverity(event)] += 1
  return counts
}

/** The event types present in the case, in alphabetical order (§5.15). */
export function presentTypes(events: CaseEvent[]): string[] {
  const types = new Set<string>()
  for (const event of events) if (event.type) types.add(event.type)
  return [...types].sort()
}

/** The protocols present in the case, in the order of the design (§5.15). */
export function presentProtocols(events: CaseEvent[]): string[] {
  const order = ['ftp', 'ftp-data', 'http', 'https', 'dns', 'tcp', 'udp', 'unknown']
  const found = new Set<string>()
  for (const event of events) if (event.proto) found.add(event.proto)
  const known = order.filter((proto) => found.has(proto))
  const rest = [...found].filter((proto) => !order.includes(proto)).sort()
  return [...known, ...rest]
}

/** The phases present in the case, in the order of the design (§5.5). */
export function presentPhases(events: CaseEvent[]): string[] {
  const order = ['recon', 'access', 'action', 'exfil', 'c2']
  const found = new Set<string>()
  for (const event of events) if (event.phase) found.add(event.phase)
  const known = order.filter((phase) => found.has(phase))
  const rest = [...found].filter((phase) => !order.includes(phase)).sort()
  return [...known, ...rest]
}

export interface BuildRowsOptions {
  /** The ids of the groups that are expanded. */
  expandedGroups?: ReadonlySet<number>
  /** The time basis of the date separators: "utc" or "local". */
  basis?: 'utc' | 'local'
  /** The start of the capture; the elapsed time of the cards counts from it. */
  captureStart?: number
  /** The number of events of the whole case, used for the "so far" count. */
  total?: number
  /**
   * Every event of the case. The filters hide the children of a group that do
   * not match, but the group still shows how many it holds (§5.6).
   */
  allEvents?: CaseEvent[]
}

/**
 * Builds the rows of the feed. The chapter headers appear only when the data
 * has phases, the group cards only when an event has children, and the
 * date separators only when the capture crosses midnight (§5.2, §5.5–§5.6).
 */
export function buildRows(events: CaseEvent[], options: BuildRowsOptions = {}): StoryboardRow[] {
  const expanded = options.expandedGroups ?? new Set<number>()
  const basis = options.basis ?? 'utc'
  const sorted = sortEvents(events)
  const rows: StoryboardRow[] = []

  const childrenOf = new Map<number, CaseEvent[]>()
  const topLevel: CaseEvent[] = []
  for (const event of sorted) {
    if (event.parentId && event.parentId > 0) {
      const list = childrenOf.get(event.parentId)
      if (list) list.push(event)
      else childrenOf.set(event.parentId, [event])
      continue
    }
    topLevel.push(event)
  }

  // The number of children of every group, before the filters.
  const totalsOf = new Map<number, number>()
  for (const event of options.allEvents ?? sorted) {
    if (!event.parentId || event.parentId <= 0) continue
    totalsOf.set(event.parentId, (totalsOf.get(event.parentId) ?? 0) + 1)
  }

  const timed = sorted.filter((event) => Boolean(event.ts))
  const start = options.captureStart ?? (timed.length > 0 ? parseTimestamp(timed[0].ts) : 0)
  const end = timed.length > 0 ? parseTimestamp(timed[timed.length - 1].ts) : start
  const duration = Math.max(0, end - start)
  const gapThreshold = Math.max(MIN_GAP_MS, duration * GAP_SHARE)

  const hasPhases = topLevel.some((event) => Boolean(event.phase))
  const phases = hasPhases ? groupByPhase(topLevel) : []

  const emitEvent = (event: CaseEvent, depth: number): void => {
    const children = childrenOf.get(event.id) ?? []
    if (children.length > 0) {
      rows.push({
        kind: 'group',
        key: `group-${event.id}`,
        event,
        children,
        total: totalsOf.get(event.id) ?? children.length,
        depth,
      })
      if (expanded.has(event.id)) {
        for (const child of children) emitEvent(child, depth + 1)
      }
      return
    }
    if (!event.ts) {
      rows.push({ kind: 'not-dated', key: `event-${event.id}`, event, depth })
      return
    }
    rows.push({ kind: 'event', key: `event-${event.id}`, event, depth })
  }

  const emitRun = (run: CaseEvent[]): void => {
    let lastDay = ''
    let lastTs: number | null = null
    for (const event of run) {
      const ts = parseTimestamp(event.ts)
      const day = dayKey(ts, basis)
      if (lastDay && day !== lastDay) {
        rows.push({
          kind: 'date',
          key: `date-${day}-${event.id}`,
          label: formatDateSeparator(ts, basis),
        })
      }
      if (lastTs !== null && ts - lastTs >= gapThreshold) {
        rows.push({
          kind: 'gap',
          key: `gap-${event.id}`,
          label: `${formatDuration(ts - lastTs)} with no events`,
        })
      }
      lastDay = day
      lastTs = ts
      emitEvent(event, 0)
    }
  }

  if (hasPhases) {
    for (const phase of phases) {
      rows.push({
        kind: 'chapter',
        key: `chapter-${phase.phase}`,
        phase: phase.phase,
        label: phaseLabel(phase.phase),
        count: phase.events.length,
        span: phaseSpan(phase.events, start),
      })
      emitRun(phase.events)
    }
    return rows
  }

  emitRun(topLevel)
  return rows
}

interface PhaseRun {
  phase: string
  events: CaseEvent[]
}

/** Groups the events by phase; the order follows the earliest event. */
function groupByPhase(events: CaseEvent[]): PhaseRun[] {
  const runs = new Map<string, PhaseRun>()
  for (const event of events) {
    const phase = event.phase || ''
    const run = runs.get(phase)
    if (run) run.events.push(event)
    else runs.set(phase, { phase, events: [event] })
  }
  return [...runs.values()].sort((a, b) => {
    const left = a.events.length > 0 ? parseTimestamp(a.events[0].ts) : 0
    const right = b.events.length > 0 ? parseTimestamp(b.events[0].ts) : 0
    return left - right
  })
}

/** The time span of a chapter, for example "8.4 s". */
function phaseSpan(events: CaseEvent[], start: number): string {
  if (events.length === 0) return ''
  const first = parseTimestamp(events[0].ts)
  const last = parseTimestamp(events[events.length - 1].ts)
  if (last - first < 1000) return formatElapsedRange(first - start, last - start)
  return formatDuration(last - first)
}

/** The calendar day of a timestamp, in the chosen time zone. */
function dayKey(timestamp: number, basis: 'utc' | 'local'): string {
  const date = new Date(timestamp)
  const year = basis === 'utc' ? date.getUTCFullYear() : date.getFullYear()
  const month = basis === 'utc' ? date.getUTCMonth() : date.getMonth()
  const day = basis === 'utc' ? date.getUTCDate() : date.getDate()
  return `${year}-${month}-${day}`
}

/**
 * The filters of a deep link (UI_Design.md §3.2). The parameters are
 * comma-separated lists; an unknown value is dropped.
 */
export function filtersFromParams(params: Record<string, string>): StoryboardFilters {
  const severities = splitList(params.sev).filter(
    (value): value is Severity => value === 'info' || value === 'warning' || value === 'critical',
  )
  return {
    severities,
    types: splitList(params.type),
    protos: splitList(params.proto),
    phases: splitList(params.phase),
    query: params.q ?? '',
    from: parseBound(params.from),
    to: parseBound(params.to),
    findingsOnly: false,
  }
}

/** The deep-link parameters of the filters; empty values are left out. */
export function filtersToParams(filters: StoryboardFilters): Record<string, string> {
  const params: Record<string, string> = {}
  if (filters.severities.length > 0) params.sev = filters.severities.join(',')
  if (filters.types.length > 0) params.type = filters.types.join(',')
  if (filters.protos.length > 0) params.proto = filters.protos.join(',')
  if (filters.phases.length > 0) params.phase = filters.phases.join(',')
  if (filters.query.trim().length > 0) params.q = filters.query
  if (filters.from !== null) params.from = new Date(filters.from).toISOString()
  if (filters.to !== null) params.to = new Date(filters.to).toISOString()
  return params
}

/** Splits a comma-separated list of a deep link. */
export function splitList(value: string | undefined): string[] {
  if (!value) return []
  return value
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part.length > 0)
}

/** Reads a time bound of a deep link; an unusable value is dropped. */
function parseBound(value: string | undefined): number | null {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isNaN(parsed) ? null : parsed
}

/** The rows of the events that match the filters, in the order of the feed. */
export function filterEvents(
  events: CaseEvent[],
  filters: StoryboardFilters,
  searchText?: (event: CaseEvent) => string,
): CaseEvent[] {
  if (!filtersActive(filters)) return events
  return events.filter((event) => matchesFilters(event, filters, searchText))
}

/**
 * Parses a jump-to-time value (UI_Design.md §5.16). "00:41" is an elapsed
 * time and "14:03:07" is a wall-clock time of day. The result says which of
 * the two it is, because the capture start decides the answer.
 */
export function parseJumpTime(
  value: string,
): { kind: 'elapsed' | 'clock'; time: number } | null {
  const text = value.trim()
  if (text.length === 0) return null
  const parts = text.split(':')
  if (parts.length < 2 || parts.length > 3) return null
  if (!parts.every((part) => /^\d{1,2}$/.test(part))) return null
  const numbers = parts.map((part) => Number(part))
  if (numbers.some((number) => !Number.isFinite(number))) return null
  if (parts.length === 2) {
    const [minutes, seconds] = numbers
    if (seconds > 59) return null
    return { kind: 'elapsed', time: minutes * 60_000 + seconds * 1000 }
  }
  const [hours, minutes, seconds] = numbers
  if (minutes > 59 || seconds > 59) return null
  return { kind: 'clock', time: hours * 3_600_000 + minutes * 60_000 + seconds * 1000 }
}

/**
 * The event that holds a time, or the nearest one before it. The wall-clock
 * time of day is matched against the time of day of the capture.
 */
export function findEventByTime(
  events: CaseEvent[],
  time: number,
  kind: 'elapsed' | 'clock',
  captureStart: number,
): number | null {
  if (events.length === 0) return null
  const sorted = sortEvents(events)
  const target = kind === 'elapsed' ? captureStart + time : timeOfDay(parseTimestamp(sorted[0].ts)) + time
  // The last event at or before the target, so the reader lands on what had
  // already happened. A target before everything lands on the first event.
  let best: number | null = null
  for (const event of sorted) {
    if (parseTimestamp(event.ts) > target) break
    best = event.id
  }
  return best ?? sorted[0].id
}

/**
 * The event whose packet range holds a packet number, or the nearest one.
 * The events without a packet are never chosen.
 */
export function findEventByPacket(events: CaseEvent[], packetNo: number): number | null {
  let best: number | null = null
  let bestDistance = Number.POSITIVE_INFINITY
  for (const event of events) {
    if (!event.packetNo || event.packetNo <= 0) continue
    const end = event.packetEnd && event.packetEnd > event.packetNo ? event.packetEnd : event.packetNo
    if (packetNo >= event.packetNo && packetNo <= end) return event.id
    const distance = packetNo < event.packetNo ? event.packetNo - packetNo : packetNo - end
    if (distance < bestDistance) {
      bestDistance = distance
      best = event.id
    }
  }
  return best
}

/** The milliseconds since midnight of a timestamp. */
function timeOfDay(timestamp: number): number {
  const date = new Date(timestamp)
  return (
    date.getUTCHours() * 3_600_000 +
    date.getUTCMinutes() * 60_000 +
    date.getUTCSeconds() * 1000 +
    date.getUTCMilliseconds()
  )
}

/** The label of a filter chip of the type filter. */
export function typeChipLabel(type: string): string {
  return typeLabel(type)
}

/** The label of the packet range of an event, for the evidence chip. */
export function eventPacketLabel(event: CaseEvent): string | null {
  return packetRangeLabel(event.packetNo, event.packetEnd)
}

/** True when the event is a finding, used for the bookmark card (§5.7). */
export function eventIsFinding(event: CaseEvent): boolean {
  return isFindingEvent(event)
}
