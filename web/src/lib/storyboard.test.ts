import { describe, expect, it } from 'vitest'

import type { CaseEvent } from '../api/types'
import {
  buildRows,
  EMPTY_FILTERS,
  filtersActive,
  filtersFromParams,
  filtersToParams,
  filterEvents,
  findEventByPacket,
  findEventByTime,
  matchesFilters,
  parseJumpTime,
  presentPhases,
  presentProtocols,
  presentTypes,
  severityCounts,
  sortEvents,
  splitList,
  type StoryboardFilters,
} from './storyboard'

function event(overrides: Partial<CaseEvent> & { id: number }): CaseEvent {
  return {
    ts: '2026-01-01T12:00:00.000000000Z',
    packetNo: 0,
    packetEnd: 0,
    type: 'STREAM_OPENED',
    severity: 'info',
    phase: '',
    streamId: 0,
    src: '',
    dst: '',
    proto: '',
    title: 'Event',
    details: {},
    explain: '',
    parentId: 0,
    fileId: 0,
    findingIds: [],
    ...overrides,
  }
}

const FTP_LOGIN = event({
  id: 1,
  ts: '2026-01-01T12:00:01.000000000Z',
  type: 'FTP_LOGIN_FAILED',
  severity: 'warning',
  phase: 'access',
  proto: 'ftp',
  streamId: 2,
  src: '192.0.2.14:51822',
  dst: '192.0.2.50:21',
  title: 'FTP login failed',
  details: { user: 'root', password: 'hunter2' },
})

const HTTP = event({
  id: 2,
  ts: '2026-01-01T12:00:02.000000000Z',
  type: 'HTTP_TRANSACTION',
  severity: 'critical',
  phase: 'exfil',
  proto: 'http',
  streamId: 3,
  title: 'GET /secret',
  details: { method: 'GET', url: 'http://example.test/secret' },
})

const FINDING = event({
  id: 3,
  ts: '2026-01-01T12:00:03.000000000Z',
  type: 'FINDING',
  severity: 'critical',
  title: 'Brute force',
  details: { evidenceIds: [1, 2], technique: 'T1110' },
})

describe('the filters of the storyboard', () => {
  it('knows when a filter narrows the list', () => {
    expect(filtersActive(EMPTY_FILTERS)).toBe(false)
    expect(filtersActive({ ...EMPTY_FILTERS, severities: ['critical'] })).toBe(true)
    expect(filtersActive({ ...EMPTY_FILTERS, query: '  ' })).toBe(false)
    expect(filtersActive({ ...EMPTY_FILTERS, query: 'ftp' })).toBe(true)
    expect(filtersActive({ ...EMPTY_FILTERS, findingsOnly: true })).toBe(true)
  })

  it('keeps an event that matches every filter', () => {
    const filters: StoryboardFilters = {
      ...EMPTY_FILTERS,
      severities: ['warning', 'critical'],
      protos: ['ftp'],
      phases: ['access'],
      query: 'login',
    }
    expect(matchesFilters(FTP_LOGIN, filters)).toBe(true)
    expect(matchesFilters(HTTP, filters)).toBe(false)
  })

  it('shows only the findings when the finding filter is on', () => {
    const filters = { ...EMPTY_FILTERS, findingsOnly: true }
    const kept = filterEvents([FTP_LOGIN, HTTP, FINDING], filters)
    expect(kept.map((item) => item.id)).toEqual([3])
  })

  it('counts the events per severity', () => {
    const counts = severityCounts([FTP_LOGIN, HTTP, FINDING])
    expect(counts).toEqual({ info: 0, warning: 1, critical: 2 })
  })

  it('lists the types, the protocols and the phases of the case', () => {
    const events = [FTP_LOGIN, HTTP]
    expect(presentTypes(events)).toEqual(['FTP_LOGIN_FAILED', 'HTTP_TRANSACTION'])
    expect(presentProtocols(events)).toEqual(['ftp', 'http'])
    expect(presentPhases(events)).toEqual(['access', 'exfil'])
  })
})

describe('the deep-link parameters of the filters', () => {
  it('reads a comma-separated list', () => {
    expect(splitList('critical,warning')).toEqual(['critical', 'warning'])
    expect(splitList('critical, warning')).toEqual(['critical', 'warning'])
    expect(splitList('')).toEqual([])
    expect(splitList(undefined)).toEqual([])
  })

  it('reads the filters of a link', () => {
    const filters = filtersFromParams({
      sev: 'critical,warning',
      type: 'HTTP_TRANSACTION',
      proto: 'http',
      phase: 'exfil',
      q: 'secret',
      from: '2026-01-01T12:00:00.000Z',
    })
    expect(filters.severities).toEqual(['critical', 'warning'])
    expect(filters.types).toEqual(['HTTP_TRANSACTION'])
    expect(filters.protos).toEqual(['http'])
    expect(filters.phases).toEqual(['exfil'])
    expect(filters.query).toBe('secret')
    expect(filters.from).toBe(Date.parse('2026-01-01T12:00:00.000Z'))
  })

  it('drops an unusable value', () => {
    const filters = filtersFromParams({ sev: 'critical,purple', from: 'not-a-date' })
    expect(filters.severities).toEqual(['critical'])
    expect(filters.from).toBeNull()
  })

  it('writes the filters of a link and leaves the empty ones out', () => {
    const params = filtersToParams({
      ...EMPTY_FILTERS,
      severities: ['critical'],
      types: ['HTTP_TRANSACTION'],
      query: 'secret',
    })
    expect(params).toEqual({ sev: 'critical', type: 'HTTP_TRANSACTION', q: 'secret' })
    expect(filtersToParams(EMPTY_FILTERS)).toEqual({})
  })
})

describe('the rows of the feed', () => {
  it('sorts the events by time and then by id', () => {
    const late = event({ id: 3, ts: '2026-01-01T12:00:02.000000000Z' })
    const early = event({ id: 1, ts: '2026-01-01T12:00:01.000000000Z' })
    const same = event({ id: 2, ts: '2026-01-01T12:00:01.000000000Z' })
    expect(sortEvents([late, early, same]).map((item) => item.id)).toEqual([1, 2, 3])
  })

  it('builds no chapter when the data has no phase', () => {
    const rows = buildRows([event({ id: 1 })])
    expect(rows.every((row) => row.kind !== 'chapter')).toBe(true)
  })

  it('builds a chapter per phase, in the order of the first event', () => {
    const rows = buildRows([HTTP, FTP_LOGIN])
    const chapters = rows.filter((row) => row.kind === 'chapter')
    expect(chapters.map((row) => (row.kind === 'chapter' ? row.phase : ''))).toEqual([
      'access',
      'exfil',
    ])
  })

  it('replaces a run of children with a group card', () => {
    const parent = event({ id: 10, title: '12 failed FTP logins' })
    const child = event({ id: 11, parentId: 10 })
    const rows = buildRows([parent, child])
    const group = rows.find((row) => row.kind === 'group')
    expect(group).toBeDefined()
    expect(group?.kind === 'group' ? group.children.length : 0).toBe(1)
    expect(rows.filter((row) => row.kind === 'event')).toHaveLength(0)
  })

  it('shows the children of a group when it is expanded', () => {
    const parent = event({ id: 10 })
    const child = event({ id: 11, parentId: 10 })
    const rows = buildRows([parent, child], { expandedGroups: new Set([10]) })
    expect(rows.filter((row) => row.kind === 'event')).toHaveLength(1)
  })

  it('counts the children a group had before the filters', () => {
    const parent = event({ id: 10 })
    const child = event({ id: 11, parentId: 10 })
    const rows = buildRows([parent, child], { allEvents: [parent, child] })
    const group = rows.find((row) => row.kind === 'group')
    expect(group?.kind === 'group' ? group.total : 0).toBe(1)
  })

  it('puts an event without a time under its own row', () => {
    const rows = buildRows([event({ id: 1, ts: '' })])
    expect(rows[0]?.kind).toBe('not-dated')
  })

  it('shows a date separator when the capture crosses midnight', () => {
    const first = event({ id: 1, ts: '2026-01-01T23:59:59.000000000Z' })
    const second = event({ id: 2, ts: '2026-01-02T00:00:01.000000000Z' })
    const rows = buildRows([first, second])
    expect(rows.filter((row) => row.kind === 'date')).toHaveLength(1)
  })

  it('shows a gap marker when the capture was quiet', () => {
    const first = event({ id: 1, ts: '2026-01-01T12:00:00.000000000Z' })
    const second = event({ id: 2, ts: '2026-01-01T12:05:00.000000000Z' })
    const rows = buildRows([first, second])
    expect(rows.filter((row) => row.kind === 'gap')).toHaveLength(1)
  })
})

describe('the jump controls of the list', () => {
  it('reads an elapsed time and a clock time', () => {
    expect(parseJumpTime('00:41')).toEqual({ kind: 'elapsed', time: 41_000 })
    expect(parseJumpTime('01:02:03')).toEqual({ kind: 'clock', time: 3_723_000 })
  })

  it('refuses a value it cannot read', () => {
    expect(parseJumpTime('')).toBeNull()
    expect(parseJumpTime('later')).toBeNull()
    expect(parseJumpTime('00:75')).toBeNull()
  })

  it('finds the event that holds a time', () => {
    const start = Date.parse('2026-01-01T12:00:00.000Z')
    const events = [
      event({ id: 1, ts: '2026-01-01T12:00:00.000000000Z' }),
      event({ id: 2, ts: '2026-01-01T12:00:30.000000000Z' }),
      event({ id: 3, ts: '2026-01-01T12:01:00.000000000Z' }),
    ]
    // The last event at or before the target.
    expect(findEventByTime(events, 40_000, 'elapsed', start)).toBe(2)
    expect(findEventByTime(events, 10_000, 'elapsed', start)).toBe(1)
    // A target before the first event lands on the first event.
    expect(findEventByTime(events, 0, 'elapsed', start)).toBe(1)
  })

  it('finds the event whose packet range holds a packet', () => {
    const events = [
      event({ id: 1, packetNo: 10, packetEnd: 19 }),
      event({ id: 2, packetNo: 40, packetEnd: 40 }),
    ]
    expect(findEventByPacket(events, 15)).toBe(1)
    expect(findEventByPacket(events, 40)).toBe(2)
  })

  it('falls back to the nearest event with a packet', () => {
    const events = [event({ id: 1, packetNo: 10, packetEnd: 19 })]
    expect(findEventByPacket(events, 25)).toBe(1)
  })

  it('never chooses an event without a packet', () => {
    expect(findEventByPacket([event({ id: 1 })], 5)).toBeNull()
  })
})
