import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from '../api/api'
import type { CaseEvent, EventQuery, FileQuery, Page } from '../api/types'
import { EMPTY_FILTERS } from '../lib/storyboard'
import { useStoryboard } from './useStoryboard'

const CASE_ID = '20260101-120000-abcdef'

function event(id: number, overrides: Partial<CaseEvent> = {}): CaseEvent {
  return {
    id,
    ts: `2026-01-01T12:00:${String(id).padStart(2, '0')}.000000000Z`,
    packetNo: id,
    packetEnd: id,
    type: 'HTTP_TRANSACTION',
    severity: 'info',
    phase: 'access',
    streamId: 1,
    src: '192.0.2.14:51822',
    dst: '192.0.2.50:80',
    proto: 'http',
    title: `Event ${id}`,
    details: {},
    explain: '',
    parentId: 0,
    fileId: 0,
    findingIds: [],
    ...overrides,
  }
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function makeApi(events: CaseEvent[]) {
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page(events))
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page([]))
  const api = { listEvents, listFiles } as unknown as RaccoonApi
  return { api, listEvents, listFiles }
}

function renderStoryboard(
  api: RaccoonApi,
  overrides: Partial<Parameters<typeof useStoryboard>[0]> = {},
) {
  return renderHook(() =>
    useStoryboard({
      caseId: CASE_ID,
      api,
      filters: EMPTY_FILTERS,
      onFiltersChange: () => undefined,
      total: events_total(events_of(api)),
      basis: 'utc',
      initialEventId: null,
      ...overrides,
    }),
  )
}

// The mock API keeps the events; these helpers read them back.
const EVENTS = new WeakMap<RaccoonApi, CaseEvent[]>()
function events_of(api: RaccoonApi): CaseEvent[] {
  return EVENTS.get(api) ?? []
}
function events_total(events: CaseEvent[]): number {
  return events.length
}

beforeEach(() => {
  window.localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useStoryboard', () => {
  it('loads every event of the case once', async () => {
    const events = [event(1), event(2), event(3)]
    const { api, listEvents } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.events).toHaveLength(3)
    expect(listEvents).toHaveBeenCalledTimes(1)
    expect(listEvents.mock.calls[0][1]).toMatchObject({ flat: true, limit: 1000 })
  })

  it('loads the carved files with the low-confidence ones included', async () => {
    const events = [event(1)]
    const { api, listFiles } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(listFiles).toHaveBeenCalledWith(CASE_ID, { confidence: 'all' })
  })

  it('reports an error instead of an empty list', async () => {
    const api = {
      listEvents: vi.fn(async () => {
        throw new Error('boom')
      }),
      listFiles: vi.fn(async () => page([])),
    } as unknown as RaccoonApi
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.error).not.toBeNull()
  })

  it('filters the events without asking the server again', async () => {
    const events = [
      event(1, { severity: 'critical', type: 'HTTP_TRANSACTION' }),
      event(2, { severity: 'info', type: 'DNS_QUERY' }),
    ]
    const { api, listEvents } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api, {
      filters: { ...EMPTY_FILTERS, severities: ['critical'] },
    })

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.filtered).toHaveLength(1)
    expect(result.current.filtered[0].id).toBe(1)
    expect(listEvents).toHaveBeenCalledTimes(1)
  })

  it('selects the first critical event when nothing is remembered', async () => {
    const events = [
      event(1, { severity: 'info' }),
      event(2, { severity: 'critical' }),
      event(3, { severity: 'warning' }),
    ]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.selectedId).toBe(2)
  })

  it('selects the first event when the case has no critical event', async () => {
    const events = [event(1, { severity: 'info' }), event(2, { severity: 'warning' })]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.selectedId).toBe(1)
  })

  it('selects the event of a deep link', async () => {
    const events = [event(1), event(2), event(3)]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api, { initialEventId: 3 })

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.selectedId).toBe(3)
  })

  it('remembers the selection per case', async () => {
    const events = [event(1), event(2)]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const first = renderStoryboard(api)
    await waitFor(() => expect(first.result.current.loading).toBe(false))

    act(() => first.result.current.select(2))
    expect(first.result.current.selectedId).toBe(2)

    const second = renderStoryboard(api)
    await waitFor(() => expect(second.result.current.loading).toBe(false))
    expect(second.result.current.selectedId).toBe(2)
  })

  it('remembers the open groups per case', async () => {
    const events = [event(1), event(2)]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const first = renderStoryboard(api)
    await waitFor(() => expect(first.result.current.loading).toBe(false))

    act(() => first.result.current.toggleGroup(7))
    expect(first.result.current.expandedGroups).toEqual([7])

    const second = renderStoryboard(api)
    await waitFor(() => expect(second.result.current.loading).toBe(false))
    expect(second.result.current.expandedGroups).toEqual([7])
  })

  it('counts the events per severity and the findings of the case', async () => {
    const events = [
      event(1, { severity: 'critical' }),
      event(2, { severity: 'warning' }),
      event(3, { severity: 'info' }),
      event(4, { type: 'FINDING', findingIds: [1] }),
    ]
    const { api } = makeApi(events)
    EVENTS.set(api, events)
    const { result } = renderStoryboard(api)

    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.counts).toEqual({ info: 2, warning: 1, critical: 1 })
    expect(result.current.findingCount).toBe(1)
  })
})
