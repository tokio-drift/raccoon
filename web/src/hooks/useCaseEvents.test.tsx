import { act, renderHook } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ManualEventStream } from '../api/events'
import type { RaccoonApi } from '../api/api'
import type { ServerEvent } from '../api/types'
import { applyEvents, useCaseEvents } from './useCaseEvents'

function makeApi() {
  const stream = new ManualEventStream()
  const api = { openEventStream: () => stream } as unknown as RaccoonApi
  return { api, stream }
}

afterEach(() => {
  vi.useRealTimers()
})

describe('useCaseEvents', () => {
  it('batches the events before it updates the state', async () => {
    vi.useFakeTimers()
    const { api, stream } = makeApi()
    const { result } = renderHook(() => useCaseEvents('case-1', api))

    act(() => {
      stream.emit({ name: 'progress', data: { stage: 'read', percent: 15, packets: 1, bytes: 1, streams: 0, files: 0 } })
      stream.emit({ name: 'progress', data: { stage: 'process', percent: 80, packets: 2, bytes: 2, streams: 1, files: 0 } })
      stream.emit({ name: 'progress', data: { stage: 'process', percent: 92, packets: 3, bytes: 3, streams: 1, files: 1 } })
    })

    // Nothing is applied before the batch window closes.
    expect(result.current.progress).toBeNull()

    act(() => {
      vi.advanceTimersByTime(500)
    })

    expect(result.current.progress).toMatchObject({ percent: 92, stage: 'process' })
  })

  it('marks the timeline as ready', async () => {
    vi.useFakeTimers()
    const { api, stream } = makeApi()
    const { result } = renderHook(() => useCaseEvents('case-1', api))

    act(() => {
      stream.emit({ name: 'ready', data: { events: 43, files: 5 } })
      vi.advanceTimersByTime(500)
    })

    expect(result.current.timelineReady).toBe(true)
    expect(result.current.ready).toEqual({ events: 43, files: 5 })
  })

  it('reports the connection state', async () => {
    const { api, stream } = makeApi()
    const { result } = renderHook(() => useCaseEvents('case-1', api))

    act(() => {
      stream.setState({ status: 'reconnecting', attempt: 2 })
    })

    expect(result.current.status).toBe('reconnecting')
    expect(result.current.attempt).toBe(2)
  })

  it('marks a quiet connection as stale', async () => {
    vi.useFakeTimers()
    const { api, stream } = makeApi()
    const { result } = renderHook(() => useCaseEvents('case-1', api))

    act(() => {
      stream.emit({ name: 'progress', data: { stage: 'read', percent: 15, packets: 1, bytes: 1, streams: 0, files: 0 } })
      vi.advanceTimersByTime(500)
    })
    expect(result.current.stale).toBe(false)

    act(() => {
      vi.advanceTimersByTime(16000)
    })
    expect(result.current.stale).toBe(true)
  })

  it('does nothing without a case', () => {
    const { api } = makeApi()
    const { result } = renderHook(() => useCaseEvents(null, api))
    expect(result.current.status).toBe('idle')
    expect(result.current.progress).toBeNull()
  })
})

describe('applyEvents', () => {
  const base = {
    status: 'open' as const,
    attempt: 0,
    progress: null,
    timelineReady: false,
    ready: null,
    verdicts: {},
    done: false,
    error: null,
    stale: false,
    lastUpdateAt: null,
  }

  it('keeps the order of the files when a verdict arrives', () => {
    const state = applyEvents(
      base,
      [
        { name: 'verdict', data: { fileId: 2, sha256: 'b'.repeat(64), status: 'malicious' } },
        { name: 'verdict', data: { fileId: 1, sha256: 'a'.repeat(64), status: 'no_detections' } },
      ],
      1000,
    )
    // The verdicts are a map by file id, so an arriving verdict never changes
    // the order of the file list of the view.
    expect(Object.keys(state.verdicts)).toEqual(['1', '2'])
    expect(state.verdicts[2]).toMatchObject({ status: 'malicious' })
    expect(state.verdicts[1]).toMatchObject({ status: 'no_detections' })
  })

  it('replaces the verdict of a file instead of adding a second one', () => {
    const state = applyEvents(
      base,
      [
        { name: 'verdict', data: { fileId: 1, sha256: 'a'.repeat(64), status: 'unknown' } },
        { name: 'verdict', data: { fileId: 1, sha256: 'a'.repeat(64), status: 'malicious' } },
      ],
      1000,
    )
    expect(Object.keys(state.verdicts)).toEqual(['1'])
    expect(state.verdicts[1].status).toBe('malicious')
  })

  it('remembers the finished analysis and the error', () => {
    const events: ServerEvent[] = [
      { name: 'done', data: { caseId: 'case-1' } },
      { name: 'error', data: { code: 'internal', message: 'boom' } },
    ]
    const state = applyEvents(base, events, 1000)
    expect(state.done).toBe(true)
    expect(state.error).toEqual({ code: 'internal', message: 'boom' })
  })
})
