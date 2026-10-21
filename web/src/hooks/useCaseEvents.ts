import { useCallback, useEffect, useRef, useState } from 'react'
import type { RaccoonApi } from '../api/api'
import type { EventStream, EventStreamStatus } from '../api/events'
import type { ErrorEvent, ProgressEvent, ReadyEvent, ServerEvent, VerdictEvent } from '../api/types'

/** The state the shell derives from the event stream of a case. */
export interface CaseEventsData {
  status: EventStreamStatus | 'idle'
  /** The number of consecutive failed connection attempts. */
  attempt: number
  progress: ProgressEvent | null
  /** The timeline is complete and can be browsed. */
  timelineReady: boolean
  ready: ReadyEvent | null
  /** The verdicts by file id; updating one never re-sorts the list. */
  verdicts: Record<number, VerdictEvent>
  done: boolean
  error: ErrorEvent | null
  /** The connection has been quiet for too long. */
  stale: boolean
  /** The time of the last event, in milliseconds since the epoch. */
  lastUpdateAt: number | null
}

/** The state of the stream, with the actions the shell can trigger. */
export interface CaseEventsState extends CaseEventsData {
  /** Tries the connection again right now. */
  reconnect: () => void
}

/** Server events are delivered in batches to keep the views calm. */
export const EVENT_BATCH_MS = 500

/** A connection without traffic for this long is marked as stale. */
export const STALE_AFTER_MS = 15000

const EMPTY_STATE: CaseEventsData = {
  status: 'idle',
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

/**
 * Subscribes to the event stream of a case. The server events are collected
 * and applied in batches of {@link EVENT_BATCH_MS} milliseconds, so a burst of
 * events costs one render instead of one render per event.
 */
export function useCaseEvents(caseId: string | null, api: RaccoonApi): CaseEventsState {
  const [state, setState] = useState<CaseEventsData>(EMPTY_STATE)
  const buffer = useRef<ServerEvent[]>([])
  const lastActivity = useRef<number | null>(null)
  const staleRef = useRef(false)
  const streamRef = useRef<EventStream | null>(null)

  useEffect(() => {
    if (!caseId) {
      setState(EMPTY_STATE)
      return
    }

    const stream = api.openEventStream(caseId)
    streamRef.current = stream
    const flush = window.setInterval(() => {
      if (buffer.current.length === 0) return
      const events = buffer.current
      buffer.current = []
      setState((previous) => applyEvents(previous, events, Date.now()))
    }, EVENT_BATCH_MS)

    const unsubscribes = [
      stream.subscribe((event) => {
        buffer.current.push(event)
      }),
      stream.onStateChange((connection) => {
        setState((previous) => ({
          ...previous,
          status: connection.status,
          attempt: connection.attempt,
        }))
      }),
      stream.onActivity(() => {
        lastActivity.current = Date.now()
        if (staleRef.current) {
          staleRef.current = false
          setState((previous) => ({ ...previous, stale: false }))
        }
      }),
    ]

    const watcher = window.setInterval(() => {
      const last = lastActivity.current
      const stale = last !== null && Date.now() - last > STALE_AFTER_MS
      if (stale !== staleRef.current) {
        staleRef.current = stale
        setState((previous) => ({ ...previous, stale }))
      }
    }, 1000)

    return () => {
      window.clearInterval(flush)
      window.clearInterval(watcher)
      for (const unsubscribe of unsubscribes) unsubscribe()
      stream.close()
      streamRef.current = null
    }
  }, [api, caseId])

  const reconnect = useCallback(() => {
    streamRef.current?.reconnect()
  }, [])

  return { ...state, reconnect }
}

/** Applies a batch of server events to the state of a case. */
export function applyEvents(
  previous: CaseEventsData,
  events: ServerEvent[],
  now: number,
): CaseEventsData {
  let next = previous
  for (const event of events) {
    switch (event.name) {
      case 'progress':
        next = { ...next, progress: event.data as ProgressEvent, lastUpdateAt: now }
        break
      case 'ready':
        next = {
          ...next,
          ready: event.data as ReadyEvent,
          timelineReady: true,
          lastUpdateAt: now,
        }
        break
      case 'verdict': {
        const verdict = event.data as VerdictEvent
        next = {
          ...next,
          verdicts: { ...next.verdicts, [verdict.fileId]: verdict },
          lastUpdateAt: now,
        }
        break
      }
      case 'done':
        next = { ...next, done: true, lastUpdateAt: now }
        break
      case 'error':
        next = { ...next, error: event.data as ErrorEvent, lastUpdateAt: now }
        break
      default:
        break
    }
  }
  return next
}
