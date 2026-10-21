import { getSessionToken } from '../lib/token'
import type { ErrorEvent, ServerEvent } from './types'

/**
 * The server-sent event stream of a case (docs/api.md,
 * `GET /api/case/{id}/events/stream`).
 *
 * The stream is read with `fetch` instead of `EventSource` so the session
 * token travels in the `X-Raccoon-Token` header and never in a URL.
 */

export type EventStreamStatus = 'connecting' | 'open' | 'reconnecting' | 'closed'

export interface EventStreamState {
  status: EventStreamStatus
  /** The number of consecutive failed attempts. */
  attempt: number
}

export interface EventStream {
  /** Registers a listener for server events; the returned function unsubscribes. */
  subscribe(listener: (event: ServerEvent) => void): () => void
  /** Registers a listener for connection state changes. */
  onStateChange(listener: (state: EventStreamState) => void): () => void
  /** Registers a listener for any traffic on the connection, heartbeats included. */
  onActivity(listener: () => void): () => void
  /** Tries the connection again right now, without waiting for the backoff. */
  reconnect(): void
  /** Ends the stream; no reconnect happens afterwards. */
  close(): void
}

/** Parses one SSE frame; returns null for heartbeats and malformed frames. */
export function parseSseFrame(frame: string): ServerEvent | null {
  let name = 'message'
  const data: string[] = []
  for (const raw of frame.split('\n')) {
    if (raw.startsWith(':')) continue
    const colon = raw.indexOf(':')
    const field = colon < 0 ? raw : raw.slice(0, colon)
    let value = colon < 0 ? '' : raw.slice(colon + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'event') name = value
    else if (field === 'data') data.push(value)
  }
  if (data.length === 0) return null
  let payload: unknown
  try {
    payload = JSON.parse(data.join('\n'))
  } catch {
    return null
  }
  return { name, data: payload } as ServerEvent
}

/** An incremental parser for a text stream of SSE frames. */
export class SseParser {
  private buffer = ''

  /** Feeds a chunk of the response body and returns the complete events. */
  push(chunk: string): ServerEvent[] {
    this.buffer += chunk.replace(/\r\n/g, '\n')
    const events: ServerEvent[] = []
    for (;;) {
      const index = this.buffer.indexOf('\n\n')
      if (index < 0) break
      const frame = this.buffer.slice(0, index)
      this.buffer = this.buffer.slice(index + 2)
      const event = parseSseFrame(frame)
      if (event) events.push(event)
    }
    return events
  }
}

const RECONNECT_BASE_MS = 1000
const RECONNECT_MAX_MS = 15000

function backoffDelay(attempt: number): number {
  return Math.min(RECONNECT_MAX_MS, RECONNECT_BASE_MS * 2 ** Math.max(0, attempt - 1))
}

/**
 * Opens the event stream of a case over `fetch` and reconnects with a
 * backoff. The server replays the current state on every reconnect, so a
 * dropped connection never loses a state transition.
 */
export function createFetchEventStream(path: string): EventStream {
  const listeners = new Set<(event: ServerEvent) => void>()
  const stateListeners = new Set<(state: EventStreamState) => void>()
  const activityListeners = new Set<() => void>()
  let controller: AbortController | null = null
  let timer: number | null = null
  let closed = false
  let attempt = 0
  let generation = 0

  const emitState = (status: EventStreamStatus) => {
    const state: EventStreamState = { status, attempt }
    for (const listener of stateListeners) listener(state)
  }

  const scheduleReconnect = () => {
    if (closed) return
    attempt += 1
    emitState('reconnecting')
    timer = window.setTimeout(() => {
      timer = null
      void connect()
    }, backoffDelay(attempt))
  }

  const connect = async () => {
    if (closed) return
    const mine = ++generation
    controller = new AbortController()
    const token = getSessionToken()
    const headers = new Headers({ Accept: 'text/event-stream' })
    if (token) headers.set('X-Raccoon-Token', token)

    try {
      const response = await fetch(path, { headers, signal: controller.signal })
      if (!response.ok || !response.body) {
        if (!closed && mine === generation) scheduleReconnect()
        return
      }
      attempt = 0
      emitState('open')
      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      const parser = new SseParser()
      for (;;) {
        const { done, value } = await reader.read()
        if (done) break
        if (value) {
          const chunk = decoder.decode(value, { stream: true })
          for (const listener of activityListeners) listener()
          for (const event of parser.push(chunk)) {
            for (const listener of listeners) listener(event)
          }
        }
      }
      if (!closed && mine === generation) scheduleReconnect()
    } catch {
      if (!closed && mine === generation) scheduleReconnect()
    }
  }

  emitState('connecting')
  void connect()

  return {
    subscribe(listener) {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    onStateChange(listener) {
      stateListeners.add(listener)
      return () => stateListeners.delete(listener)
    },
    onActivity(listener) {
      activityListeners.add(listener)
      return () => activityListeners.delete(listener)
    },
    reconnect() {
      if (closed) return
      if (timer !== null) {
        window.clearTimeout(timer)
        timer = null
      }
      controller?.abort()
      attempt = 0
      void connect()
    },
    close() {
      closed = true
      generation += 1
      if (timer !== null) window.clearTimeout(timer)
      controller?.abort()
      emitState('closed')
      listeners.clear()
      stateListeners.clear()
      activityListeners.clear()
    },
  }
}

/** An event stream that can be driven by a test or by the mock adapter. */
export class ManualEventStream implements EventStream {
  private readonly listeners = new Set<(event: ServerEvent) => void>()
  private readonly stateListeners = new Set<(state: EventStreamState) => void>()
  private readonly activityListeners = new Set<() => void>()
  private state: EventStreamState = { status: 'connecting', attempt: 0 }

  subscribe(listener: (event: ServerEvent) => void): () => void {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  onStateChange(listener: (state: EventStreamState) => void): () => void {
    this.stateListeners.add(listener)
    listener(this.state)
    return () => this.stateListeners.delete(listener)
  }

  onActivity(listener: () => void): () => void {
    this.activityListeners.add(listener)
    return () => this.activityListeners.delete(listener)
  }

  reconnect(): void {
    this.setState({ status: 'connecting', attempt: 0 })
  }

  close(): void {
    this.setState({ status: 'closed', attempt: this.state.attempt })
    this.listeners.clear()
    this.stateListeners.clear()
  }

  /** Delivers a server event to every listener. */
  emit(event: ServerEvent): void {
    for (const listener of this.activityListeners) listener()
    for (const listener of this.listeners) listener(event)
  }

  /** Changes the connection state and notifies the listeners. */
  setState(state: EventStreamState): void {
    this.state = state
    for (const listener of this.stateListeners) listener(state)
  }
}

/** True when the event is an error event. */
export function isErrorEvent(event: ServerEvent): event is { name: 'error'; data: ErrorEvent } {
  return event.name === 'error'
}
