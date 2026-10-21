import { afterEach, describe, expect, it, vi } from 'vitest'

import { SseParser, createFetchEventStream, parseSseFrame } from './events'
import { setSessionToken } from '../lib/token'
import type { ServerEvent } from './types'

function eventStreamResponse(chunks: string[], keepOpen = false): Response {
  const encoder = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk))
      if (!keepOpen) controller.close()
    },
  })
  return new Response(body, {
    status: 200,
    headers: { 'Content-Type': 'text/event-stream' },
  })
}

afterEach(() => {
  setSessionToken(null)
  vi.useRealTimers()
})

describe('parseSseFrame', () => {
  it('reads the event name and the data', () => {
    const event = parseSseFrame('event: progress\ndata: {"percent":42}')
    expect(event).toEqual({ name: 'progress', data: { percent: 42 } })
  })

  it('joins several data lines', () => {
    const event = parseSseFrame('event: note\ndata: {"a":1,\ndata: "b":2}')
    expect(event).toMatchObject({ name: 'note' })
  })

  it('ignores heartbeats and broken frames', () => {
    expect(parseSseFrame(': ping')).toBeNull()
    expect(parseSseFrame('event: progress\ndata: not json')).toBeNull()
  })
})

describe('SseParser', () => {
  it('returns the events of a complete frame', () => {
    const parser = new SseParser()
    expect(parser.push('event: progress\ndata: {"percent":10}\n\n')).toHaveLength(1)
  })

  it('waits for the end of a frame', () => {
    const parser = new SseParser()
    expect(parser.push('event: progress\ndata: {"perc')).toHaveLength(0)
    expect(parser.push('ent":10}\n\n')).toHaveLength(1)
  })

  it('reads several frames of one chunk', () => {
    const parser = new SseParser()
    const events = parser.push(
      'event: progress\ndata: {"percent":10}\n\nevent: done\ndata: {"caseId":"c"}\n\n',
    )
    expect(events.map((event) => event.name)).toEqual(['progress', 'done'])
  })

  it('normalises windows line endings', () => {
    const parser = new SseParser()
    expect(parser.push('event: done\r\ndata: {"caseId":"c"}\r\n\r\n')).toHaveLength(1)
  })
})

describe('createFetchEventStream', () => {
  it('delivers the events of the stream', async () => {
    const events: ServerEvent[] = []
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        eventStreamResponse([
          'event: progress\ndata: {"percent":15}\n\n',
          'event: ready\ndata: {"events":43,"files":5}\n\n',
        ]),
      ),
    )

    const stream = createFetchEventStream('/api/case/c1/events/stream')
    stream.subscribe((event) => events.push(event))
    await vi.waitFor(() => expect(events).toHaveLength(2))
    expect(events[0]).toMatchObject({ name: 'progress' })
    expect(events[1]).toMatchObject({ name: 'ready' })
    stream.close()
  })

  it('sends the token in a header and keeps it out of the URL', async () => {
    const calls: { url: string; headers: Headers }[] = []
    setSessionToken('s3cret-token')
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string, init?: RequestInit) => {
        calls.push({ url: String(url), headers: new Headers(init?.headers) })
        return eventStreamResponse([])
      }),
    )

    const stream = createFetchEventStream('/api/case/c1/events/stream')
    await vi.waitFor(() => expect(calls).toHaveLength(1))
    expect(calls[0].headers.get('X-Raccoon-Token')).toBe('s3cret-token')
    expect(calls[0].url).not.toContain('s3cret-token')
    stream.close()
  })

  it('reconnects when the connection drops', async () => {
    vi.useFakeTimers()
    let calls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls += 1
        return eventStreamResponse(['event: progress\ndata: {"percent":15}\n\n'])
      }),
    )

    const states: string[] = []
    const stream = createFetchEventStream('/api/case/c1/events/stream')
    stream.onStateChange((state) => states.push(state.status))

    await vi.advanceTimersByTimeAsync(10)
    expect(calls).toBe(1)

    // The server closed the connection; the client waits a second and retries.
    await vi.advanceTimersByTimeAsync(1200)
    expect(calls).toBe(2)
    expect(states).toContain('reconnecting')
    expect(states).toContain('open')
    stream.close()
  })

  it('stops reconnecting after close', async () => {
    vi.useFakeTimers()
    let calls = 0
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        calls += 1
        return eventStreamResponse([])
      }),
    )

    const stream = createFetchEventStream('/api/case/c1/events/stream')
    await vi.advanceTimersByTimeAsync(10)
    stream.close()
    await vi.advanceTimersByTimeAsync(5000)
    expect(calls).toBe(1)
  })
})
