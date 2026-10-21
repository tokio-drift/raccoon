import { afterEach, describe, expect, it, vi } from 'vitest'

import { ApiClient, ApiError, buildQuery, filenameFromDisposition } from './client'
import { setSessionToken } from '../lib/token'

interface FetchCall {
  url: string
  init: RequestInit | undefined
}

function mockFetch(makeResponse: () => Response) {
  const calls: FetchCall[] = []
  const fetchMock = vi.fn(async (url: string, init?: RequestInit) => {
    calls.push({ url: String(url), init })
    return makeResponse()
  })
  vi.stubGlobal('fetch', fetchMock)
  return { calls, fetchMock }
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

afterEach(() => {
  setSessionToken(null)
})

describe('buildQuery', () => {
  it('skips empty values', () => {
    expect(buildQuery({ a: undefined, b: '', c: 'x' })).toBe('?c=x')
  })

  it('returns an empty string without values', () => {
    expect(buildQuery({})).toBe('')
  })
})

describe('ApiClient', () => {
  it('encodes the event filters in the query string', async () => {
    const { calls } = mockFetch(() => jsonResponse({ items: [] }))
    const client = new ApiClient()

    await client.listEvents('case 1', {
      severity: ['info', 'warning'],
      type: ['FTP_LOGIN_FAILED'],
      phase: ['recon'],
      proto: ['ftp'],
      q: 'login failed',
      limit: 50,
      cursor: 'abc',
      flat: true,
    })

    const url = calls[0].url
    expect(url.startsWith('/api/case/case%201/events?')).toBe(true)
    const query = new URLSearchParams(url.slice(url.indexOf('?')))
    expect(query.get('severity')).toBe('info,warning')
    expect(query.get('type')).toBe('FTP_LOGIN_FAILED')
    expect(query.get('phase')).toBe('recon')
    expect(query.get('proto')).toBe('ftp')
    expect(query.get('q')).toBe('login failed')
    expect(query.get('limit')).toBe('50')
    expect(query.get('cursor')).toBe('abc')
    expect(query.get('flat')).toBe('1')
  })

  it('sends the session token in a header and never in the URL', async () => {
    const { calls } = mockFetch(() => jsonResponse({ id: 'case-1' }))
    setSessionToken('s3cret-token')
    const client = new ApiClient()

    await client.getCase('case-1')

    const headers = calls[0].init?.headers as Headers
    expect(headers.get('X-Raccoon-Token')).toBe('s3cret-token')
    expect(calls[0].url).not.toContain('s3cret-token')
    expect(calls[0].url).toBe('/api/case/case-1')
  })

  it('maps a missing session to an auth error', async () => {
    mockFetch(() => jsonResponse({ error: { code: 'unauthorized', message: 'no session' } }, 401))
    const client = new ApiClient()

    await expect(client.getCase('case-1')).rejects.toBeInstanceOf(ApiError)
    await expect(client.getCase('case-1')).rejects.toMatchObject({
      status: 401,
      code: 'unauthorized',
      isAuthError: true,
    })
  })

  it('maps a missing case to a not-found error', async () => {
    mockFetch(() => jsonResponse({ error: { code: 'not_found', message: 'no case' } }, 404))
    const client = new ApiClient()

    await expect(client.getCase('case-1')).rejects.toMatchObject({
      status: 404,
      isNotFound: true,
    })
  })

  it('reports an unreachable server without a status', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('failed to fetch')
      }),
    )
    const client = new ApiClient()

    await expect(client.getCase('case-1')).rejects.toMatchObject({ status: 0, code: 'network' })
  })

  it('builds the report URL with the format', () => {
    const client = new ApiClient()
    expect(client.getReportUrl('case-1', 'pdf')).toBe('/api/case/case-1/report?format=pdf')
  })

  it('builds the stream byte URL with the window', async () => {
    const { calls } = mockFetch(() => jsonResponse({ streamId: 3, dir: 'c2s' }))
    const client = new ApiClient()

    await client.getStreamBytes('case-1', 3, { dir: 'c2s', offset: 64, len: 512 })

    expect(calls[0].url).toBe('/api/case/case-1/streams/3/bytes?dir=c2s&offset=64&len=512')
  })
})

describe('filenameFromDisposition', () => {
  it('reads a quoted file name', () => {
    const headers = new Headers({ 'Content-Disposition': 'attachment; filename="secret.png"' })
    expect(filenameFromDisposition(headers)).toBe('secret.png')
  })

  it('falls back to a neutral name', () => {
    expect(filenameFromDisposition(new Headers())).toBe('download')
  })
})
