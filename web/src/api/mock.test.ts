import { describe, expect, it, vi } from 'vitest'

import { ApiClient } from './client'
import { MockApi, createHttpMockLoader, paginate } from './mock'
import { createApi } from './index'
import type { CaseEvent, CarvedFile, CaseSummary, Page, StreamSummary } from './types'

const CASE: CaseSummary = {
  id: '20260101-120000-abcdef',
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: 'a'.repeat(64),
  status: 'ready',
  stage: 'done',
  progress: 100,
  durationNs: 2450000000,
  packets: 52,
  streams: 1,
  files: 2,
  events: 2,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00Z',
  finishedAt: '2026-01-01T12:00:02Z',
  error: '',
}

const EVENTS: Page<CaseEvent> = {
  items: [
    {
      id: 1,
      ts: '2026-01-01T12:00:00Z',
      packetNo: 1,
      packetEnd: 2,
      type: 'STREAM_OPENED',
      severity: 'info',
      phase: 'recon',
      streamId: 1,
      src: '10.0.0.1:50000',
      dst: '10.0.0.2:21',
      proto: 'ftp',
      title: 'TCP stream opened',
      details: {},
      explain: '',
      parentId: 0,
      fileId: 0,
      findingIds: [],
    },
    {
      id: 2,
      ts: '2026-01-01T12:00:01Z',
      packetNo: 3,
      packetEnd: 3,
      type: 'FTP_LOGIN_FAILED',
      severity: 'critical',
      phase: 'exfil',
      streamId: 1,
      src: '10.0.0.1:50000',
      dst: '10.0.0.2:21',
      proto: 'ftp',
      title: 'Login failed',
      details: {},
      explain: '',
      parentId: 0,
      fileId: 0,
      findingIds: [],
    },
  ],
  nextCursor: null,
}

const FILES: Page<CarvedFile> = {
  items: [
    {
      id: 1,
      streamId: 1,
      dir: 'c2s',
      startOff: 0,
      endOff: 10,
      format: 'PNG',
      ext: 'png',
      status: 'complete',
      confidence: 'high',
      size: 10,
      md5: 'b'.repeat(32),
      sha256: 'c'.repeat(64),
      displayName: 'secret.png',
      path: '/tmp/secret.png',
      magicHex: '89504e47',
    },
    {
      id: 2,
      streamId: 1,
      dir: 's2c',
      startOff: 0,
      endOff: 4,
      format: 'TEXT',
      ext: 'txt',
      status: 'truncated',
      confidence: 'low',
      size: 4,
      md5: 'd'.repeat(32),
      sha256: 'e'.repeat(64),
      displayName: 'notes.txt',
      path: '/tmp/notes.txt',
      magicHex: '74657874',
    },
  ],
  nextCursor: null,
}

const STREAMS: Page<StreamSummary> = {
  items: [
    {
      id: 1,
      parentId: 0,
      proto: 'ftp',
      srcIp: '10.0.0.1',
      srcPort: 50000,
      dstIp: '10.0.0.2',
      dstPort: 21,
      startTs: '2026-01-01T12:00:00Z',
      endTs: '2026-01-01T12:00:02Z',
      bytesC2S: 53,
      bytesS2C: 0,
      packets: 4,
      firstPacket: 1,
      lastPacket: 4,
      midstream: false,
      hasGaps: false,
      udp: false,
    },
  ],
  nextCursor: null,
}

function loader() {
  const fixtures: Record<string, unknown> = {
    case: CASE,
    events: EVENTS,
    files: FILES,
    streams: STREAMS,
  }
  return async (name: string) => {
    const fixture = fixtures[name]
    if (!fixture) throw new Error(`unknown fixture ${name}`)
    return fixture
  }
}

describe('MockApi', () => {
  it('serves the case metadata', async () => {
    const api = new MockApi(loader(), 0)
    await expect(api.getCase(CASE.id)).resolves.toMatchObject({ id: CASE.id, status: 'ready' })
  })

  it('reports an unknown case', async () => {
    const api = new MockApi(loader(), 0)
    await expect(api.getCase('other')).rejects.toMatchObject({ status: 404 })
  })

  it('filters the events by severity', async () => {
    const api = new MockApi(loader(), 0)
    const page = await api.listEvents(CASE.id, { severity: ['critical'] })
    expect(page.items.map((event) => event.id)).toEqual([2])
  })

  it('hides the low-confidence files by default', async () => {
    const api = new MockApi(loader(), 0)
    const page = await api.listFiles(CASE.id)
    expect(page.items.map((file) => file.id)).toEqual([1])
  })

  it('shows every file with confidence=all', async () => {
    const api = new MockApi(loader(), 0)
    const page = await api.listFiles(CASE.id, { confidence: 'all' })
    expect(page.items.map((file) => file.id)).toEqual([1, 2])
  })

  it('filters the streams by protocol', async () => {
    const api = new MockApi(loader(), 0)
    await expect(api.listStreams(CASE.id, { proto: 'ftp' })).resolves.toMatchObject({
      items: [{ id: 1 }],
    })
    await expect(api.listStreams(CASE.id, { proto: 'http' })).resolves.toMatchObject({ items: [] })
  })

  it('replays the stages of the analysis on the event stream', async () => {
    const api = new MockApi(loader(), 0)
    const stream = api.openEventStream(CASE.id)
    const names: string[] = []
    stream.subscribe((event) => names.push(event.name))
    await new Promise((resolve) => setTimeout(resolve, 60))
    expect(names).toContain('progress')
    expect(names).toContain('ready')
    expect(names).toContain('done')
    stream.close()
  })
})

describe('paginate', () => {
  it('cuts the list at the limit and returns a cursor', () => {
    const page = paginate([{ id: 1 }, { id: 2 }, { id: 3 }], 2)
    expect(page.items.map((item) => item.id)).toEqual([1, 2])
    expect(page.nextCursor).toBe('2')
  })

  it('continues after the cursor', () => {
    const page = paginate([{ id: 1 }, { id: 2 }, { id: 3 }], 2, '2')
    expect(page.items.map((item) => item.id)).toEqual([3])
    expect(page.nextCursor).toBeNull()
  })
})

describe('createApi', () => {
  it('uses the real client by default', async () => {
    vi.stubEnv('VITE_MOCK', '')
    await expect(createApi()).resolves.toBeInstanceOf(ApiClient)
  })

  it('uses the mock adapter with VITE_MOCK=1', async () => {
    vi.stubEnv('VITE_MOCK', '1')
    const api = await createApi()
    expect(api).toBeInstanceOf(MockApi)
    vi.unstubAllEnvs()
  })
})

describe('createHttpMockLoader', () => {
  it('reads the fixture over HTTP', async () => {
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(CASE), { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)
    const load = createHttpMockLoader('/mock')
    await expect(load('case')).resolves.toMatchObject({ id: CASE.id })
    expect(fetchMock).toHaveBeenCalledWith('/mock/case.json')
  })

  it('reports a missing fixture', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('', { status: 404 })))
    const load = createHttpMockLoader('/mock')
    await expect(load('case')).rejects.toMatchObject({ status: 404 })
  })
})
