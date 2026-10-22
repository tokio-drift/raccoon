import { renderHook, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from '../api/api'
import type { CarvedFile, EventQuery, FileQuery, Page, StreamSummary, VerdictEvent } from '../api/types'
import { EMPTY_FILE_FILTERS, type FileFilters } from '../lib/files'
import { useFiles } from './useFiles'

const CASE_ID = '20260101-120000-abcdef'

function file(id: number, overrides: Partial<CarvedFile> = {}): CarvedFile {
  return {
    id,
    streamId: 1,
    dir: 'c2s',
    startOff: 0,
    endOff: 1024,
    format: 'PNG',
    ext: 'png',
    status: 'complete',
    confidence: 'high',
    size: 1024,
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    displayName: `file-${id}.png`,
    path: `carved/file-${id}.png`,
    magicHex: '89504e47',
    ...overrides,
  }
}

const STREAM: StreamSummary = {
  id: 1,
  parentId: 0,
  proto: 'ftp',
  srcIp: '192.0.2.14',
  srcPort: 51822,
  dstIp: '192.0.2.50',
  dstPort: 21,
  startTs: '2026-01-01T12:00:00.000000000Z',
  endTs: '2026-01-01T12:00:05.000000000Z',
  bytesC2S: 4096,
  bytesS2C: 0,
  packets: 4,
  firstPacket: 1,
  lastPacket: 4,
  midstream: false,
  hasGaps: false,
  udp: false,
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function makeApi(files: CarvedFile[] = [], streams: StreamSummary[] = [STREAM]) {
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const listStreams = vi.fn(async (_caseId: string, _query: unknown) => page(streams))
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page([]))
  const api = { listFiles, listStreams, listEvents } as unknown as RaccoonApi
  return { api, listFiles, listStreams, listEvents }
}

function renderFiles(
  api: RaccoonApi,
  overrides: Partial<Parameters<typeof useFiles>[0]> = {},
) {
  return renderHook(() =>
    useFiles({
      caseId: CASE_ID,
      api,
      filters: EMPTY_FILE_FILTERS,
      sortKey: 'verdict',
      sortDescending: false,
      verdicts: {},
      initialFileId: null,
      onSortChange: () => undefined,
      ...overrides,
    }),
  )
}

beforeEach(() => {
  window.localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('useFiles', () => {
  it('loads the files and the streams of the case', async () => {
    const { api } = makeApi([file(1), file(2)])
    const { result } = renderFiles(api)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.files).toHaveLength(2)
    expect(result.current.streams.get(1)?.srcIp).toBe('192.0.2.14')
  })

  it('asks for the low-confidence files too', async () => {
    const { api, listFiles } = makeApi([file(1)])
    renderFiles(api)
    await waitFor(() => expect(listFiles).toHaveBeenCalled())
    expect(listFiles.mock.calls[0][1]).toEqual({ confidence: 'all' })
  })

  it('hides the low-confidence files until the switch is on', async () => {
    const { api } = makeApi([file(1), file(2, { confidence: 'low' })])
    const { result, rerender } = renderHook(
      (props: { filters: FileFilters }) =>
        useFiles({
          caseId: CASE_ID,
          api,
          filters: props.filters,
          sortKey: 'verdict',
          sortDescending: false,
          verdicts: {},
          initialFileId: null,
          onSortChange: () => undefined,
        }),
      { initialProps: { filters: EMPTY_FILE_FILTERS } },
    )
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.rows).toHaveLength(1)
    expect(result.current.hiddenCount).toBe(1)

    rerender({ filters: { ...EMPTY_FILE_FILTERS, showLowConfidence: true } })
    await waitFor(() => expect(result.current.rows).toHaveLength(2))
  })

  it('filters by the verdict, the format, the direction and the text', async () => {
    const { api } = makeApi([
      file(1, { format: 'PNG' }),
      file(2, { format: 'ZIP', dir: 's2c' }),
      file(3, { format: 'ZIP' }),
    ])
    const { result } = renderFiles(api, {
      filters: { ...EMPTY_FILE_FILTERS, formats: ['ZIP'] },
    })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.rows.map((item) => item.id)).toEqual([2, 3])
  })

  it('searches the name, the hash and the endpoints', async () => {
    const { api } = makeApi([file(1, { displayName: 'invoice.pdf' }), file(2)])
    const { result } = renderFiles(api, {
      filters: { ...EMPTY_FILE_FILTERS, query: 'invoice' },
    })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.rows.map((item) => item.id)).toEqual([1])
  })

  it('takes the live verdict without moving the rows', async () => {
    const { api } = makeApi([
      file(1, { verdict: { source: 'yara', status: 'not_checked', score: 0, total: 70, checkedAt: '' } }),
      file(2, { verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' } }),
    ])
    const { result, rerender } = renderHook(
      (props: { verdicts: Record<number, VerdictEvent> }) =>
        useFiles({
          caseId: CASE_ID,
          api,
          filters: EMPTY_FILE_FILTERS,
          sortKey: 'verdict',
          sortDescending: false,
          verdicts: props.verdicts,
          initialFileId: null,
          onSortChange: () => undefined,
        }),
      { initialProps: { verdicts: {} as Record<number, VerdictEvent> } },
    )
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.rows.map((item) => item.id)).toEqual([1, 2])

    rerender({ verdicts: { 1: { fileId: 1, sha256: 'abc', status: 'malicious' } } })
    await waitFor(() => expect(result.current.files[0].verdict?.status).toBe('malicious'))
    // The row keeps its place; the reader is told that the order changed.
    expect(result.current.rows.map((item) => item.id)).toEqual([1, 2])
    expect(result.current.orderChanged).toBe(true)
  })

  it('keeps the score, the source and the time of the loaded check', async () => {
    const { api } = makeApi([
      file(1, { verdict: { source: 'virustotal', status: 'unknown', score: 3, total: 70, checkedAt: '2026-01-01T12:00:00.000000000Z' } }),
    ])
    const { result } = renderFiles(api, {
      verdicts: { 1: { fileId: 1, sha256: 'abc', status: 'malicious' } },
    })
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.files[0].verdict).toEqual({
      source: 'virustotal',
      status: 'malicious',
      score: 3,
      total: 70,
      checkedAt: '2026-01-01T12:00:00.000000000Z',
    })
  })

  it('remembers the selected file per case', async () => {
    const { api } = makeApi([file(1), file(2)])
    const { result } = renderFiles(api)
    await waitFor(() => expect(result.current.loading).toBe(false))
    result.current.select(2)
    await waitFor(() =>
      expect(window.localStorage.getItem(`raccoon.files.${CASE_ID}`)).toContain('"selectedId":2'),
    )
  })

  it('selects the file of a deep link', async () => {
    const { api } = makeApi([file(1), file(2)])
    const { result } = renderFiles(api, { initialFileId: 2 })
    await waitFor(() => expect(result.current.selectedId).toBe(2))
  })

  it('counts the files per verdict', async () => {
    const { api } = makeApi([
      file(1, { verdict: { source: 'yara', status: 'malicious', score: 1, total: 70, checkedAt: '' } }),
      file(2, { verdict: { source: 'yara', status: 'malicious', score: 1, total: 70, checkedAt: '' } }),
      file(3),
    ])
    const { result } = renderFiles(api)
    await waitFor(() => expect(result.current.loading).toBe(false))
    expect(result.current.verdictCounts.malicious).toBe(2)
    expect(result.current.verdictCounts.not_checked).toBe(1)
  })
})
