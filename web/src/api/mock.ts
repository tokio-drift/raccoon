import { ApiError } from './client'
import { ManualEventStream, type EventStream } from './events'
import type {
  CaseEvent,
  CarvedFile,
  CaseSummary,
  EventQuery,
  FileQuery,
  GraphResponse,
  Page,
  ReportFormat,
  Severity,
  StreamBytes,
  StreamBytesQuery,
  StreamQuery,
  StreamSummary,
  UploadProgress,
  UploadResponse,
} from './types'
import type { RaccoonApi } from './api'

/**
 * The mock adapter (PLAN 11.3). It serves the fixtures of `web/mock/*.json`
 * with the same types, the same filters and a small latency, so the UI can be
 * developed and tested without a running server.
 */

/** Loads one fixture by name, for example `case`, `events` or `stream-1-c2s`. */
export type MockLoader = (name: string) => Promise<unknown>

/** The latency the mock adds to every answer, in milliseconds. */
export const MOCK_LATENCY_MS = 120

/** A loader that reads the fixtures over HTTP from the dev server. */
export function createHttpMockLoader(base = '/mock'): MockLoader {
  return async (name: string) => {
    const response = await fetch(`${base}/${name}.json`)
    if (!response.ok) {
      throw new ApiError(response.status, 'not_found', `The mock fixture ${name} is missing.`)
    }
    return response.json()
  }
}

function matchesText(haystack: string, needle: string): boolean {
  return haystack.toLowerCase().includes(needle.toLowerCase())
}

function matchesAny(value: string, wanted: string[] | undefined): boolean {
  if (!wanted || wanted.length === 0) return true
  return wanted.includes(value)
}

/** The mock implementation of every route in `docs/api.md`. */
export class MockApi implements RaccoonApi {
  private readonly loader: MockLoader
  private readonly latencyMs: number
  private readonly cases = new Map<string, CaseSummary>()

  constructor(loader: MockLoader, latencyMs: number = MOCK_LATENCY_MS) {
    this.loader = loader
    this.latencyMs = latencyMs
  }

  private async delay(): Promise<void> {
    if (this.latencyMs <= 0) return
    await new Promise((resolve) => setTimeout(resolve, this.latencyMs))
  }

  private async fixture<T>(name: string): Promise<T> {
    return (await this.loader(name)) as T
  }

  async getCase(caseId: string): Promise<CaseSummary> {
    await this.delay()
    const summary = await this.fixture<CaseSummary>('case')
    if (summary.id !== caseId) {
      throw new ApiError(404, 'not_found', 'The case does not exist.')
    }
    return summary
  }

  async listEvents(_caseId: string, query: EventQuery = {}): Promise<Page<CaseEvent>> {
    await this.delay()
    const page = await this.fixture<Page<CaseEvent>>('events')
    const severity = query.severity as Severity[] | undefined
    const filtered = page.items.filter((event) => {
      if (!matchesAny(event.severity, severity)) return false
      if (query.type?.length && !query.type.includes(event.type)) return false
      if (query.phase?.length && !query.phase.includes(event.phase)) return false
      if (query.proto?.length && !query.proto.includes(event.proto)) return false
      if (query.q && !matchesText(`${event.title} ${JSON.stringify(event.details)}`, query.q)) {
        return false
      }
      if (query.parent !== undefined && event.parentId !== query.parent) return false
      if (!query.flat && event.parentId !== 0) return false
      return true
    })
    return paginate(filtered, query.limit, query.cursor)
  }

  async listFiles(_caseId: string, query: FileQuery = {}): Promise<Page<CarvedFile>> {
    await this.delay()
    const page = await this.fixture<Page<CarvedFile>>('files')
    const filtered = page.items.filter((file) => {
      if (query.confidence === undefined) {
        return file.confidence !== 'low'
      }
      if (query.confidence === 'all') return true
      return file.confidence === query.confidence
    })
    return { items: filtered, nextCursor: null }
  }

  async listStreams(_caseId: string, query: StreamQuery = {}): Promise<Page<StreamSummary>> {
    await this.delay()
    const page = await this.fixture<Page<StreamSummary>>('streams')
    const filtered = page.items.filter((stream) => {
      if (query.proto && stream.proto !== query.proto) return false
      if (query.q) {
        const text = `${stream.srcIp}:${stream.srcPort} ${stream.dstIp}:${stream.dstPort} ${stream.proto}`
        if (!matchesText(text, query.q)) return false
      }
      return true
    })
    return paginate(filtered, query.limit, query.cursor)
  }

  async getStreamBytes(
    _caseId: string,
    streamId: number,
    query: StreamBytesQuery,
  ): Promise<StreamBytes> {
    await this.delay()
    const window = await this.fixture<StreamBytes>(`stream-${streamId}-${query.dir}`)
    const offset = query.offset ?? 0
    const length = query.len ?? 4096
    const data = decodeBase64(window.dataBase64)
    const slice = data.slice(offset, offset + length)
    return {
      ...window,
      offset,
      length: slice.length,
      dataBase64: encodeBase64(slice),
      segments: window.segments.filter(
        (segment) => segment.off < offset + length && segment.off + segment.len > offset,
      ),
      gaps: (window.gaps ?? []).filter(
        (gap) => gap.off < offset + length && gap.off + gap.len > offset,
      ),
      carved: window.carved.filter(
        (range) => range.start < offset + length && range.end > offset,
      ),
    }
  }

  async getGraph(_caseId: string): Promise<GraphResponse> {
    await this.delay()
    return { nodes: [], edges: [] }
  }

  getReportUrl(_caseId: string, format: ReportFormat = 'html'): string {
    return `/mock/report.${format}`
  }

  async uploadCapture(
    file: File,
    options?: { onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal },
  ): Promise<UploadResponse> {
    const total = file.size
    options?.onProgress?.({ loaded: total, total })
    await this.delay()
    if (options?.signal?.aborted) {
      throw new ApiError(0, 'cancelled', 'The upload was cancelled.')
    }
    const summary = await this.fixture<CaseSummary>('case')
    this.cases.set(summary.id, summary)
    return { caseId: summary.id }
  }

  async downloadFile(_caseId: string, fileId: number): Promise<{ blob: Blob; filename: string }> {
    await this.delay()
    const page = await this.fixture<Page<CarvedFile>>('files')
    const file = page.items.find((item) => item.id === fileId)
    if (!file) {
      throw new ApiError(404, 'not_found', 'The file does not exist.')
    }
    return { blob: new Blob([file.magicHex]), filename: file.displayName }
  }

  /**
   * The mock event stream replays the same sequence as the server: a progress
   * event per stage, the ready event, then the done event.
   */
  openEventStream(_caseId: string): EventStream {
    const stream = new ManualEventStream()
    const stages = [
      { stage: 'init', percent: 0, packets: 0, bytes: 0, streams: 0, files: 0 },
      { stage: 'read', percent: 15, packets: 52, bytes: 48213, streams: 0, files: 0 },
      { stage: 'process', percent: 80, packets: 52, bytes: 48213, streams: 3, files: 5 },
    ]
    let index = 0
    const tick = () => {
      if (index < stages.length) {
        stream.setState({ status: 'open', attempt: 0 })
        stream.emit({ name: 'progress', data: stages[index] })
        index += 1
        window.setTimeout(tick, this.latencyMs)
        return
      }
      stream.emit({ name: 'ready', data: { events: 43, files: 5 } })
      stream.setState({ status: 'open', attempt: 0 })
      window.setTimeout(() => {
        stream.emit({ name: 'done', data: { caseId: _caseId } })
      }, this.latencyMs)
    }
    window.setTimeout(tick, this.latencyMs)
    return stream
  }
}

/** Paginates a list the way the API does: a limit and an opaque cursor. */
export function paginate<T extends { id: number }>(
  items: T[],
  limit?: number,
  cursor?: string,
): Page<T> {
  const start = cursor ? items.findIndex((item) => item.id > Number(cursor)) : 0
  const from = start < 0 ? items.length : start
  const size = limit ?? 200
  const page = items.slice(from, from + size)
  const last = page[page.length - 1]
  const hasMore = from + size < items.length
  return { items: page, nextCursor: hasMore && last ? String(last.id) : null }
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value)
  const bytes = new Uint8Array(binary.length)
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index)
  }
  return bytes
}

function encodeBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary)
}
