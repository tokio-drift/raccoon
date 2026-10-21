import { getSessionToken } from '../lib/token'
import { createFetchEventStream, type EventStream } from './events'
import type {
  CaseEvent,
  CarvedFile,
  CaseSummary,
  EventQuery,
  FileQuery,
  GraphResponse,
  Page,
  ReportFormat,
  StreamBytes,
  StreamBytesQuery,
  StreamQuery,
  StreamSummary,
  UploadProgress,
  UploadResponse,
} from './types'

/** An error returned by the local server, carrying its error code. */
export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  /** The session is missing or has expired (401). */
  get isAuthError(): boolean {
    return this.status === 401
  }

  /** The case, route or object does not exist (404). */
  get isNotFound(): boolean {
    return this.status === 404
  }
}

/** Builds a query string from defined values only. */
export function buildQuery(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams()
  for (const [name, value] of Object.entries(params)) {
    if (value === undefined || value === '') continue
    search.set(name, String(value))
  }
  const query = search.toString()
  return query ? `?${query}` : ''
}

/**
 * The typed client for the local RACCOON API. Every request carries the
 * session token in a header; the token never appears in a URL.
 */
export class ApiClient {
  private readonly baseUrl: string

  constructor(baseUrl = '') {
    this.baseUrl = baseUrl
  }

  /** Performs a request and returns the parsed JSON body. */
  async request<T>(path: string, init: RequestInit = {}): Promise<T> {
    const token = getSessionToken()
    const headers = new Headers(init.headers)
    headers.set('Accept', 'application/json')
    if (token) headers.set('X-Raccoon-Token', token)

    let response: Response
    try {
      response = await fetch(`${this.baseUrl}${path}`, { ...init, headers })
    } catch {
      throw new ApiError(0, 'network', 'RACCOON is not answering on this computer.')
    }

    if (!response.ok) {
      let code = 'internal'
      let message = response.statusText || 'The request failed.'
      try {
        const body = (await response.json()) as { error?: { code?: string; message?: string } }
        if (body?.error?.code) code = body.error.code
        if (body?.error?.message) message = body.error.message
      } catch {
        // A non-JSON error body keeps the generic message.
      }
      throw new ApiError(response.status, code, message)
    }

    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  /** Case metadata and progress. */
  getCase(caseId: string): Promise<CaseSummary> {
    return this.request<CaseSummary>(`/api/case/${encodeURIComponent(caseId)}`)
  }

  /** The event list, filtered and paginated. */
  listEvents(caseId: string, query: EventQuery = {}): Promise<Page<CaseEvent>> {
    const search = buildQuery({
      severity: query.severity?.join(','),
      type: query.type?.join(','),
      phase: query.phase?.join(','),
      proto: query.proto?.join(','),
      q: query.q,
      from: query.from,
      to: query.to,
      parent: query.parent,
      flat: query.flat ? '1' : undefined,
      limit: query.limit,
      cursor: query.cursor,
    })
    return this.request<Page<CaseEvent>>(
      `/api/case/${encodeURIComponent(caseId)}/events${search}`,
    )
  }

  /** The carved files. */
  listFiles(caseId: string, query: FileQuery = {}): Promise<Page<CarvedFile>> {
    const search = buildQuery({ confidence: query.confidence })
    return this.request<Page<CarvedFile>>(`/api/case/${encodeURIComponent(caseId)}/files${search}`)
  }

  /** The stream list. */
  listStreams(caseId: string, query: StreamQuery = {}): Promise<Page<StreamSummary>> {
    const search = buildQuery({
      q: query.q,
      proto: query.proto,
      limit: query.limit,
      cursor: query.cursor,
    })
    return this.request<Page<StreamSummary>>(
      `/api/case/${encodeURIComponent(caseId)}/streams${search}`,
    )
  }

  /** A window of the reassembled bytes of one stream direction. */
  getStreamBytes(
    caseId: string,
    streamId: number,
    query: StreamBytesQuery,
  ): Promise<StreamBytes> {
    const search = buildQuery({ dir: query.dir, offset: query.offset, len: query.len })
    return this.request<StreamBytes>(
      `/api/case/${encodeURIComponent(caseId)}/streams/${encodeURIComponent(String(streamId))}/bytes${search}`,
    )
  }

  /** The network graph; reserved for PLUS-F. */
  getGraph(caseId: string): Promise<GraphResponse> {
    return this.request<GraphResponse>(`/api/case/${encodeURIComponent(caseId)}/graph`)
  }

  /** The URL of the rendered report. */
  getReportUrl(caseId: string, format: ReportFormat = 'html'): string {
    return `${this.baseUrl}/api/case/${encodeURIComponent(caseId)}/report${buildQuery({ format })}`
  }

  /** The event stream of a case. */
  openEventStream(caseId: string): EventStream {
    return createFetchEventStream(
      `${this.baseUrl}/api/case/${encodeURIComponent(caseId)}/events/stream`,
    )
  }

  /**
   * Uploads a capture file. The upload uses `XMLHttpRequest` because `fetch`
   * cannot report the upload progress the design asks for.
   */
  uploadCapture(
    file: File,
    options?: { onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal },
  ): Promise<UploadResponse> {
    return new Promise<UploadResponse>((resolve, reject) => {
      const request = new XMLHttpRequest()
      const token = getSessionToken()
      request.open('POST', `${this.baseUrl}/api/upload`)
      if (token) request.setRequestHeader('X-Raccoon-Token', token)

      const form = new FormData()
      form.append('file', file, file.name)

      request.upload.addEventListener('progress', (event) => {
        if (!event.lengthComputable) return
        options?.onProgress?.({ loaded: event.loaded, total: event.total })
      })

      request.addEventListener('load', () => {
        if (request.status >= 200 && request.status < 300) {
          try {
            resolve(JSON.parse(request.responseText) as UploadResponse)
          } catch {
            reject(new ApiError(request.status, 'internal', 'The upload answer was not valid.'))
          }
          return
        }
        let code = 'internal'
        let message = 'The upload failed.'
        try {
          const body = JSON.parse(request.responseText) as {
            error?: { code?: string; message?: string }
          }
          if (body?.error?.code) code = body.error.code
          if (body?.error?.message) message = body.error.message
        } catch {
          // A non-JSON error body keeps the generic message.
        }
        reject(new ApiError(request.status, code, message))
      })

      request.addEventListener('error', () => {
        reject(new ApiError(0, 'network', 'RACCOON is not answering on this computer.'))
      })

      request.addEventListener('abort', () => {
        reject(new ApiError(0, 'cancelled', 'The upload was cancelled.'))
      })

      options?.signal?.addEventListener('abort', () => request.abort())
      request.send(form)
    })
  }

  /** Downloads a carved file; the name comes from the server, never the request. */
  async downloadFile(caseId: string, fileId: number): Promise<{ blob: Blob; filename: string }> {
    const token = getSessionToken()
    const headers = new Headers()
    if (token) headers.set('X-Raccoon-Token', token)
    const response = await fetch(
      `${this.baseUrl}/api/case/${encodeURIComponent(caseId)}/files/${encodeURIComponent(
        String(fileId),
      )}/download`,
      { headers },
    )
    if (!response.ok) {
      throw new ApiError(response.status, 'download_failed', "Couldn't download this file.")
    }
    return { blob: await response.blob(), filename: filenameFromDisposition(response.headers) }
  }
}

/** Reads the file name from a `Content-Disposition` header. */
export function filenameFromDisposition(headers: Headers): string {
  const disposition = headers.get('Content-Disposition') ?? ''
  const match = /filename\*?=(?:UTF-8''|")?([^";]+)"?/i.exec(disposition)
  return match ? decodeURIComponent(match[1]) : 'download'
}
