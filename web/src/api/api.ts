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
import type { EventStream } from './events'

/**
 * Every route of `docs/api.md` behind one interface, so the real client and
 * the mock adapter can be swapped without touching the views.
 */
export interface RaccoonApi {
  getCase(caseId: string): Promise<CaseSummary>
  listEvents(caseId: string, query: EventQuery): Promise<Page<CaseEvent>>
  listFiles(caseId: string, query: FileQuery): Promise<Page<CarvedFile>>
  listStreams(caseId: string, query: StreamQuery): Promise<Page<StreamSummary>>
  getStreamBytes(caseId: string, streamId: number, query: StreamBytesQuery): Promise<StreamBytes>
  getGraph(caseId: string): Promise<GraphResponse>
  /** The URL of the rendered report; the endpoint serves the file directly. */
  getReportUrl(caseId: string, format: ReportFormat): string
  /** Downloads a rendered report from the report endpoint. */
  downloadReport(caseId: string, format?: ReportFormat): Promise<{ blob: Blob; filename: string }>
  uploadCapture(
    file: File,
    options?: {
      onProgress?: (progress: UploadProgress) => void
      signal?: AbortSignal
    },
  ): Promise<UploadResponse>
  downloadFile(caseId: string, fileId: number): Promise<{ blob: Blob; filename: string }>
  /** Opens the server-sent event stream of a case. */
  openEventStream(caseId: string): EventStream
}
