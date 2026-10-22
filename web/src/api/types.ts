/**
 * The API contract of docs/api.md, in TypeScript. Field names are camelCase
 * and timestamps are RFC 3339 with nanosecond precision in UTC.
 */

export type CaseStatus = 'queued' | 'running' | 'ready' | 'failed'
export type Severity = 'info' | 'warning' | 'critical'
export type VerdictStatus = 'malicious' | 'suspicious' | 'no_detections' | 'unknown' | 'not_checked'
export type Direction = 'c2s' | 's2c'
export type Confidence = 'high' | 'medium' | 'low'
export type CarvedFileStatus = 'complete' | 'truncated' | 'corrupt'
export type StreamProto = string

export interface CaseSummary {
  id: string
  fileName: string
  size: number
  pcapSha256: string
  status: CaseStatus
  stage: string
  progress: number
  durationNs: number
  packets: number
  streams: number
  files: number
  events: number
  toolVersion: string
  startedAt: string
  finishedAt: string
  error: string
}

export interface CaseEvent {
  id: number
  ts: string
  packetNo: number
  packetEnd: number
  type: string
  severity: Severity
  phase: string
  streamId: number
  src: string
  dst: string
  proto: string
  title: string
  details: Record<string, unknown>
  explain: string
  parentId: number
  fileId: number
  findingIds: number[]
}

export interface Verdict {
  source: string
  status: VerdictStatus
  score: number
  total: number
  checkedAt: string
}

export interface CarvedFile {
  id: number
  streamId: number
  dir: Direction
  startOff: number
  endOff: number
  format: string
  ext: string
  status: CarvedFileStatus
  confidence: Confidence
  size: number
  md5: string
  sha256: string
  displayName: string
  path: string
  magicHex: string
  verdict?: Verdict
}

export interface StreamSummary {
  id: number
  parentId: number
  proto: StreamProto
  srcIp: string
  srcPort: number
  dstIp: string
  dstPort: number
  startTs: string
  endTs: string
  bytesC2S: number
  bytesS2C: number
  packets: number
  firstPacket: number
  lastPacket: number
  midstream: boolean
  hasGaps: boolean
  udp: boolean
}

export interface StreamSegment {
  off: number
  len: number
  ts: string
  packetNo: number
}

export interface CarvedRange {
  fileId: number
  start: number
  end: number
}

/** A range of bytes that was never captured. */
export interface StreamGap {
  off: number
  len: number
}

export interface StreamBytes {
  streamId: number
  dir: Direction
  offset: number
  length: number
  total: number
  dataBase64: string
  segments: StreamSegment[]
  gaps?: StreamGap[]
  carved: CarvedRange[]
}

export interface Page<T> {
  items: T[]
  nextCursor?: string | null
}

export interface UploadResponse {
  caseId: string
}

/* ------------------------------------------------------------ query shapes */

/** Query of `GET /api/case/{id}/events` (docs/api.md). */
export interface EventQuery {
  severity?: Severity[]
  type?: string[]
  phase?: string[]
  proto?: string[]
  q?: string
  from?: string
  to?: string
  parent?: number
  flat?: boolean
  limit?: number
  cursor?: string
}

/** Query of `GET /api/case/{id}/files` (docs/api.md). */
export interface FileQuery {
  /** `all` includes the low-confidence files the API hides by default. */
  confidence?: 'all' | 'high' | 'medium' | 'low'
}

/** Query of `GET /api/case/{id}/streams` (docs/api.md). */
export interface StreamQuery {
  q?: string
  proto?: string
  limit?: number
  cursor?: string
}

/** Query of `GET /api/case/{id}/streams/{sid}/bytes` (docs/api.md). */
export interface StreamBytesQuery {
  dir: Direction
  offset?: number
  len?: number
}

export interface GraphNode {
  id: string
  role: string
  bytes: number
  severity: Severity
}

export interface GraphEdge {
  src: string
  dst: string
  proto: string
  streams: number
  bytes: number
  firstTs: string
  lastTs: string
  severity: Severity
}

export interface GraphResponse {
  nodes: GraphNode[]
  edges: GraphEdge[]
}

export type ReportFormat = 'html' | 'pdf' | 'json'

/** Progress of an upload, in bytes. */
export interface UploadProgress {
  loaded: number
  total: number
}

/** Server-sent events of `GET /api/case/{id}/events/stream`. */
export type ServerEvent =
  | { name: 'progress'; data: ProgressEvent }
  | { name: 'ready'; data: ReadyEvent }
  | { name: 'verdict'; data: VerdictEvent }
  | { name: 'done'; data: DoneEvent }
  | { name: 'error'; data: ErrorEvent }

export interface ProgressEvent {
  stage: string
  percent: number
  packets: number
  bytes: number
  streams: number
  files: number
}

export interface ReadyEvent {
  events: number
  files: number
}

export interface VerdictEvent {
  fileId: number
  sha256: string
  status: VerdictStatus
}

export interface DoneEvent {
  caseId: string
}

export interface ErrorEvent {
  code: string
  message: string
}
