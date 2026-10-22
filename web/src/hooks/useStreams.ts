import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { RaccoonApi } from '../api/api'
import { ApiError } from '../api/client'
import type { CarvedFile, Direction, StreamSummary } from '../api/types'
import {
  LARGE_WINDOW_SIZE,
  MAX_CACHED_WINDOWS,
  WINDOW_SIZE,
  base64ToBytes,
  buildWindowModel,
  type WindowModel,
} from '../lib/streams'
import type { URLParams } from '../lib/router'

/** The direction of the inspector: one direction or both of them (§7.4). */
export type StreamDirection = Direction | 'both'

/** The page size the stream list asks for; it is the maximum of the server. */
export const STREAM_PAGE_SIZE = 1000

/** A loaded window of bytes. */
export interface StreamWindow {
  /** The direction of the window. */
  dir: Direction
  /** The offset of the first byte. */
  offset: number
  /** The number of bytes that were requested. */
  length: number
  /** The total number of bytes in the direction. */
  total: number
  /** The model of the window. */
  model: WindowModel
}

/** The state of the stream inspector. */
export interface UseStreams {
  /** Every stream of the case. */
  streams: StreamSummary[]
  /** The carved files of the case, for the labels of the ranges. */
  files: CarvedFile[]
  /** The list is loading. */
  loading: boolean
  /** The list could not be loaded. */
  error: ApiError | null
  /** The selected stream. */
  selected: StreamSummary | null
  /** The id of the selected stream. */
  selectedId: number | null
  /** Selects a stream and shows it from the start. */
  selectStream: (id: number | null) => void
  /** The direction of the inspector. */
  direction: StreamDirection
  /** Sets the direction. */
  setDirection: (direction: StreamDirection) => void
  /** The offset of the first visible byte. */
  offset: number
  /** Moves to another offset. */
  setOffset: (offset: number) => void
  /** The window that is shown. */
  window: StreamWindow | null
  /** The window of the other direction, in the Both mode. */
  otherWindow: StreamWindow | null
  /** The window is loading. */
  pending: boolean
  /** The window could not be loaded. */
  bytesError: ApiError | null
  /** Loads the window again. */
  reloadBytes: () => void
  /** The size of the windows, 4 KB or 64 KB. */
  windowSize: number
  /** Loads a larger window of 64 KB. */
  loadLarger: () => void
  /** Moves to the previous window. */
  previous: () => void
  /** Moves to the next window. */
  next: () => void
  /** The number of bytes of the direction that is shown. */
  total: number
}

export interface UseStreamsOptions {
  caseId: string
  api: RaccoonApi
  /** The deep-link parameters of the streams view (§3.2). */
  params: URLParams
  /** Writes the deep-link parameters back to the address bar. */
  onParamsChange: (params: Record<string, string>) => void
}

function windowKey(dir: Direction, offset: number, length: number): string {
  return `${dir}:${offset}:${length}`
}

/**
 * The data of the stream inspector (UI_Design.md §7). The stream list is
 * loaded once, the bytes are loaded in windows of 4 KB and at most three
 * windows are kept in memory (§7.9).
 */
export function useStreams(options: UseStreamsOptions): UseStreams {
  const { caseId, api, params, onParamsChange } = options
  const [streams, setStreams] = useState<StreamSummary[]>([])
  const [files, setFiles] = useState<CarvedFile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [direction, setDirectionState] = useState<StreamDirection>('c2s')
  const [offset, setOffsetState] = useState(0)
  const [windowSize, setWindowSize] = useState(WINDOW_SIZE)
  const [windows, setWindows] = useState<Map<string, StreamWindow>>(() => new Map())
  const [pending, setPending] = useState(false)
  const [bytesError, setBytesError] = useState<ApiError | null>(null)
  const [nonce, setNonce] = useState(0)
  const order = useRef<string[]>([])

  // The deep link chooses the stream, the direction and the offset (§3.2).
  const deepStream = params.stream ? Number.parseInt(params.stream, 10) : null
  const deepDirection = params.dir === 's2c' || params.dir === 'both' ? params.dir : 'c2s'
  const deepOffset = params.offset ? Number.parseInt(params.offset, 10) : 0

  useEffect(() => {
    setDirectionState(deepDirection)
    setOffsetState(Number.isFinite(deepOffset) && deepOffset > 0 ? deepOffset : 0)
  }, [deepDirection, deepOffset])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const load = async (): Promise<void> => {
      const collected: StreamSummary[] = []
      let cursor: string | undefined
      for (;;) {
        const page = await api.listStreams(caseId, { limit: STREAM_PAGE_SIZE, cursor })
        if (cancelled) return
        if (Array.isArray(page?.items)) collected.push(...page.items)
        if (!page.nextCursor) break
        cursor = page.nextCursor
      }
      setStreams(collected)
      setError(null)
      setLoading(false)
    }
    api
      .listFiles(caseId, { confidence: 'all' })
      .then((page) => {
        if (cancelled) return
        setFiles(Array.isArray(page?.items) ? page.items : [])
      })
      .catch(() => undefined)
    load().catch((cause: unknown) => {
      if (cancelled) return
      setError(cause instanceof ApiError ? cause : new ApiError(0, 'internal', String(cause)))
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [api, caseId, nonce])

  // The deep link selects the stream when the list arrives.
  useEffect(() => {
    if (deepStream === null || !Number.isFinite(deepStream)) return
    setSelectedId((current) => (current === deepStream ? current : deepStream))
  }, [deepStream, streams.length])

  const selected = useMemo(
    () => streams.find((stream) => stream.id === selectedId) ?? null,
    [streams, selectedId],
  )

  const total = useMemo(() => {
    if (!selected) return 0
    if (direction === 'c2s') return selected.bytesC2S
    if (direction === 's2c') return selected.bytesS2C
    return Math.max(selected.bytesC2S, selected.bytesS2C)
  }, [selected, direction])

  // The bytes of the current window are loaded whenever the stream, the
  // direction, the offset or the window size changes.
  useEffect(() => {
    if (!selected) return
    const wanted: Direction[] = direction === 'both' ? ['c2s', 's2c'] : [direction]
    let cancelled = false
    setPending(true)
    setBytesError(null)
    const load = async (): Promise<void> => {
      const next = new Map(windows)
      const nextOrder = [...order.current]
      for (const dir of wanted) {
        const key = windowKey(dir, offset, windowSize)
        if (next.has(key)) {
          const index = nextOrder.indexOf(key)
          if (index >= 0) nextOrder.splice(index, 1)
          nextOrder.push(key)
          continue
        }
        const response = await api.getStreamBytes(caseId, selected.id, {
          dir,
          offset,
          len: windowSize,
        })
        if (cancelled) return
        const bytes = base64ToBytes(response.dataBase64)
        const model = buildWindowModel({
          bytes,
          offset: response.offset,
          total: response.total,
          segments: response.segments ?? [],
          gaps: response.gaps ?? [],
          carved: response.carved ?? [],
          files,
        })
        next.set(key, {
          dir,
          offset: response.offset,
          length: response.length,
          total: response.total,
          model,
        })
        nextOrder.push(key)
      }
      // At most three windows are kept; the oldest one is replaced (§7.9).
      while (nextOrder.length > MAX_CACHED_WINDOWS) {
        const oldest = nextOrder.shift()
        if (oldest === undefined) break
        next.delete(oldest)
      }
      order.current = nextOrder
      setWindows(next)
      setPending(false)
    }
    load().catch((cause: unknown) => {
      if (cancelled) return
      setBytesError(cause instanceof ApiError ? cause : new ApiError(0, 'internal', String(cause)))
      setPending(false)
    })
    return () => {
      cancelled = true
    }
    // The window is loaded again when the stream, the direction, the offset or
    // the size changes; the files only change the labels of the ranges.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [api, caseId, selected?.id, direction, offset, windowSize, nonce])

  // The deep link keeps the parameters it does not own, so the search of the
  // list survives a change of the stream (§3.2).
  const writeParams = useCallback(
    (next: { stream?: number | null; dir?: StreamDirection; offset?: number }) => {
      const merged: Record<string, string> = {}
      for (const [key, value] of Object.entries(params)) {
        if (typeof value === 'string' && value) merged[key] = value
      }
      if (next.stream === null) delete merged.stream
      else if (next.stream !== undefined) merged.stream = String(next.stream)
      if (next.dir !== undefined) {
        if (next.dir === 'c2s') delete merged.dir
        else merged.dir = next.dir
      }
      if (next.offset !== undefined) {
        if (next.offset <= 0) delete merged.offset
        else merged.offset = String(next.offset)
      }
      onParamsChange(merged)
    },
    [onParamsChange, params],
  )

  const selectStream = useCallback(
    (id: number | null) => {
      setSelectedId(id)
      setOffsetState(0)
      writeParams({ stream: id, offset: 0 })
    },
    [writeParams],
  )

  const setDirection = useCallback(
    (next: StreamDirection) => {
      setDirectionState(next)
      writeParams({ dir: next })
    },
    [writeParams],
  )

  const setOffset = useCallback(
    (next: number) => {
      const clamped = Math.max(0, Math.trunc(next))
      setOffsetState(clamped)
      writeParams({ offset: clamped })
    },
    [writeParams],
  )

  const previous = useCallback(() => {
    setOffsetState((current) => {
      const next = Math.max(0, current - windowSize)
      writeParams({ offset: next })
      return next
    })
  }, [windowSize, writeParams])

  const next = useCallback(() => {
    setOffsetState((current) => {
      const next = current + windowSize
      writeParams({ offset: next })
      return next
    })
  }, [windowSize, writeParams])

  const loadLarger = useCallback(() => {
    setWindowSize(LARGE_WINDOW_SIZE)
  }, [])

  const reloadBytes = useCallback(() => setNonce((value) => value + 1), [])

  // In the Both mode the panes show the client to server bytes and the
  // server to client bytes of the same offset (§7.4).
  const window = useMemo(() => {
    const dir: Direction = direction === 's2c' ? 's2c' : 'c2s'
    return windows.get(windowKey(dir, offset, windowSize)) ?? null
  }, [windows, direction, offset, windowSize])

  const otherWindow = useMemo(() => {
    if (direction !== 'both') return null
    return windows.get(windowKey('s2c', offset, windowSize)) ?? null
  }, [windows, direction, offset, windowSize])

  return {
    streams,
    files,
    loading,
    error,
    selected,
    selectedId,
    selectStream,
    direction,
    setDirection,
    offset,
    setOffset,
    window,
    otherWindow,
    pending,
    bytesError,
    reloadBytes,
    windowSize,
    loadLarger,
    previous,
    next,
    total,
  }
}
