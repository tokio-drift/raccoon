import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

import type { RaccoonApi } from '../api/api'
import { ApiError } from '../api/client'
import type { CarvedFile, StreamSummary, Verdict, VerdictEvent } from '../api/types'
import {
  fileSearchText,
  fileVerdict,
  sortFiles,
  type FileFilters,
  type FileSortKey,
} from '../lib/files'

/** The verdict statuses of the gallery filter (§6.9). */
export type VerdictStatusKey =
  | 'malicious'
  | 'suspicious'
  | 'unknown'
  | 'not_checked'
  | 'no_detections'

/** The state of the artifact gallery (UI_Design.md §6). */
export interface UseFiles {
  /** Every file of the case, with the live verdicts merged in. */
  files: CarvedFile[]
  /** The files that pass the filters. */
  filtered: CarvedFile[]
  /** The rows of the table, in the frozen order of the last sort. */
  rows: CarvedFile[]
  /** The streams of the case, by id, for the endpoints. */
  streams: Map<number, StreamSummary>
  loading: boolean
  error: ApiError | null
  reload: () => void
  /** The formats the case holds, for the filter. */
  formats: string[]
  /** The number of low-confidence files that are hidden. */
  hiddenCount: number
  /** The number of files per verdict status, for the filter. */
  verdictCounts: Record<VerdictStatusKey, number>
  /** The ids of the files whose verdict arrived live; their row pulses. */
  updatedIds: number[]
  selectedId: number | null
  select: (id: number | null) => void
  /** The sort of the table. */
  sortKey: FileSortKey
  sortDescending: boolean
  /** Sorts by a column; the same column again reverses the order. */
  setSort: (key: FileSortKey) => void
  /** True when a live verdict would change the order of the rows. */
  orderChanged: boolean
  /** Applies the current sort again and moves the rows. */
  reSort: () => void
}

export interface UseFilesOptions {
  caseId: string
  api: RaccoonApi
  filters: FileFilters
  sortKey: FileSortKey
  sortDescending: boolean
  /** The live verdicts of the case, by file id. */
  verdicts: Record<number, VerdictEvent>
  /** The file the deep link selects. */
  initialFileId: number | null
  /** Called when the reader sorts by another column. */
  onSortChange: (key: FileSortKey, descending: boolean) => void
}

interface FrozenOrder {
  key: FileSortKey
  descending: boolean
  ids: number[]
}

/**
 * The data of the artifact gallery. Every file is loaded once, so the counts
 * of the filter bar are exact and a filter change costs no request. The order
 * of the rows never changes on its own: a live verdict offers a re-sort
 * instead (§6.9).
 */
export function useFiles(options: UseFilesOptions): UseFiles {
  const { caseId, api, filters, sortKey, sortDescending, verdicts, initialFileId, onSortChange } =
    options
  const [files, setFiles] = useState<CarvedFile[]>([])
  const [streams, setStreams] = useState<Map<number, StreamSummary>>(new Map())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [nonce, setNonce] = useState(0)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [frozen, setFrozen] = useState<FrozenOrder | null>(null)
  const storageKey = `raccoon.files.${caseId}`

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const load = async (): Promise<void> => {
      const [filePage, streamPage] = await Promise.all([
        api.listFiles(caseId, { confidence: 'all' }),
        api.listStreams(caseId, { limit: 1000 }),
      ])
      if (cancelled) return
      setFiles(Array.isArray(filePage?.items) ? filePage.items : [])
      const map = new Map<number, StreamSummary>()
      for (const stream of Array.isArray(streamPage?.items) ? streamPage.items : []) {
        map.set(stream.id, stream)
      }
      setStreams(map)
      setError(null)
      setLoading(false)
    }
    load().catch((cause: unknown) => {
      if (cancelled) return
      setError(cause instanceof ApiError ? cause : new ApiError(0, 'internal', String(cause)))
      setLoading(false)
    })
    return () => {
      cancelled = true
    }
  }, [api, caseId, nonce])

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  // The live verdicts change the status of a file; the score, the source and
  // the time of the check stay as they were loaded (§6.6).
  const merged = useMemo(() => {
    if (Object.keys(verdicts).length === 0) return files
    return files.map((file) => {
      const live = verdicts[file.id]
      if (!live) return file
      const loaded = file.verdict
      const verdict: Verdict = {
        source: loaded?.source ?? 'threat check',
        status: live.status,
        score: loaded?.score ?? 0,
        total: loaded?.total ?? 0,
        checkedAt: loaded?.checkedAt ?? '',
      }
      return { ...file, verdict }
    })
  }, [files, verdicts])

  // The files that pass the filters (§6.9).
  const filtered = useMemo(() => {
    const query = filters.query.trim().toLowerCase()
    return merged.filter((file) => {
      if (filters.verdicts.length > 0 && !filters.verdicts.includes(fileVerdict(file))) return false
      if (filters.formats.length > 0 && !filters.formats.includes(file.format)) return false
      if (filters.dir !== null && file.dir !== filters.dir) return false
      if (filters.extractions.length > 0 && !filters.extractions.includes(file.status)) return false
      if (file.confidence === 'low' && !filters.showLowConfidence) return false
      if (query) {
        const stream = streams.get(file.streamId)
        if (!fileSearchText(file, stream).includes(query)) return false
      }
      return true
    })
  }, [merged, filters, streams])

  // The order the sort would give right now.
  const sorted = useMemo(
    () => sortFiles(filtered, sortKey, sortDescending),
    [filtered, sortKey, sortDescending],
  )

  // The order of the rows, as it was when the sort was applied. A live
  // verdict never moves a row (§6.9).
  const sortedIds = useRef<number[]>([])
  sortedIds.current = sorted.map((file) => file.id)

  // A new sort is applied at once: the reader asked for it.
  useEffect(() => {
    setFrozen({ key: sortKey, descending: sortDescending, ids: sortedIds.current })
  }, [sortKey, sortDescending])

  const current = frozen !== null && frozen.key === sortKey && frozen.descending === sortDescending

  const rows = useMemo(() => {
    if (!current || frozen === null) return sorted
    const byId = new Map(sorted.map((file) => [file.id, file]))
    const known = frozen.ids.filter((id) => byId.has(id))
    const added = sorted.filter((file) => !frozen.ids.includes(file.id)).map((file) => file.id)
    return [...known, ...added]
      .map((id) => byId.get(id))
      .filter((file): file is CarvedFile => file !== undefined)
  }, [sorted, current, frozen])

  // The reader is told when a live verdict would move a row.
  const orderChanged =
    current && frozen !== null ? frozen.ids.join(',') !== sorted.map((file) => file.id).join(',') : false

  const reSort = useCallback(() => {
    setFrozen({ key: sortKey, descending: sortDescending, ids: sortedIds.current })
  }, [sortKey, sortDescending])

  const setSort = useCallback(
    (key: FileSortKey) => {
      // The same column again reverses the order; a new column starts over.
      onSortChange(key, key === sortKey ? !sortDescending : false)
    },
    [onSortChange, sortKey, sortDescending],
  )

  // The selection is remembered per case (§6.7).
  useEffect(() => {
    setSelectedId(null)
    try {
      const raw = window.localStorage.getItem(storageKey)
      if (raw) {
        const stored = JSON.parse(raw) as { selectedId?: number | null }
        if (typeof stored.selectedId === 'number') setSelectedId(stored.selectedId)
      }
    } catch {
      // A browser without storage keeps the selection in memory only.
    }
  }, [storageKey])

  useEffect(() => {
    try {
      window.localStorage.setItem(storageKey, JSON.stringify({ selectedId }))
    } catch {
      // A missing localStorage must not break the gallery.
    }
  }, [selectedId, storageKey])

  // The deep link selects a file when the view opens (§3.2).
  useEffect(() => {
    if (initialFileId === null) return
    setSelectedId(initialFileId)
  }, [initialFileId])

  const select = useCallback((id: number | null) => setSelectedId(id), [])

  const formats = useMemo(() => {
    const names = new Set<string>()
    for (const file of merged) if (file.format) names.add(file.format)
    return [...names].sort((left, right) => left.localeCompare(right, 'en'))
  }, [merged])

  const hiddenCount = useMemo(
    () => merged.filter((file) => file.confidence === 'low').length,
    [merged],
  )

  const verdictCounts = useMemo(() => {
    const result: Record<VerdictStatusKey, number> = {
      malicious: 0,
      suspicious: 0,
      unknown: 0,
      not_checked: 0,
      no_detections: 0,
    }
    for (const file of merged) result[fileVerdict(file)] += 1
    return result
  }, [merged])

  const updatedIds = useMemo(
    () => Object.keys(verdicts).map((id) => Number(id)).filter((id) => Number.isInteger(id)),
    [verdicts],
  )

  return {
    files: merged,
    filtered,
    rows,
    streams,
    loading,
    error,
    reload,
    formats,
    hiddenCount,
    verdictCounts,
    updatedIds,
    selectedId,
    select,
    sortKey,
    sortDescending,
    setSort,
    orderChanged,
    reSort,
  }
}
