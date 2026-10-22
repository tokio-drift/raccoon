import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { RaccoonApi } from '../api/api'
import { ApiError } from '../api/client'
import type { CarvedFile, CaseEvent, Severity, VerdictStatus } from '../api/types'
import { eventSearchText, eventSeverity, isFindingEvent } from '../lib/events'
import {
  buildRows,
  filterEvents,
  presentPhases,
  presentProtocols,
  presentTypes,
  severityCounts,
  type StoryboardFilters,
  type StoryboardRow,
} from '../lib/storyboard'
import { parseTimestamp } from '../lib/format'

/** The page size the storyboard asks for; it is the maximum of the server. */
export const STORYBOARD_PAGE_SIZE = 1000

/** The state of the storyboard feed. */
export interface UseStoryboard {
  /** Every event of the case, in the order of the server. */
  events: CaseEvent[]
  /** The events that pass the filters. */
  filtered: CaseEvent[]
  /** The rows of the feed: chapters, separators, gaps, cards and groups. */
  rows: StoryboardRow[]
  loading: boolean
  error: ApiError | null
  reload: () => void
  filters: StoryboardFilters
  setFilters: (next: StoryboardFilters) => void
  selectedId: number | null
  select: (id: number | null) => void
  /** The ids of the groups that are expanded. */
  expandedGroups: number[]
  toggleGroup: (id: number) => void
  /** The number of events the server reports that are not in the list yet. */
  newCount: number
  /** Fetches the new events and inserts them in time order. */
  showNew: () => void
  counts: Record<Severity, number>
  /** The carved files of the case, with the low-confidence ones included. */
  files: CarvedFile[]
  /** The number of files per verdict status, for the brief band (§5.19). */
  verdictCounts: Record<VerdictStatus, number>
  /** The number of finding events in the case. */
  findingCount: number
  types: string[]
  protos: string[]
  phases: string[]
  hasPhases: boolean
  /** The start of the capture, in milliseconds since the epoch. */
  captureStart: number
  /** The length of the capture, in milliseconds. */
  duration: number
}

export interface UseStoryboardOptions {
  caseId: string
  api: RaccoonApi
  filters: StoryboardFilters
  onFiltersChange: (filters: StoryboardFilters) => void
  /** The number of events the server reports; used for the live pill. */
  total: number | null
  /** The time basis of the date separators. */
  basis: 'utc' | 'local'
  /** The event the deep link selects. */
  initialEventId: number | null
}

interface PersistedState {
  selectedId: number | null
  expandedGroups: number[]
}

/**
 * The data of the storyboard. Every event of the case is loaded once, so the
 * result count of the filter bar is exact and a filter change costs no
 * request. The filters live in the URL, the selection and the open groups are
 * remembered per case (§3.2, §5.15, §5.17).
 */
export function useStoryboard(options: UseStoryboardOptions): UseStoryboard {
  const { caseId, api, filters, onFiltersChange, total, basis, initialEventId } = options
  const [events, setEvents] = useState<CaseEvent[]>([])
  const [files, setFiles] = useState<CarvedFile[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<ApiError | null>(null)
  const [nonce, setNonce] = useState(0)
  const [selectedId, setSelectedId] = useState<number | null>(null)
  const [expandedGroups, setExpandedGroups] = useState<number[]>([])
  const restored = useRef(false)
  const dirty = useRef(false)
  const chosen = useRef(false)

  const storageKey = `raccoon.storyboard.${caseId}`

  // The selection and the open groups are remembered per case.
  useEffect(() => {
    restored.current = false
    dirty.current = false
    chosen.current = false
    setSelectedId(null)
    setExpandedGroups([])
    try {
      const raw = window.localStorage.getItem(storageKey)
      if (raw) {
        const stored = JSON.parse(raw) as PersistedState
        setSelectedId(typeof stored.selectedId === 'number' ? stored.selectedId : null)
        setExpandedGroups(Array.isArray(stored.expandedGroups) ? stored.expandedGroups : [])
      }
    } catch {
      // A browser without storage keeps the state in memory only.
    }
    restored.current = true
  }, [storageKey])

  useEffect(() => {
    if (!restored.current || !dirty.current) return
    try {
      window.localStorage.setItem(
        storageKey,
        JSON.stringify({ selectedId, expandedGroups } satisfies PersistedState),
      )
    } catch {
      // A missing localStorage must not break the storyboard.
    }
  }, [selectedId, expandedGroups, storageKey])

  // The deep link selects an event when the view opens (§3.2). It does not
  // change the remembered selection: the link is a visit, not a choice.
  useEffect(() => {
    if (initialEventId === null) return
    chosen.current = true
    setSelectedId(initialEventId)
  }, [initialEventId])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    const load = async (): Promise<void> => {
      const collected: CaseEvent[] = []
      let cursor: string | undefined
      for (;;) {
        const page = await api.listEvents(caseId, {
          limit: STORYBOARD_PAGE_SIZE,
          cursor,
          flat: true,
        })
        if (cancelled) return
        if (Array.isArray(page?.items)) collected.push(...page.items)
        if (!page.nextCursor) break
        cursor = page.nextCursor
      }
      setEvents(collected)
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

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  const filtered = useMemo(
    () => filterEvents(events, filters, eventSearchText),
    [events, filters],
  )

  const rows = useMemo(
    () =>
      buildRows(filtered, {
        expandedGroups: new Set(expandedGroups),
        basis,
        allEvents: events,
      }),
    [filtered, events, expandedGroups, basis],
  )

  const setFilters = useCallback(
    (next: StoryboardFilters) => onFiltersChange(next),
    [onFiltersChange],
  )

  const select = useCallback((id: number | null) => {
    dirty.current = true
    setSelectedId(id)
  }, [])

  const toggleGroup = useCallback((id: number) => {
    dirty.current = true
    setExpandedGroups((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    )
  }, [])

  // The events the server reports but the list does not hold yet. They are
  // never inserted on their own; the reader decides with the pill (§5.14).
  const newCount = total === null ? 0 : Math.max(0, total - events.length)

  const showNew = useCallback(() => {
    setNonce((value) => value + 1)
  }, [])

  const timed = useMemo(
    () => events.filter((event) => Boolean(event.ts)).map((event) => parseTimestamp(event.ts)),
    [events],
  )
  const captureStart = timed.length > 0 ? timed[0] : 0
  const duration = timed.length > 0 ? timed[timed.length - 1] - timed[0] : 0

  // A case that is opened without a remembered selection starts at the first
  // critical event, or at the first event when there is none (§3.4).
  useEffect(() => {
    if (chosen.current) return
    if (loading || events.length === 0) return
    chosen.current = true
    if (selectedId !== null) return
    const critical = events.find((event) => eventSeverity(event) === 'critical')
    setSelectedId((critical ?? events[0]).id)
  }, [events, loading, selectedId])

  const counts = useMemo(() => severityCounts(events), [events])
  const verdictCounts = useMemo(() => {
    const result: Record<VerdictStatus, number> = {
      malicious: 0,
      suspicious: 0,
      no_detections: 0,
      unknown: 0,
      not_checked: 0,
    }
    for (const file of Array.isArray(files) ? files : []) {
      result[file.verdict?.status ?? 'not_checked'] += 1
    }
    return result
  }, [files])
  const findingCount = useMemo(
    () => events.filter((event) => isFindingEvent(event)).length,
    [events],
  )
  const types = useMemo(() => presentTypes(events), [events])
  const protos = useMemo(() => presentProtocols(events), [events])
  const phases = useMemo(() => presentPhases(events), [events])

  return {
    events,
    filtered,
    rows,
    loading,
    error,
    reload,
    filters,
    setFilters,
    selectedId,
    select,
    expandedGroups,
    toggleGroup,
    newCount,
    showNew,
    counts,
    files,
    verdictCounts,
    findingCount,
    types,
    protos,
    phases,
    hasPhases: phases.length > 0,
    captureStart,
    duration,
  }
}
