import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react'

import type { CaseEvent } from '../api/types'
import { Button } from '../components/primitives/Button'
import { EmptyState, ErrorState } from '../components/primitives/States'
import { Skeleton } from '../components/primitives/Skeleton'
import { TimeStrip } from '../components/content/TimeStrip'
import { CaseBriefBand } from './CaseBriefBand'
import { StoryboardDetailPane } from './StoryboardDetailPane'
import { StoryboardFilterBar } from './StoryboardFilterBar'
import { StoryboardList } from './StoryboardList'
import { eventSeverity, isFindingEvent } from '../lib/events'
import { filtersActive, filtersFromParams, filtersToParams, type StoryboardFilters } from '../lib/storyboard'
import { parseTimestamp } from '../lib/format'
import { usePreferences } from '../lib/preferences'
import { useRoute, type URLParams } from '../lib/router'
import { useStoryboard } from '../hooks/useStoryboard'
import type { RaccoonApi } from '../api/api'

/**
 * The Storyboard view (UI_Design.md §4.3, §5). It shows the chronological
 * event feed, the case brief, the filters, the time strip, the detail pane and
 * all of its states.
 */

export interface StoryboardViewProps {
  caseId: string
  api: RaccoonApi
  /** The number of events reported by the server; used for the live pill. */
  totalEvents: number | null
  params: URLParams
  onParamsChange: (params: URLParams) => void
  onOpenStreams: () => void
}

export function StoryboardView({
  caseId,
  api,
  totalEvents,
  params,
  onParamsChange,
  onOpenStreams,
}: StoryboardViewProps): JSX.Element {
  const [preferences] = usePreferences()
  const { navigate } = useRoute()
  const [briefCollapsed, setBriefCollapsed] = useState(false)
  const [expandedCards, setExpandedCards] = useState<number[]>([])
  const searchRef = useRef<HTMLInputElement | null>(null)

  const initialFilters = useMemo(() => filtersFromParams(params), [params])
  const [filters, setFilters] = useState<StoryboardFilters>(initialFilters)

  // Keep the URL in sync with the filters (§3.2, §5.15).
  useEffect(() => {
    const next = filtersToParams(filters)
    onParamsChange(next)
  }, [filters, onParamsChange])

  const [initialEventId] = useState<number | null>(() => {
    const value = params.event
    if (!value) return null
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null
  })

  const storyboard = useStoryboard({
    caseId,
    api,
    filters,
    onFiltersChange: setFilters,
    total: totalEvents,
    basis: preferences.timeBasis,
    initialEventId,
  })

  const { selectedId, select, expandedGroups, toggleGroup, rows, events, filtered } = storyboard

  // "/" focuses the search field (§5.17).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      if (event.key === '/') {
        event.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // The keyboard map of the list (§5.17).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      const ids = events.map((item) => item.id)
      if (ids.length === 0) return
      const index = selectedId === null ? -1 : ids.indexOf(selectedId)
      if (event.key === 'ArrowDown' || event.key === 'j') {
        event.preventDefault()
        const next = ids[Math.min(ids.length - 1, index + 1)]
        select(next)
        return
      }
      if (event.key === 'ArrowUp' || event.key === 'k') {
        event.preventDefault()
        const next = ids[Math.max(0, index <= 0 ? 0 : index - 1)]
        select(next === undefined ? null : index === -1 ? ids[0] : next)
        return
      }
      if (event.key === 'Home') {
        event.preventDefault()
        select(ids[0])
        return
      }
      if (event.key === 'End') {
        event.preventDefault()
        select(ids[ids.length - 1])
        return
      }
      if (event.key === '[' || event.key === ']') {
        const critical = events
          .filter((item) => eventSeverity(item) === 'critical')
          .map((item) => item.id)
        if (critical.length === 0) return
        const current = selectedId === null ? -1 : critical.indexOf(selectedId)
        const targetIndex =
          event.key === '['
            ? Math.max(0, current <= 0 ? 0 : current - 1)
            : Math.min(critical.length - 1, current + 1)
        event.preventDefault()
        select(critical[targetIndex])
        return
      }
      if (event.key === 'e' && selectedId !== null) {
        const eventItem = events.find((item) => item.id === selectedId)
        if (!eventItem || eventItem.streamId <= 0) return
        event.preventDefault()
        navigate(
          `/case/${encodeURIComponent(caseId)}/streams?stream=${eventItem.streamId}&offset=0`,
        )
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [events, selectedId, select, caseId, navigate])

  const toggleCard = useCallback((id: number) => {
    setExpandedCards((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    )
  }, [])

  const eventsById = useMemo(() => {
    const map = new Map<number, CaseEvent>()
    for (const event of events) map.set(event.id, event)
    return map
  }, [events])

  const findingTitles = useMemo(() => {
    const map = new Map<number, string>()
    for (const event of events) {
      if (isFindingEvent(event)) map.set(event.id, event.title || 'Finding')
    }
    return map
  }, [events])

  const titlesByEvent = useMemo(() => {
    const map = new Map<number, string>()
    for (const event of events) map.set(event.id, event.title || '')
    return map
  }, [events])

  const selectedEvent = selectedId === null ? null : eventsById.get(selectedId) ?? null
  const criticalIds = useMemo(
    () => events.filter((event) => eventSeverity(event) === 'critical').map((event) => event.id),
    [events],
  )
  const criticalIndex = selectedId === null ? -1 : criticalIds.indexOf(selectedId)

  const previousCritical = useCallback(() => {
    if (criticalIds.length === 0) return
    const index = criticalIndex <= 0 ? criticalIds.length - 1 : criticalIndex - 1
    select(criticalIds[index])
  }, [criticalIds, criticalIndex, select])

  const nextCritical = useCallback(() => {
    if (criticalIds.length === 0) return
    const index = criticalIndex < 0 ? 0 : (criticalIndex + 1) % criticalIds.length
    select(criticalIds[index])
  }, [criticalIds, criticalIndex, select])

  const firstCritical = useCallback(() => {
    if (criticalIds.length === 0) return
    select(criticalIds[0])
  }, [criticalIds, select])

  const clearAll = useCallback(() => setFilters({ ...filters, severities: [], types: [], protos: [], phases: [], query: '', from: null, to: null, findingsOnly: false }), [filters])

  const onOpenStream = useCallback(
    (streamId: number, packetNo: number) => {
      const offset = packetNo > 0 ? String(packetNo) : '0'
      navigate(
        `/case/${encodeURIComponent(caseId)}/streams?stream=${streamId}&dir=c2s&offset=${offset}`,
      )
    },
    [caseId, navigate],
  )

  const onOpenFile = useCallback(
    (fileId: number) => {
      navigate(`/case/${encodeURIComponent(caseId)}/files?file=${fileId}`)
    },
    [caseId, navigate],
  )

  if (storyboard.loading) {
    return (
      <section className="storyboard" aria-label="Storyboard">
        <div className="storyboard__top">
          <CaseBriefBand
            counts={storyboard.counts}
            verdictCounts={storyboard.verdictCounts}
            findingCount={storyboard.findingCount}
            duration={storyboard.duration}
            captureStart={storyboard.captureStart}
            collapsed={briefCollapsed}
            onToggleCollapsed={() => setBriefCollapsed((value) => !value)}
            onGoToFirstCritical={firstCritical}
            hasCritical={criticalIds.length > 0}
            findingsOnly={filters.findingsOnly}
            onToggleFindings={() => setFilters({ ...filters, findingsOnly: !filters.findingsOnly })}
          />
          <StoryboardFilterBar
            filters={filters}
            onChange={setFilters}
            total={events.length}
            matching={filtered.length}
            types={storyboard.types}
            protos={storyboard.protos}
            phases={storyboard.phases}
            onClearAll={clearAll}
            onPreviousCritical={previousCritical}
            onNextCritical={nextCritical}
            canJumpCritical={criticalIds.length > 0}
            searchRef={searchRef}
          />
          <TimeStrip
            ticks={events.map((event) => ({
              id: event.id,
              time: parseTimestamp(event.ts) - storyboard.captureStart,
              severity: eventSeverity(event),
            }))}
            duration={storyboard.duration}
            selectedId={selectedId ?? undefined}
            onSelect={(id) => select(id)}
            onRangeChange={(range) => {
              if (!range) {
                setFilters({ ...filters, from: null, to: null })
                return
              }
              setFilters({
                ...filters,
                from: storyboard.captureStart + range[0],
                to: storyboard.captureStart + range[1],
              })
            }}
            onRangeClear={() => setFilters({ ...filters, from: null, to: null })}
            range={
              filters.from !== null && filters.to !== null
                ? [filters.from - storyboard.captureStart, filters.to - storyboard.captureStart]
                : null
            }
          />
        </div>
        <div className="storyboard__body">
          <div className="storyboard__list-pane">
            <div className="storyboard__skeletons">
              {Array.from({ length: 8 }).map((_, index) => (
                <Skeleton key={index} />
              ))}
            </div>
          </div>
        </div>
      </section>
    )
  }

  if (storyboard.error) {
    return (
      <section className="storyboard" aria-label="Storyboard">
        <div className="storyboard__error">
          <ErrorState
            title="Couldn't load events"
            explanation={storyboard.error.message}
            actions={[
              { label: 'Try again', onClick: storyboard.reload, variant: 'primary' },
            ]}
          />
        </div>
      </section>
    )
  }

  if (events.length === 0) {
    return (
      <section className="storyboard" aria-label="Storyboard">
        <EmptyState
          kind="no-data"
          title="No events in this capture"
          body={`RACCOON read ${totalEvents ?? 0} packets but didn't find activity it knows how to describe. You can still read the raw conversations.`}
          actions={[{ label: 'Open Streams', onClick: onOpenStreams, variant: 'secondary' }]}
        />
      </section>
    )
  }

  if (filtered.length === 0 && filtersActive(filters)) {
    return (
      <section className="storyboard" aria-label="Storyboard">
        <div className="storyboard__top">
          <CaseBriefBand
            counts={storyboard.counts}
            verdictCounts={storyboard.verdictCounts}
            findingCount={storyboard.findingCount}
            duration={storyboard.duration}
            captureStart={storyboard.captureStart}
            collapsed={briefCollapsed}
            onToggleCollapsed={() => setBriefCollapsed((value) => !value)}
            onGoToFirstCritical={firstCritical}
            hasCritical={criticalIds.length > 0}
            findingsOnly={filters.findingsOnly}
            onToggleFindings={() => setFilters({ ...filters, findingsOnly: !filters.findingsOnly })}
          />
          <StoryboardFilterBar
            filters={filters}
            onChange={setFilters}
            total={events.length}
            matching={0}
            types={storyboard.types}
            protos={storyboard.protos}
            phases={storyboard.phases}
            onClearAll={clearAll}
            onPreviousCritical={previousCritical}
            onNextCritical={nextCritical}
            canJumpCritical={criticalIds.length > 0}
            searchRef={searchRef}
          />
        </div>
        <div className="storyboard__body">
          <div className="storyboard__list-pane">
            <EmptyState
              kind="filtered"
              title="No events match these filters"
              actions={[
                { label: 'Clear all filters', onClick: clearAll, variant: 'secondary' },
                { label: 'Show all severities', onClick: () => setFilters({ ...filters, severities: [] }), variant: 'tertiary' },
              ]}
            >
              {filters.severities.length > 0 ? (
                <Button variant="tertiary" onClick={() => setFilters({ ...filters, severities: [] })}>
                  {`Show all severities (${formatCount(storyboard.counts.info + storyboard.counts.warning + storyboard.counts.critical)})`}
                </Button>
              ) : null}
            </EmptyState>
          </div>
        </div>
      </section>
    )
  }

  return (
    <section className="storyboard" aria-label="Storyboard">
      <div className="storyboard__top">
        <CaseBriefBand
          counts={storyboard.counts}
          verdictCounts={storyboard.verdictCounts}
          findingCount={storyboard.findingCount}
          duration={storyboard.duration}
          captureStart={storyboard.captureStart}
          collapsed={briefCollapsed}
          onToggleCollapsed={() => setBriefCollapsed((value) => !value)}
          onGoToFirstCritical={firstCritical}
          hasCritical={criticalIds.length > 0}
          findingsOnly={filters.findingsOnly}
          onToggleFindings={() => setFilters({ ...filters, findingsOnly: !filters.findingsOnly })}
        />
        <StoryboardFilterBar
          filters={filters}
          onChange={setFilters}
          total={events.length}
          matching={filtered.length}
          types={storyboard.types}
          protos={storyboard.protos}
          phases={storyboard.phases}
          onClearAll={clearAll}
          onPreviousCritical={previousCritical}
          onNextCritical={nextCritical}
          canJumpCritical={criticalIds.length > 0}
          searchRef={searchRef}
        />
        <TimeStrip
          ticks={events.map((event) => ({
            id: event.id,
            time: parseTimestamp(event.ts) - storyboard.captureStart,
            severity: eventSeverity(event),
          }))}
          duration={storyboard.duration}
          selectedId={selectedId ?? undefined}
          onSelect={(id) => select(id)}
          onRangeChange={(range) => {
            if (!range) {
              setFilters({ ...filters, from: null, to: null })
              return
            }
            setFilters({
              ...filters,
              from: storyboard.captureStart + range[0],
              to: storyboard.captureStart + range[1],
            })
          }}
          onRangeClear={() => setFilters({ ...filters, from: null, to: null })}
          range={
            filters.from !== null && filters.to !== null
              ? [filters.from - storyboard.captureStart, filters.to - storyboard.captureStart]
              : null
          }
        />
      </div>

      <div className="storyboard__body">
        <div className="storyboard__list-pane" role="region" aria-label="Event list">
          <StoryboardList
            rows={rows}
            selectedId={selectedId}
            onSelect={select}
            expandedGroups={expandedGroups}
            onToggleGroup={toggleGroup}
            expandedCards={expandedCards}
            onToggleCard={toggleCard}
            captureStart={storyboard.captureStart}
            basis={preferences.timeBasis}
            newCount={storyboard.newCount}
            onShowNew={storyboard.showNew}
            findingTitles={findingTitles}
            scrollToId={initialEventId}
            onOpenStream={onOpenStream}
            onOpenFile={onOpenFile}
          />
        </div>
        <div className="storyboard__divider" />
        <StoryboardDetailPane
          event={selectedEvent}
          findingTitles={selectedEvent ? (selectedEvent.findingIds ?? []).map((id) => findingTitles.get(id) ?? `Finding ${id}`) : []}
          findings={events.filter((event) => isFindingEvent(event))}
          supportedTitles={titlesByEvent}
          eventsById={eventsById}
          onSelectEvent={select}
          onOpenStream={onOpenStream}
          onOpenFile={onOpenFile}
        />
      </div>
    </section>
  )
}

import { formatCount } from '../lib/format'
