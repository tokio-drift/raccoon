import { useCallback, useEffect, useMemo, useRef, useState, type JSX, type RefObject } from 'react'

import type { CaseEvent } from '../api/types'
import { Button } from '../components/primitives/Button'
import { PaneResizer } from '../components/primitives/PaneResizer'
import { EmptyState, ErrorState } from '../components/primitives/States'
import { Skeleton } from '../components/primitives/Skeleton'
import { TimeStrip } from '../components/content/TimeStrip'
import { CaseBriefBand } from './CaseBriefBand'
import { StoryboardDetailPane } from './StoryboardDetailPane'
import { StoryboardFilterBar } from './StoryboardFilterBar'
import { StoryboardJumpBar } from './StoryboardJumpBar'
import { StoryboardList } from './StoryboardList'
import { eventSeverity, isFindingEvent } from '../lib/events'
import { filtersActive, filtersFromParams, filtersToParams, type StoryboardFilters } from '../lib/storyboard'
import { formatCount, parseTimestamp } from '../lib/format'
import { usePreferences } from '../lib/preferences'
import { useRoute, type URLParams } from '../lib/router'
import { useResizablePane } from '../hooks/useResizablePane'
import { useStoryboard } from '../hooks/useStoryboard'
import type { RaccoonApi } from '../api/api'

/**
 * The Storyboard view (UI_Design.md §4.3, §5). It shows the chronological
 * event feed, the case brief, the filters, the time strip, the detail pane and
 * all of its states.
 */

/** The smallest width of the event list, in pixels (§14.2). */
const LIST_MIN_WIDTH = 420

/** The largest width of the event list, in pixels (§14.2). */
const LIST_MAX_WIDTH = 640

/** The smallest width of the detail pane, in pixels (§14.2). */
const DETAIL_MIN_WIDTH = 440

export interface StoryboardViewProps {
  caseId: string
  api: RaccoonApi
  /** The number of events reported by the server; used for the live pill. */
  totalEvents: number | null
  params: URLParams
  onParamsChange: (params: URLParams) => void
  onOpenStreams: () => void
  headingRef?: RefObject<HTMLHeadingElement>
  /** The analysis is still running; the list shows partial results (§5.18). */
  partial?: boolean
  /** The analysis stopped early; the results are partial (§8.5). */
  partialResults?: boolean
}

export function StoryboardView({
  caseId,
  api,
  totalEvents,
  params,
  onParamsChange,
  onOpenStreams,
  headingRef,
  partial = false,
  partialResults = false,
}: StoryboardViewProps): JSX.Element {
  const [preferences] = usePreferences()
  const { navigate } = useRoute()
  const [briefCollapsed, setBriefCollapsed] = useState(false)
  const [expandedCards, setExpandedCards] = useState<number[]>([])
  const [focusRequest, setFocusRequest] = useState<number | null>(null)
  const searchRef = useRef<HTMLInputElement | null>(null)
  const detailRef = useRef<HTMLElement | null>(null)

  const initialFilters = useMemo(() => filtersFromParams(params), [params])
  const [filters, setFilters] = useState<StoryboardFilters>(initialFilters)
  // The list pane can be resized; the width is remembered (§14.2).
  const listPane = useResizablePane('storyboard-list', {
    min: LIST_MIN_WIDTH,
    max: LIST_MAX_WIDTH,
    fallback: 500,
  })
  const listWidth = listPane.width

  // The deep link of the event: `?event={id}` (§3.2). It is read on every
  // change, so a link that arrives while the view is open still selects.
  const deepLinkId = useMemo(() => {
    const value = params.event
    if (!value) return null
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null
  }, [params.event])

  // Keep the URL in sync with the filters (§3.2, §5.15). The same filter set
  // is never written twice, so the view cannot loop over the address bar.
  const filterParams = useMemo(() => filtersToParams(filters), [filters])
  const pushedParams = useRef<string>('')
  useEffect(() => {
    const key = JSON.stringify(filterParams)
    if (pushedParams.current === key) return
    pushedParams.current = key
    onParamsChange(filterParams)
  }, [filterParams, onParamsChange])

  const storyboard = useStoryboard({
    caseId,
    api,
    filters,
    onFiltersChange: setFilters,
    total: totalEvents,
    basis: preferences.timeBasis,
    initialEventId: deepLinkId,
  })

  const { selectedId, select, expandedGroups, toggleGroup, rows, events, filtered } = storyboard

  const toggleCard = useCallback((id: number) => {
    setExpandedCards((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id],
    )
  }, [])

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

  // The rows that hold an event, so the keyboard knows what a selection is.
  const groupIds = useMemo(() => {
    const ids = new Set<number>()
    for (const row of rows) if (row.kind === 'group') ids.add(row.event.id)
    return ids
  }, [rows])

  // Space and the right arrow open the selected card or group (§5.17).
  const toggleSelection = useCallback(
    (id: number) => {
      if (groupIds.has(id)) {
        toggleGroup(id)
        return
      }
      toggleCard(id)
    },
    [groupIds, toggleCard, toggleGroup],
  )

  // The left arrow closes the card, and moves to the parent when the card is
  // already closed (§5.17).
  const collapseSelection = useCallback(
    (id: number) => {
      if (groupIds.has(id)) {
        if (expandedGroups.includes(id)) toggleGroup(id)
        return
      }
      if (expandedCards.includes(id)) {
        toggleCard(id)
        return
      }
      const parent = events.find((item) => item.id === id)?.parentId ?? 0
      if (parent > 0) select(parent)
    },
    [groupIds, expandedGroups, expandedCards, events, select, toggleCard, toggleGroup],
  )

  // "/" focuses the search field (§5.17).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null
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

  // The keyboard map of the list (§5.17). The keys work wherever the focus
  // is, except in a text field, and never twice: a card that has the focus
  // handles Space itself.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      if (event.metaKey || event.ctrlKey || event.altKey) return
      const onCard = target?.getAttribute('role') === 'listitem'
      const inDetail = detailRef.current?.contains(target ?? null) ?? false
      const ids = events.map((item) => item.id)

      if (event.key === 'Escape') {
        if (inDetail) {
          event.preventDefault()
          setFocusRequest(selectedId)
          return
        }
        if (selectedId !== null) {
          event.preventDefault()
          select(null)
        }
        return
      }

      if (event.key === 'Enter') {
        event.preventDefault()
        detailRef.current?.focus()
        return
      }

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
      if ((event.key === ' ' || event.key === 'ArrowRight') && !onCard) {
        if (selectedId === null) return
        event.preventDefault()
        toggleSelection(selectedId)
        return
      }
      if (event.key === 'ArrowLeft' && !onCard) {
        if (selectedId === null) return
        event.preventDefault()
        collapseSelection(selectedId)
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
        if (!eventItem) return
        if (eventItem.streamId > 0) {
          event.preventDefault()
          onOpenStream(eventItem.streamId, eventItem.packetNo)
          return
        }
        if (eventItem.fileId > 0) {
          event.preventDefault()
          onOpenFile(eventItem.fileId)
        }
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [
    events,
    selectedId,
    select,
    caseId,
    navigate,
    toggleSelection,
    collapseSelection,
    onOpenStream,
    onOpenFile,
    detailRef,
  ])

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
  const relatedFile = useMemo(() => {
    if (!selectedEvent || selectedEvent.fileId <= 0) return null
    return storyboard.files.find((file) => file.id === selectedEvent.fileId) ?? null
  }, [selectedEvent, storyboard.files])
  const selectedChildren = useMemo(() => {
    if (!selectedEvent) return []
    return events.filter((event) => event.parentId === selectedEvent.id)
  }, [selectedEvent, events])
  const criticalIds = useMemo(
    () => events.filter((event) => eventSeverity(event) === 'critical').map((event) => event.id),
    [events],
  )
  const criticalIndex = selectedId === null ? -1 : criticalIds.indexOf(selectedId)
  const warningIds = useMemo(
    () => events.filter((event) => eventSeverity(event) === 'warning').map((event) => event.id),
    [events],
  )
  const warningIndex = selectedId === null ? -1 : warningIds.indexOf(selectedId)

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

  const previousWarning = useCallback(() => {
    if (warningIds.length === 0) return
    const index = warningIndex <= 0 ? warningIds.length - 1 : warningIndex - 1
    select(warningIds[index])
  }, [warningIds, warningIndex, select])

  const nextWarning = useCallback(() => {
    if (warningIds.length === 0) return
    const index = warningIndex < 0 ? 0 : (warningIndex + 1) % warningIds.length
    select(warningIds[index])
  }, [warningIds, warningIndex, select])

  const clearAll = useCallback(() => setFilters({ ...filters, severities: [], types: [], protos: [], phases: [], query: '', from: null, to: null, findingsOnly: false }), [filters])

  // "Reset view" puts the view back to its start: no filter, no search and no
  // selection (UI_Design.md §3.6).
  const resetView = useCallback(() => {
    clearAll()
    storyboard.select(null)
  }, [clearAll, storyboard])


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
            onResetView={resetView}
            onPreviousCritical={previousCritical}
            onNextCritical={nextCritical}
            canJumpCritical={criticalIds.length > 0}
            onPreviousWarning={previousWarning}
            onNextWarning={nextWarning}
            canJumpWarning={warningIds.length > 0}
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
            onResetView={resetView}
            onPreviousCritical={previousCritical}
            onNextCritical={nextCritical}
            canJumpCritical={criticalIds.length > 0}
            onPreviousWarning={previousWarning}
            onNextWarning={nextWarning}
            canJumpWarning={warningIds.length > 0}
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
      <h1 className="visually-hidden" ref={headingRef} tabIndex={-1}>
        Storyboard
      </h1>
      {partialResults ? (
        <p className="storyboard__partial">
          <span className="tag tag--warning">Partial</span>
          The analysis stopped early. Some events are missing.
        </p>
      ) : null}
      {partial ? (
        <p className="storyboard__partial" role="status">
          Showing partial results. Analysis is still running; events may be added.{' '}
          {`${formatCount(events.length)} events so far`}
        </p>
      ) : null}
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
            onResetView={resetView}
          onPreviousCritical={previousCritical}
          onNextCritical={nextCritical}
          canJumpCritical={criticalIds.length > 0}
          onPreviousWarning={previousWarning}
          onNextWarning={nextWarning}
          canJumpWarning={warningIds.length > 0}
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

      <div
        className="storyboard__body"
        style={{ gridTemplateColumns: `${listWidth}px 8px minmax(${DETAIL_MIN_WIDTH}px, 1fr)` }}
      >
        <div className="storyboard__list-pane" role="region" aria-label="Event list">
          <StoryboardJumpBar
            events={events}
            captureStart={storyboard.captureStart}
            selectedId={selectedId}
            onSelect={select}
          />
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
            scrollToId={deepLinkId}
            focusId={focusRequest}
            onOpenStream={onOpenStream}
            onOpenFile={onOpenFile}
          />
        </div>
        <PaneResizer
          value={listWidth}
          min={LIST_MIN_WIDTH}
          max={LIST_MAX_WIDTH}
          onChange={listPane.setWidth}
          label="Resize the event list"
        />
        <StoryboardDetailPane
          paneRef={detailRef}
          event={selectedEvent}
          relatedFile={relatedFile}
          children={selectedChildren}
          findingTitles={selectedEvent ? (selectedEvent.findingIds ?? []).map((id) => findingTitles.get(id) ?? `Finding ${id}`) : []}
          findings={events.filter((event) => isFindingEvent(event))}
          supportedTitles={titlesByEvent}
          eventsById={eventsById}
          captureStart={storyboard.captureStart}
          onSelectEvent={select}
          onOpenStream={onOpenStream}
          onOpenFile={onOpenFile}
        />
      </div>
    </section>
  )
}
