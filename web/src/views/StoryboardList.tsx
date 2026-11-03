import {
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type RefObject,
} from 'react'

import type { CaseEvent } from '../api/types'
import { Icon } from '../assets/icons'
import { ChapterHeader, EventCard, GroupCard } from '../components/content/EventCard'
import { EvidenceChip } from '../components/content/EvidenceChip'
import { LoadMorePill } from '../components/primitives/Pagination'
import {
  eventSeverity,
  endpointsForCard,
  endpointsLabel,
  formatEndpoints,
  findingEvidenceCount,
  isFindingEvent,
  isUnknownEventType,
  protocolLabel,
  typeLabel,
  uncertaintyTags,
  unknownTypeLabel,
} from '../lib/events'
import { formatClock, formatDuration, formatElapsed, parseTimestamp } from '../lib/format'
import type { StoryboardRow } from '../lib/storyboard'
import { computeOffsets, computeVirtualRange, findAnchor, ROW_HEIGHTS } from '../lib/virtual'

/**
 * The event list of the storyboard (UI_Design.md §5.1–§5.7). The feed is
 * virtualised: only the rows near the viewport are rendered, so a capture with
 * five thousand events scrolls as smoothly as a short one.
 */

/** The height a card gets when it is expanded. */
const EXPANDED_EXTRA = 120

/** The viewport height used when the container cannot be measured. */
const FALLBACK_VIEWPORT = 640

export interface StoryboardListProps {
  rows: StoryboardRow[]
  selectedId: number | null
  onSelect: (id: number) => void
  /** The ids of the groups that are expanded. */
  expandedGroups: number[]
  onToggleGroup: (id: number) => void
  /** The ids of the cards that are expanded. */
  expandedCards: number[]
  onToggleCard: (id: number) => void
  /** The start of the capture in milliseconds since the epoch. */
  captureStart: number
  /** The time basis of the wall-clock times. */
  basis: 'utc' | 'local'
  /** The number of events the server reports that are not in the list yet. */
  newCount: number
  onShowNew: () => void
  /** The titles of the findings, by event id. */
  findingTitles: Map<number, string>
  /** The reference of the scroll container. */
  containerRef?: RefObject<HTMLDivElement>
  /** The id of the event that must be scrolled to. */
  scrollToId?: number | null
  /** The id of the card that must take the focus. */
  focusId?: number | null
  onOpenStream?: (streamId: number, packetNo: number) => void
  onOpenFile?: (fileId: number) => void
}

export function StoryboardList({
  rows,
  selectedId,
  onSelect,
  expandedGroups,
  onToggleGroup,
  expandedCards,
  onToggleCard,
  captureStart,
  basis,
  newCount,
  onShowNew,
  findingTitles,
  containerRef,
  scrollToId,
  focusId,
  onOpenStream,
  onOpenFile,
}: StoryboardListProps): JSX.Element {
  const innerRef = useRef<HTMLDivElement | null>(null)
  const scrollRef = containerRef ?? innerRef
  const [scrollTop, setScrollTop] = useState(0)
  const [viewportHeight, setViewportHeight] = useState(FALLBACK_VIEWPORT)
  const anchor = useRef<{ key: string; delta: number } | null>(null)

  const [measuredHeights, setMeasuredHeights] = useState<
    Record<string, { height: number; expanded: boolean }>
  >({})

  const measureRow = useCallback(
    (key: string, expanded: boolean, node: HTMLDivElement | null) => {
      if (!node) return
      const height = node.offsetHeight
      if (height <= 0) return
      setMeasuredHeights((prev) => {
        const current = prev[key]
        if (current?.height === height && current.expanded === expanded) return prev
        return { ...prev, [key]: { height, expanded } }
      })
    },
    [],
  )

  const heights = useMemo(
    () =>
      rows.map((row) => {
        const base = ROW_HEIGHTS[row.kind] ?? 104
        const expandable = row.kind === 'event' || row.kind === 'not-dated'
        const expanded = expandable && expandedCards.includes(row.event.id)
        const measured = measuredHeights[row.key]
        // A measurement is only used for the state it was taken in. A card that
        // has just been expanded therefore keeps its estimated height until the
        // new height is read, instead of briefly overlapping the rows below.
        if (measured && measured.expanded === expanded) return measured.height
        return expandable && expanded ? base + EXPANDED_EXTRA : base
      }),
    [rows, expandedCards, measuredHeights],
  )
  const offsets = useMemo(() => computeOffsets(heights), [heights])

  useEffect(() => {
    const element = scrollRef.current
    if (!element) return
    const measure = () => {
      const height = element.clientHeight
      if (height > 0) setViewportHeight(height)
    }
    measure()
    window.addEventListener('resize', measure)
    let ro: ResizeObserver | null = null
    if (typeof ResizeObserver !== 'undefined') {
      ro = new ResizeObserver(measure)
      ro.observe(element)
    }
    return () => {
      window.removeEventListener('resize', measure)
      ro?.disconnect()
    }
  }, [scrollRef])

  // The reading position is kept when the list grows: the row that was at the
  // top stays at the top (§5.14).
  useLayoutEffect(() => {
    const element = scrollRef.current
    if (!element || !anchor.current) return
    const index = rows.findIndex((row) => row.key === anchor.current?.key)
    if (index < 0) return
    const next = offsets[index] + anchor.current.delta
    if (Math.abs(next - element.scrollTop) > 1) element.scrollTop = next
    anchor.current = null
  }, [rows, offsets, scrollRef])

  const onScroll = useCallback(() => {
    const element = scrollRef.current
    if (!element) return
    const position = findAnchor(offsets, element.scrollTop)
    const row = rows[position.index]
    if (row) anchor.current = { key: row.key, delta: position.delta }
    setScrollTop(element.scrollTop)
  }, [offsets, rows, scrollRef])

  // The deep link scrolls to its event once the list is there. It scrolls once
  // per link: the list never moves under the reader (§5.14).
  const scrolledTo = useRef<number | null>(null)
  useEffect(() => {
    if (scrollToId === null || scrollToId === undefined) return
    if (scrolledTo.current === scrollToId) return
    const index = rows.findIndex(
      (row) => row.kind === 'event' && row.event.id === scrollToId,
    )
    if (index < 0) return
    const element = scrollRef.current
    if (!element) return
    scrolledTo.current = scrollToId
    element.scrollTop = Math.max(0, offsets[index] - 80)
    setScrollTop(element.scrollTop)
  }, [scrollToId, rows, offsets, scrollRef])

  // The selected card is brought into view when the selection moves, so the
  // keyboard map of §5.17 ("next event: selects, scrolls into view") holds. A
  // card that is already visible is never moved (§5.14). The heights and the
  // offsets change while rows are measured, so the scroll happens once per
  // selection: otherwise scrolling away from the selected card would snap the
  // list back to it whenever a row above it was measured.
  const selectedScrolled = useRef<number | null>(null)
  useEffect(() => {
    if (selectedId === null) {
      selectedScrolled.current = null
      return
    }
    if (selectedScrolled.current === selectedId) return
    const index = rows.findIndex((row) => row.kind === 'event' && row.event.id === selectedId)
    if (index < 0) return
    const element = scrollRef.current
    if (!element) return
    const top = offsets[index]
    const bottom = top + (heights[index] ?? 72)
    if (top < element.scrollTop) {
      element.scrollTop = top
    } else if (bottom > element.scrollTop + element.clientHeight) {
      element.scrollTop = Math.max(0, bottom - element.clientHeight)
    }
    selectedScrolled.current = selectedId
    setScrollTop(element.scrollTop)
  }, [selectedId, rows, offsets, heights, scrollRef])

  // The card that must take the focus: it is scrolled into view first, so the
  // reader sees where the focus went (§5.17).
  const focused = useRef<number | null>(null)
  useEffect(() => {
    if (focusId === null || focusId === undefined) return
    if (focused.current === focusId) return
    const index = rows.findIndex(
      (row) => row.kind === 'event' && row.event.id === focusId,
    )
    if (index < 0) return
    const element = scrollRef.current
    if (!element) return
    focused.current = focusId
    element.scrollTop = Math.max(0, offsets[index] - 80)
    setScrollTop(element.scrollTop)
    const card = element.querySelector<HTMLElement>(`[data-event-id="${focusId}"] [role="listitem"]`)
    card?.focus()
  }, [focusId, rows, offsets, scrollRef])

  const range = computeVirtualRange(offsets, heights, scrollTop, viewportHeight)

  // The number of the row inside the list of events, for `aria-posinset` and
  // `aria-setsize` (§13.1). The list is virtualised, so the screen reader
  // needs to be told how long the whole list is.
  const ordinals = useMemo(() => {
    const list: number[] = []
    let count = 0
    for (const row of rows) {
      if (row.kind === 'event' || row.kind === 'group') {
        count += 1
        list.push(count)
      } else {
        list.push(0)
      }
    }
    return { list, total: count }
  }, [rows])

  return (
    <div className="storyboard-list" ref={scrollRef} onScroll={onScroll} tabIndex={-1}>
      {newCount > 0 ? (
        <div className="storyboard-list__pill">
          <LoadMorePill count={newCount} noun="events" onShow={onShowNew} />
        </div>
      ) : null}
      <div
        className="storyboard-list__canvas"
        style={{ height: range.totalHeight }}
        role="list"
        aria-label="Storyboard events"
      >
        {rows.slice(range.start, range.end).map((row, index) => {
          const top = offsets[range.start + index]
          const ordinal = ordinals.list[range.start + index] ?? 0
          const expanded =
            (row.kind === 'event' || row.kind === 'not-dated') &&
            expandedCards.includes(row.event.id)
          return (
            <div
              key={row.key}
              ref={(el) => measureRow(row.key, expanded, el)}
              className="storyboard-list__row"
              data-event-id={'event' in row ? row.event.id : undefined}
              role="presentation"
              style={{ transform: `translateY(${top}px)` }}
            >
              <StoryboardRowView
                row={row}
                position={ordinal > 0 ? { index: ordinal, total: ordinals.total } : undefined}
                selectedId={selectedId}
                onSelect={onSelect}
                expandedGroups={expandedGroups}
                onToggleGroup={onToggleGroup}
                expandedCards={expandedCards}
                onToggleCard={onToggleCard}
                captureStart={captureStart}
                basis={basis}
                findingTitles={findingTitles}
                onOpenStream={onOpenStream}
                onOpenFile={onOpenFile}
              />
            </div>
          )
        })}
      </div>
    </div>
  )
}

interface RowViewProps {
  row: StoryboardRow
  /** The place of the row in the list of events, for the screen reader. */
  position?: { index: number; total: number }
  selectedId: number | null
  onSelect: (id: number) => void
  expandedGroups: number[]
  onToggleGroup: (id: number) => void
  expandedCards: number[]
  onToggleCard: (id: number) => void
  captureStart: number
  basis: 'utc' | 'local'
  findingTitles: Map<number, string>
  onOpenStream?: (streamId: number, packetNo: number) => void
  onOpenFile?: (fileId: number) => void
}

/** Renders one row of the feed. */
function StoryboardRowView({
  row,
  position,
  selectedId,
  onSelect,
  expandedGroups,
  onToggleGroup,
  expandedCards,
  onToggleCard,
  captureStart,
  basis,
  findingTitles,
  onOpenStream,
  onOpenFile,
}: RowViewProps): JSX.Element | null {
  if (row.kind === 'chapter') {
    return (
      <div className="storyboard-list__chapter">
        <ChapterHeader label={row.label} count={row.count} span={row.span} />
      </div>
    )
  }

  if (row.kind === 'date') {
    return (
      <div className="storyboard-list__date">
        <span>{row.label}</span>
      </div>
    )
  }

  if (row.kind === 'not-dated-separator') {
    return (
      <div className="storyboard-list__not-dated">
        <span>{row.label}</span>
      </div>
    )
  }

  if (row.kind === 'gap') {
    return (
      <div className="storyboard-list__gap">
        <span>{row.label}</span>
      </div>
    )
  }

  if (row.kind === 'group') {
    const children = row.children
    const severity = groupSeverity(row.event, children)
    const first = children[0]
    const last = children[children.length - 1]
    const span =
      first && last
        ? `${formatDuration(parseTimestamp(last.ts) - parseTimestamp(first.ts))}`
        : undefined
    const packets =
      first && last
        ? `${first.packetNo}–${last.packetEnd}`
        : undefined
    // A group that lost children to the filters says how many are hidden
    // (§5.6): the reader sees that the list is short on purpose.
    const hidden = Math.max(0, row.total - children.length)
    return (
      <div className={row.depth > 0 ? 'storyboard-list__item storyboard-list__item--child' : 'storyboard-list__item'}>
        <GroupCard
          position={position}
          severity={severity}
          title={row.event.title || typeLabel(row.event.type)}
          count={row.total}
          subline={
            [
              `${children.length} events${span ? ` over ${span}` : ''}`,
              packets ? `pkts ${packets}` : null,
              hidden > 0 ? `${children.length} of ${row.total} shown` : null,
            ]
              .filter(Boolean)
              .join(' · ')
          }
          expanded={expandedGroups.includes(row.event.id)}
          onToggle={() => onToggleGroup(row.event.id)}
        />
      </div>
    )
  }

  const event = row.event
  const ts = parseTimestamp(event.ts)
  const expanded = expandedCards.includes(event.id)
  const severity = eventSeverity(event)
  const tags = uncertaintyTags(event)
  const finding = isFindingEvent(event)
  const evidence = findingEvidenceCount(event)
  const inFinding = (event.findingIds ?? [])
    .map((id) => findingTitles.get(id))
    .filter((title): title is string => Boolean(title))

  return (
    <div
      className={
        row.depth > 0
          ? 'storyboard-list__item storyboard-list__item--child'
          : 'storyboard-list__item'
      }
    >
      <EventCard
        position={position}
        severity={severity}
        elapsed={formatElapsed(ts - captureStart)}
        wallClock={formatClock(ts, { basis })}
        unknownTime={!event.ts}
        unknownType={isUnknownEventType(event.type)}
        typeLabel={
          isUnknownEventType(event.type) ? unknownTypeLabel(event.type) : typeLabel(event.type)
        }
        protocol={protocolLabel(event.proto)}
        title={event.title || typeLabel(event.type)}
        mutedTitle={!event.title}
        endpoints={endpointsText(event)}
        endpointsFull={formatEndpoints(event.src ?? '', event.dst ?? '') ?? undefined}
        endpointsLabel={endpointsLabel(event.src ?? '', event.dst ?? '') || undefined}
        packetRange={packetLabel(event) ?? undefined}
        onPacketRange={
          event.streamId > 0 && onOpenStream
            ? () => onOpenStream(event.streamId, event.packetNo)
            : undefined
        }
        expanded={expanded}
        selected={selectedId === event.id}
        summary={event.explain ? event.explain.slice(0, 140) : undefined}
        badges={
          <>
            {finding ? (
              <span className="tag tag--plain storyboard-card__finding">
                <Icon name="bookmark" size={14} />
                <span>{evidence !== null ? `Finding · ${evidence} supporting events` : 'Finding'}</span>
              </span>
            ) : null}
            {inFinding.map((title) => (
              <span key={title} className="tag tag--plain storyboard-card__finding">
                <Icon name="bookmark" size={14} />
                <span>{`In finding: ${title}`}</span>
              </span>
            ))}
            {tags.map((tag) => (
              <span key={tag.label} className="tag tag--uncertain" title={tag.help}>
                <Icon name={tag.icon} size={14} />
                <span>{tag.label}</span>
              </span>
            ))}
          </>
        }
        evidence={
          <div className="storyboard-card__evidence">
            {event.streamId > 0 ? (
              <EvidenceChip
                kind="stream"
                label={`Stream ${event.streamId}`}
                onClick={onOpenStream ? () => onOpenStream(event.streamId, 0) : undefined}
              />
            ) : null}
            {event.fileId > 0 ? (
              <EvidenceChip
                kind="file"
                label={`File ${event.fileId}`}
                onClick={onOpenFile ? () => onOpenFile(event.fileId) : undefined}
              />
            ) : null}
            {packetLabel(event) ? (
              <EvidenceChip
                kind="packets"
                label={packetLabel(event) as string}
                title={
                  event.streamId > 0
                    ? 'Opens the stream at this packet.'
                    : 'This event has no stream.'
                }
                onClick={
                  event.streamId > 0 && onOpenStream
                    ? () => onOpenStream(event.streamId, event.packetNo)
                    : undefined
                }
              />
            ) : null}
          </div>
        }
        onToggle={() => onToggleCard(event.id)}
        onOpen={() => onSelect(event.id)}
      />
    </div>
  )
}

/** The severity of a group: the highest of its children, never lower (§5.6). */
function groupSeverity(event: CaseEvent, children: CaseEvent[]): 'info' | 'warning' | 'critical' {
  let severity = eventSeverity(event)
  for (const child of children) {
    const childSeverity = eventSeverity(child)
    if (childSeverity === 'critical') return 'critical'
    if (childSeverity === 'warning') severity = 'warning'
  }
  return severity
}

/** The endpoints of a card, or null when the event has none. */
function endpointsText(event: CaseEvent): string | undefined {
  return endpointsForCard(event.src ?? '', event.dst ?? '') ?? undefined
}

/** The packet range of an event, or null when it has none. */
export function packetLabel(event: CaseEvent): string | null {
  if (!event.packetNo || event.packetNo <= 0) return null
  if (!event.packetEnd || event.packetEnd <= event.packetNo) return `pkt ${event.packetNo}`
  return `pkts ${event.packetNo}–${event.packetEnd}`
}
