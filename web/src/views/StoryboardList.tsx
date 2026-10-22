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
  endpointsLabel,
  formatEndpoints,
  findingEvidenceCount,
  isFindingEvent,
  protocolLabel,
  typeLabel,
  uncertaintyTags,
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
const EXPANDED_EXTRA = 96

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

  const heights = useMemo(
    () =>
      rows.map((row) => {
        const base = ROW_HEIGHTS[row.kind] ?? 72
        if (row.kind === 'event' || row.kind === 'not-dated') {
          return expandedCards.includes(row.event.id) ? base + EXPANDED_EXTRA : base
        }
        return base
      }),
    [rows, expandedCards],
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
    element.addEventListener('resize', measure)
    return () => element.removeEventListener('resize', measure)
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
  // card that is already visible is never moved (§5.14).
  useEffect(() => {
    if (selectedId === null) return
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

  return (
    <div className="storyboard-list" ref={scrollRef} onScroll={onScroll} tabIndex={-1}>
      {newCount > 0 ? (
        <div className="storyboard-list__pill">
          <LoadMorePill count={newCount} noun="events" onShow={onShowNew} />
        </div>
      ) : null}
      <div className="storyboard-list__canvas" style={{ height: range.totalHeight }}>
        {rows.slice(range.start, range.end).map((row, index) => {
          const top = offsets[range.start + index]
          return (
            <div
              key={row.key}
              className="storyboard-list__row"
              data-event-id={'event' in row ? row.event.id : undefined}
              style={{ transform: `translateY(${top}px)` }}
            >
              <StoryboardRowView
                row={row}
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
      <div className={row.depth > 0 ? 'storyboard-list__row storyboard-list__row--child' : 'storyboard-list__row'}>
        <GroupCard
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
          ? 'storyboard-list__row storyboard-list__row--child'
          : 'storyboard-list__row'
      }
    >
      <EventCard
        severity={severity}
        elapsed={formatElapsed(ts - captureStart)}
        wallClock={formatClock(ts, { basis })}
        typeLabel={typeLabel(event.type)}
        protocol={protocolLabel(event.proto)}
        title={event.title || typeLabel(event.type)}
        endpoints={endpointsText(event)}
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
  return formatEndpoints(event.src ?? '', event.dst ?? '') ?? undefined
}

/** The packet range of an event, or null when it has none. */
export function packetLabel(event: CaseEvent): string | null {
  if (!event.packetNo || event.packetNo <= 0) return null
  if (!event.packetEnd || event.packetEnd <= event.packetNo) return `pkt ${event.packetNo}`
  return `pkts ${event.packetNo}–${event.packetEnd}`
}
