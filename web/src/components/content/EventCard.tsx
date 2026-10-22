import type { JSX, KeyboardEvent, ReactNode } from 'react'

import { Icon } from '../../assets/icons'
import { SeverityBadge, type Severity } from './Badges'

export interface EventCardProps {
  severity: Severity
  /**
   * The place of the card in the virtualised list, so the screen reader knows
   * how long the whole list is (§13.1).
   */
  position?: { index: number; total: number }
  /** The elapsed time from the capture start, for example "+00:12.431". */
  elapsed: string
  /** The wall-clock time of day, for example "14:03:07.431". */
  wallClock: string
  /** The event has no time; the time block says so instead (§5.12). */
  unknownTime?: boolean
  /** The event type is not one this build knows (§5.12). */
  unknownType?: boolean
  /** The event type in plain words, for example "FTP login failed". */
  typeLabel: string
  /** The protocol tag, for example "FTP". */
  protocol?: string
  title: string
  /** The event has no title; the type words stand in for it, in muted text. */
  mutedTitle?: boolean
  /** The endpoints, for example "192.0.2.14:51822 → 192.0.2.50:21". */
  endpoints?: string
  /** The full endpoints, for the tooltip; a long IPv6 is elided in the text. */
  endpointsFull?: string
  /** The reading of the endpoints, "from … to …", for the screen reader. */
  endpointsLabel?: string
  /** The packet range chip, for example "pkts 14–19". */
  packetRange?: string
  /** The packet chip opens the stream; without it the chip is inert. */
  onPacketRange?: () => void
  /** The card is expanded. */
  expanded?: boolean
  /** The card is the selected one. */
  selected?: boolean
  /** The one-line summary of the explanation; only shown when expanded. */
  summary?: string
  /** The evidence links; only shown when expanded. */
  evidence?: ReactNode
  /** The badges of the card, for example a verdict badge. */
  badges?: ReactNode
  onToggle?: () => void
  onOpen?: () => void
}

/**
 * An event card (UI_Design.md §5.3). The severity is carried by the rail, the
 * icon and the label, never by colour alone; every text is inert.
 */
export function EventCard({
  severity,
  position,
  elapsed,
  wallClock,
  unknownTime = false,
  unknownType = false,
  typeLabel,
  protocol,
  title,
  mutedTitle = false,
  endpoints,
  endpointsFull,
  endpointsLabel,
  packetRange,
  onPacketRange,
  expanded = false,
  selected = false,
  summary,
  evidence,
  badges,
  onToggle,
  onOpen,
}: EventCardProps): JSX.Element {
  const classes = ['event-card', `event-card--${severity}`]
  if (expanded) classes.push('event-card--expanded')
  if (selected) classes.push('event-card--selected')

  const onKeyDown = (event: KeyboardEvent<HTMLElement>) => {
    // Space expands the card. Enter moves the focus into the detail pane
    // (§5.17), so the list never handles it.
    if (event.key === ' ') {
      event.preventDefault()
      onToggle?.()
    }
  }

  return (
    <article
      className={classes.join(' ')}
      tabIndex={0}
      role="listitem"
      aria-expanded={expanded}
      aria-posinset={position?.index}
      aria-setsize={position?.total}
      onKeyDown={onKeyDown}
      onClick={onOpen}
    >
      <span className={`event-card__rail event-card__rail--${severity}`} aria-hidden="true" />
      <div className="event-card__main">
        <div className="event-card__top">
          <SeverityBadge severity={severity} />
          <div className="event-card__time">
            {unknownTime ? (
              <span className="event-card__unknown-time">Time unknown</span>
            ) : (
              <>
                <span className="event-card__elapsed">{elapsed}</span>
                <span className="event-card__wall">{wallClock}</span>
              </>
            )}
          </div>
          {unknownType ? (
            <span className="event-card__unknown-type" title="This build does not know this event type.">
              <Icon name="unknown-event" size={14} />
            </span>
          ) : null}
          <span className="event-card__type">{typeLabel}</span>
          {protocol ? <span className="tag tag--plain">{protocol}</span> : null}
          {badges}
        </div>
        <p className={mutedTitle ? 'event-card__title event-card__title--muted' : 'event-card__title'} dir="auto">
          {title}
        </p>
        <div className="event-card__foot">
          {endpoints ? (
            <span
              className="event-card__endpoints"
              aria-label={endpointsLabel}
              title={endpointsFull ?? endpoints}
              dir="auto"
            >
              {endpoints}
            </span>
          ) : null}
          {packetRange ? (
            onPacketRange ? (
              <button
                type="button"
                className="evidence-chip"
                onClick={(event) => {
                  event.stopPropagation()
                  onPacketRange()
                }}
              >
                <Icon name="flag" size={14} />
                <span>{packetRange}</span>
              </button>
            ) : (
              <span className="evidence-chip">
                <Icon name="flag" size={14} />
                <span>{packetRange}</span>
              </span>
            )
          ) : null}
        </div>
        {expanded && summary ? <p className="event-card__summary">{summary}</p> : null}
        {expanded && evidence ? <div className="event-card__evidence">{evidence}</div> : null}
      </div>
      <button
        type="button"
        className="icon-button event-card__expand"
        aria-label={expanded ? 'Collapse event' : 'Expand event'}
        aria-expanded={expanded}
        onClick={(event) => {
          event.stopPropagation()
          onToggle?.()
        }}
      >
        <Icon name={expanded ? 'chevron-up' : 'chevron-down'} size={20} />
      </button>
    </article>
  )
}

export interface GroupCardProps {
  severity: Severity
  title: string
  /**
   * The place of the group in the virtualised list (§13.1).
   */
  position?: { index: number; total: number }
  /** The number of events in the group. */
  count: number
  /** The sub-line, for example "12 events over 8.4 s · pkts 14–61". */
  subline?: string
  expanded?: boolean
  /** The child cards; they are indented when the group is expanded. */
  children?: ReactNode
  onToggle?: () => void
}

/**
 * A group card (UI_Design.md §5.6). It replaces a run of child events and
 * keeps the severity of its children.
 */
export function GroupCard({
  severity,
  title,
  position,
  count,
  subline,
  expanded = false,
  children,
  onToggle,
}: GroupCardProps): JSX.Element {
  return (
    <div className={expanded ? 'group-card group-card--expanded' : 'group-card'}>
      <article
        className={`event-card event-card--${severity}`}
        tabIndex={0}
        role="listitem"
        aria-posinset={position?.index}
        aria-setsize={position?.total}
      >
        <span className={`event-card__rail event-card__rail--${severity}`} aria-hidden="true" />
        <div className="event-card__main">
          <div className="event-card__top">
            <SeverityBadge severity={severity} />
            <Icon name="group" size={16} />
            <span className="group-card__count">{`×${count}`}</span>
          </div>
          <p className="event-card__title" dir="auto">
          {title}
        </p>
          {subline ? <p className="group-card__subline">{subline}</p> : null}
        </div>
        <button
          type="button"
          className="icon-button event-card__expand"
          aria-label={expanded ? 'Collapse group' : 'Expand group'}
          aria-expanded={expanded}
          onClick={onToggle}
        >
          <Icon name={expanded ? 'chevron-up' : 'chevron-down'} size={20} />
        </button>
      </article>
      {expanded ? <div className="group-card__children">{children}</div> : null}
    </div>
  )
}

export interface ChapterHeaderProps {
  /** The phase label, for example "Access". */
  label: string
  /** The number of events in the phase. */
  count: number
  /** The time span of the phase. */
  span?: string
  /** The header is the plain variant without the phase stripe. */
  plain?: boolean
}

/**
 * A sticky chapter header (UI_Design.md §5.5). It labels a run of events of
 * the same phase.
 */
export function ChapterHeader({
  label,
  count,
  span,
  plain = false,
}: ChapterHeaderProps): JSX.Element {
  return (
    <div className={plain ? 'chapter-header chapter-header--plain' : 'chapter-header'}>
      <span className="chapter-header__label">{label}</span>
      <span className="chapter-header__count">{count}</span>
      {span ? <span className="chapter-header__span">{span}</span> : null}
    </div>
  )
}
