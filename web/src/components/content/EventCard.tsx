import type { JSX, KeyboardEvent, ReactNode } from 'react'

import { Icon } from '../../assets/icons'
import { SeverityBadge, type Severity } from './Badges'

export interface EventCardProps {
  severity: Severity
  /** The elapsed time from the capture start, for example "+00:12.431". */
  elapsed: string
  /** The wall-clock time of day, for example "14:03:07.431". */
  wallClock: string
  /** The event type in plain words, for example "FTP login failed". */
  typeLabel: string
  /** The protocol tag, for example "FTP". */
  protocol?: string
  title: string
  /** The endpoints, for example "192.0.2.14:51822 → 192.0.2.50:21". */
  endpoints?: string
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
  elapsed,
  wallClock,
  typeLabel,
  protocol,
  title,
  endpoints,
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
    if (event.key === ' ' || event.key === 'Enter') {
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
      onKeyDown={onKeyDown}
      onClick={onOpen}
    >
      <span className={`event-card__rail event-card__rail--${severity}`} aria-hidden="true" />
      <div className="event-card__main">
        <div className="event-card__top">
          <SeverityBadge severity={severity} />
          <div className="event-card__time">
            <span className="event-card__elapsed">{elapsed}</span>
            <span className="event-card__wall">{wallClock}</span>
          </div>
          <span className="event-card__type">{typeLabel}</span>
          {protocol ? <span className="tag tag--plain">{protocol}</span> : null}
          {badges}
        </div>
        <p className="event-card__title">{title}</p>
        <div className="event-card__foot">
          {endpoints ? (
            <span className="event-card__endpoints" aria-label={endpointsLabel} title={endpoints}>
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
  count,
  subline,
  expanded = false,
  children,
  onToggle,
}: GroupCardProps): JSX.Element {
  return (
    <div className={expanded ? 'group-card group-card--expanded' : 'group-card'}>
      <article className={`event-card event-card--${severity}`} tabIndex={0}>
        <span className={`event-card__rail event-card__rail--${severity}`} aria-hidden="true" />
        <div className="event-card__main">
          <div className="event-card__top">
            <SeverityBadge severity={severity} />
            <Icon name="group" size={16} />
            <span className="group-card__count">{`×${count}`}</span>
          </div>
          <p className="event-card__title">{title}</p>
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
