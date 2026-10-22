import type { JSX } from 'react'

import { Icon } from '../../assets/icons'
import { formatZoneLabel } from '../../lib/format'
import type { TimeBasis } from '../../lib/preferences'

export interface StatusBarProps {
  timeBasis: TimeBasis
  onToggleTimeBasis: () => void
  /** A "Data as of …" chip while the connection is stale. */
  dataAsOf?: string
  onHelp: () => void
}

/** The status bar (UI_Design.md §8.13). */
export function StatusBar({
  timeBasis,
  onToggleTimeBasis,
  dataAsOf,
  onHelp,
}: StatusBarProps): JSX.Element {
  const label = `Times: ${formatZoneLabel(timeBasis)} · from capture clock`
  return (
    <footer className="status-bar" role="contentinfo">
      <div className="status-bar__group">
        <button
          type="button"
          className="status-bar__button"
          onClick={onToggleTimeBasis}
          title="Click toggles UTC / local"
        >
          {label}
        </button>
      </div>
      <div className="status-bar__group">
        {dataAsOf ? <span className="pill">{dataAsOf}</span> : null}
      </div>
      <div className="status-bar__group">
        <span className="status-bar__privacy">
          <span className="status-bar__privacy-long">
            Local only · only file hashes are sent for threat checks
          </span>
          <span className="status-bar__privacy-short">Local only</span>
        </span>
        <button type="button" className="status-bar__button" onClick={onHelp}>
          Help
        </button>
        <span aria-hidden="true">?</span>
      </div>
    </footer>
  )
}

export interface ProgressHairlineProps {
  percent: number
  /** The hairline is striped while the connection is stale. */
  stale?: boolean
}

/** The 3 px progress hairline under the header (UI_Design.md §4.1). */
export function ProgressHairline({ percent, stale = false }: ProgressHairlineProps): JSX.Element {
  return (
    <div
      className={stale ? 'progress-hairline progress-hairline--stale' : 'progress-hairline'}
      role="progressbar"
      aria-valuenow={Math.round(percent)}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-label="Analysis progress"
    >
      <div className="progress-hairline__fill" style={{ width: `${Math.min(100, Math.max(0, percent))}%` }} />
    </div>
  )
}

export interface BannerProps {
  tone: 'info' | 'warning' | 'error'
  children: JSX.Element | string
  onDismiss?: () => void
  actions?: JSX.Element | null
}

/** A banner under the case strip (UI_Design.md §8.10). */
export function Banner({ tone, children, onDismiss, actions }: BannerProps): JSX.Element {
  const icon = tone === 'error' ? 'critical' : tone === 'warning' ? 'warning' : 'info'
  return (
    <div className={`banner banner--${tone}`} role={tone === 'error' ? 'alert' : undefined}>
      <Icon name={icon} size={20} />
      <span className="banner__text">{children}</span>
      {actions ? <span className="banner__actions">{actions}</span> : null}
      {onDismiss ? (
        <button type="button" className="icon-button" aria-label="Dismiss" onClick={onDismiss}>
          <Icon name="close" size={16} />
        </button>
      ) : null}
    </div>
  )
}

export interface IncidentStripProps {
  children: JSX.Element | string
  onView?: () => void
  onDismiss?: () => void
  /** The number of further escalations, shown as "+{n} more". */
  more?: number
}

/** The critical escalation strip (UI_Design.md §8.10). */
export function IncidentStrip({
  children,
  onView,
  onDismiss,
  more = 0,
}: IncidentStripProps): JSX.Element {
  return (
    <div className="incident-strip" role="alert">
      <Icon name="critical" size={20} />
      <span>{children}</span>
      {more > 0 ? <span className="pill">+{more} more</span> : null}
      {onView ? (
        <button type="button" className="button button--tertiary" onClick={onView}>
          View
        </button>
      ) : null}
      {onDismiss ? (
        <button type="button" className="icon-button" aria-label="Dismiss" onClick={onDismiss}>
          <Icon name="close" size={16} />
        </button>
      ) : null}
    </div>
  )
}
