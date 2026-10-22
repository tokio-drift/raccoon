import type { JSX } from 'react'

import type { Confidence, Severity, VerdictStatus } from '../../api/types'
import { Icon } from '../../assets/icons'
import { formatClock, formatRelativeTime, parseTimestamp } from '../../lib/format'
import { Tooltip } from '../primitives/Tooltip'

export type { Confidence, Severity, VerdictStatus }

/** The exact severity labels and helper texts (UI_Design.md §5.4). */
export const SEVERITY_LABEL: Record<Severity, string> = {
  info: 'Info',
  warning: 'Warning',
  critical: 'Critical',
}

export const SEVERITY_HELP: Record<Severity, string> = {
  info: 'Normal or contextual activity. Included so the story makes sense.',
  warning: 'Suspicious activity, or something worth a closer look.',
  critical: 'Confirmed or strongly indicated danger.',
}

export interface SeverityBadgeProps {
  severity: Severity
  /** The dense time strip shows the icon only. */
  iconOnly?: boolean
}

/**
 * A severity badge (UI_Design.md §5.4, §11). Severity is never colour alone:
 * the shape of the icon and the label always carry it.
 */
export function SeverityBadge({ severity, iconOnly = false }: SeverityBadgeProps): JSX.Element {
  const label = SEVERITY_LABEL[severity]
  const icon = severity === 'critical' ? 'critical' : severity === 'warning' ? 'warning' : 'info'

  const badge = (
    <span className={`badge badge--${severity}`}>
      <Icon name={icon} size={iconOnly ? 12 : 16} />
      {iconOnly ? null : <span className="badge__label">{label}</span>}
    </span>
  )

  if (iconOnly) {
    return (
      <Tooltip text={SEVERITY_HELP[severity]} title={label}>
        {badge}
      </Tooltip>
    )
  }

  return <Tooltip text={SEVERITY_HELP[severity]}>{badge}</Tooltip>
}

export interface VerdictBadgeProps {
  status: VerdictStatus
  /** The number of sources that flagged the file. */
  score?: number
  /** The number of sources that were asked. */
  total?: number
  /** The source of the verdict, shown as the sub-line. */
  source?: string
  /** The time of the check, shown in the tooltip (§6.6). */
  checkedAt?: string
  /** The check is running. */
  pending?: boolean
  /** The badge pulses while the verdict is updated. */
  updating?: boolean
}

const VERDICT_LABEL: Record<VerdictStatus, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  no_detections: 'No detections',
  unknown: 'Unknown',
  not_checked: 'Not checked',
}

const VERDICT_ICON: Record<VerdictStatus, 'verdict-malicious' | 'verdict-suspicious' | 'verdict-no-detections' | 'verdict-unknown' | 'verdict-not-checked'> = {
  malicious: 'verdict-malicious',
  suspicious: 'verdict-suspicious',
  no_detections: 'verdict-no-detections',
  unknown: 'verdict-unknown',
  not_checked: 'verdict-not-checked',
}

const VERDICT_HELP: Record<VerdictStatus, string> = {
  malicious: 'Threat intelligence marks this file as malicious. Do not open it.',
  suspicious: 'Some sources flagged this file as suspicious. Treat it with caution.',
  no_detections:
    "No source flagged this file when it was checked. This is not a guarantee that the file is harmless.",
  unknown: "Threat intelligence has no record of this file. That says nothing about whether it is harmful.",
  not_checked: "This file hasn't been checked. Nothing is known about it.",
}

/**
 * A verdict badge (UI_Design.md §6.6, §11). The word "safe" never appears and
 * a "No detections" badge is never green.
 */
export function VerdictBadge({
  status,
  score,
  total,
  source,
  checkedAt,
  pending = false,
  updating = false,
}: VerdictBadgeProps): JSX.Element {
  const label = VERDICT_LABEL[status]
  const parts = [VERDICT_HELP[status]]
  if (status === 'malicious' && score !== undefined && total !== undefined) {
    parts[0] = `Threat intelligence marks this file as malicious. ${score} of ${total} sources flagged it. Do not open it.`
  }
  const checked = checkedAt ? parseTimestamp(checkedAt) : 0
  const sourceLine = source
    ? `Source: ${source}${checked ? ` · Checked ${formatClock(checked, { basis: 'utc', seconds: true })} UTC (${formatRelativeTime(checked)})` : ''}`
    : null
  const tooltip = [
    parts[0],
    sourceLine,
    "Only the file's hash is sent for checking. The file itself is never uploaded.",
  ]
    .filter(Boolean)
    .join(' ')

  const classes = ['badge', `badge--verdict-${status}`]
  if (updating) classes.push('badge--updating')
  if (pending) classes.push('badge--pending')

  return (
    <Tooltip text={tooltip} title={label}>
      <span className={classes.join(' ')}>
        <Icon name={VERDICT_ICON[status]} size={16} />
        <span className="badge__label">{label}</span>
        {score !== undefined && total !== undefined ? (
          <span className="badge__score">{`${score} / ${total}`}</span>
        ) : null}
        {pending ? <span className="badge__sub">Checking…</span> : null}
        {source && !pending ? <span className="badge__sub">{source}</span> : null}
      </span>
    </Tooltip>
  )
}

export interface ConfidenceTagProps {
  confidence: Confidence
}

/**
 * A confidence tag (UI_Design.md §6.3). High and medium are plain text, low
 * is an outlined tag with a dotted gauge icon.
 */
export function ConfidenceTag({ confidence }: ConfidenceTagProps): JSX.Element {
  if (confidence === 'low') {
    return (
      <span className="tag tag--low">
        <Icon name="info" size={14} />
        <span>Low</span>
      </span>
    )
  }
  return <span className="tag tag--plain">{confidence === 'high' ? 'High' : 'Medium'}</span>
}
