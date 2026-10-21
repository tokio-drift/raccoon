import type { JSX } from 'react'

import type { Severity, VerdictStatus } from '../api/types'
import { Icon } from '../assets/icons'
import { SEVERITY_LABEL } from '../components/content/Badges'
import { Button } from '../components/primitives/Button'
import { formatCount, formatElapsedRange } from '../lib/format'

/**
 * The case brief band (UI_Design.md §5.19). It shows the counts of the case,
 * never a generated verdict sentence, and it can be collapsed to one line.
 */

const VERDICT_LABEL: Record<VerdictStatus, string> = {
  malicious: 'Malicious',
  suspicious: 'Suspicious',
  no_detections: 'No detections',
  unknown: 'Unknown',
  not_checked: 'Not checked',
}

const VERDICT_ORDER: VerdictStatus[] = [
  'malicious',
  'suspicious',
  'no_detections',
  'unknown',
  'not_checked',
]

export interface CaseBriefBandProps {
  counts: Record<Severity, number>
  verdictCounts: Record<VerdictStatus, number>
  /** The number of finding events; the chip is hidden without findings. */
  findingCount: number
  /** The length of the capture in milliseconds. */
  duration: number
  /** The start of the capture in milliseconds since the epoch. */
  captureStart: number
  /** The band is collapsed to one line. */
  collapsed: boolean
  onToggleCollapsed: () => void
  /** The first critical event is selected and scrolled to. */
  onGoToFirstCritical: () => void
  /** True when the case has a critical event. */
  hasCritical: boolean
  /** The findings filter is on. */
  findingsOnly: boolean
  onToggleFindings: () => void
}

export function CaseBriefBand({
  counts,
  verdictCounts,
  findingCount,
  duration,
  captureStart,
  collapsed,
  onToggleCollapsed,
  onGoToFirstCritical,
  hasCritical,
  findingsOnly,
  onToggleFindings,
}: CaseBriefBandProps): JSX.Element {
  const total = counts.info + counts.warning + counts.critical
  const parts = ([
    ['critical', counts.critical],
    ['warning', counts.warning],
    ['info', counts.info],
  ] as [Severity, number][]).filter(([, count]) => count > 0)

  return (
    <section className={collapsed ? 'case-brief case-brief--collapsed' : 'case-brief'}>
      <div className="case-brief__row">
        <div
          className="case-brief__bar"
          role="img"
          aria-label={`${counts.critical} critical, ${counts.warning} warning and ${counts.info} info events`}
        >
          {parts.map(([severity, count]) => (
            <span
              key={severity}
              className={`case-brief__segment case-brief__segment--${severity}`}
              style={{ flexGrow: count }}
            />
          ))}
        </div>

        <p className="case-brief__counts">
          {parts.map(([severity, count]) => (
            <span key={severity} className="case-brief__count">
              {`${formatCount(count)} ${SEVERITY_LABEL[severity]}`}
            </span>
          ))}
          {total === 0 ? <span className="case-brief__count">No events</span> : null}
        </p>

        <p className="case-brief__span">{formatElapsedRange(captureStart, captureStart + duration)}</p>

        <div className="case-brief__actions">
          {findingCount > 0 ? (
            <button
              type="button"
              className={
                findingsOnly ? 'case-brief__chip case-brief__chip--on' : 'case-brief__chip'
              }
              aria-pressed={findingsOnly}
              onClick={onToggleFindings}
            >
              {`${formatCount(findingCount)} ${findingCount === 1 ? 'finding' : 'findings'}`}
            </button>
          ) : null}

          {VERDICT_ORDER.filter((status) => verdictCounts[status] > 0).map((status) => (
            <span key={status} className="case-brief__chip case-brief__chip--plain">
              {`${formatCount(verdictCounts[status])} ${VERDICT_LABEL[status]}`}
            </span>
          ))}

          {hasCritical ? (
            <Button variant="secondary" onClick={onGoToFirstCritical}>
              Go to first critical event
            </Button>
          ) : null}

          <button
            type="button"
            className="icon-button"
            aria-label={collapsed ? 'Expand the case brief' : 'Collapse the case brief'}
            aria-expanded={!collapsed}
            onClick={onToggleCollapsed}
          >
            <Icon name={collapsed ? 'chevron-down' : 'chevron-up'} size={16} />
          </button>
        </div>
      </div>
    </section>
  )
}
