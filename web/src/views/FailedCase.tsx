import { useState, type JSX } from 'react'

import type { CaseSummary } from '../api/types'
import { Icon } from '../assets/icons'
import { Button } from '../components/primitives/Button'
import { formatBytes, formatCount, formatPercent } from '../lib/format'

export interface FailedCaseProps {
  /** The summary of the case that failed. */
  caseSummary: CaseSummary | null
  /** The stage the analysis stopped at. */
  stage?: string
  /** The progress the analysis reached, in percent. */
  progress?: number
  /** The error code of the server, when it reported one. */
  errorCode?: string | null
  /** The error message of the server, as plain text. */
  errorMessage?: string | null
  /** The browser still holds the capture, so the analysis can be run again. */
  canRetry?: boolean
  /** The reader runs the same capture again. */
  onRetry?: () => void
  /** The reader chooses another capture. */
  onChooseAnother: () => void
  /** The reader copies the diagnostic text. */
  onCopyDiagnostics: () => void
}

/**
 * The failure view of a case that has no usable data (UI_Design.md §8.5, S5).
 * The tabs are hidden, the header keeps the case name and the Failed pill, and
 * the technical details are plain text the reader can copy.
 */
export function FailedCase({
  caseSummary,
  stage,
  progress,
  errorCode,
  errorMessage,
  canRetry = false,
  onRetry,
  onChooseAnother,
  onCopyDiagnostics,
}: FailedCaseProps): JSX.Element {
  const [detailsOpen, setDetailsOpen] = useState(false)

  const rows: [string, string | null][] = [
    ['Error code', errorCode ?? null],
    ['Error message', errorMessage ?? null],
    ['Stage', stage ?? caseSummary?.stage ?? null],
    [
      'Progress',
      typeof progress === 'number' ? formatPercent(progress) : caseSummary ? formatPercent(caseSummary.progress) : null,
    ],
    ['Capture', caseSummary?.fileName ?? null],
    ['Size', caseSummary ? formatBytes(caseSummary.size) : null],
    ['SHA-256', caseSummary?.pcapSha256 ?? null],
    ['Tool version', caseSummary?.toolVersion ?? null],
  ]
  const shown = rows.filter((row): row is [string, string] => row[1] !== null && row[1] !== '')

  return (
    <div className="failed-case">
      <Icon name="critical" size={48} />
      <h1 className="failed-case__title">Analysis failed</h1>
      <p className="failed-case__body">
        RACCOON could not finish this capture. Nothing is lost: the capture stays on this computer
        and you can run it again or choose another one.
      </p>

      <div className="failed-case__actions">
        <Button variant="primary" onClick={onChooseAnother}>
          Choose another capture
        </Button>
        {canRetry && onRetry ? (
          <Button variant="secondary" onClick={onRetry}>
            Try again
          </Button>
        ) : null}
        <Button variant="secondary" onClick={onCopyDiagnostics}>
          Copy diagnostic info
        </Button>
      </div>

      <div className="failed-case__details">
        <button
          type="button"
          className="failed-case__details-toggle"
          aria-expanded={detailsOpen}
          onClick={() => setDetailsOpen((open) => !open)}
        >
          <Icon name={detailsOpen ? 'chevron-down' : 'chevron-right'} size={16} />
          <span>Technical details</span>
        </button>
        {detailsOpen ? (
          <dl className="failed-case__detail-list">
            {shown.map(([label, value]) => (
              <div key={label} className="failed-case__detail">
                <dt>{label}</dt>
                <dd>{value}</dd>
              </div>
            ))}
            {shown.length === 0 ? (
              <div className="failed-case__detail">
                <dt>Details</dt>
                <dd>The server did not report any detail.</dd>
              </div>
            ) : null}
          </dl>
        ) : null}
      </div>

      {caseSummary ? (
        <p className="failed-case__note">
          {`${caseSummary.fileName} · ${formatBytes(caseSummary.size)} · ${formatCount(
            caseSummary.packets,
          )} packets in the capture.`}
        </p>
      ) : null}
    </div>
  )
}
