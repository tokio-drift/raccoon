import type { JSX } from 'react'

import type { CaseSummary } from '../api/types'
import { Icon } from '../assets/icons'
import { Button } from '../components/primitives/Button'
import { formatBytes, formatCount, formatDuration, formatElapsedShort, formatPercent } from '../lib/format'
import { STAGES, resolveStageIndex, type StageCounters } from '../lib/stages'
import { useNow } from '../hooks/useNow'
import { useStageDurations } from '../hooks/useStageDurations'

export interface ProcessingViewProps {
  caseSummary: CaseSummary | null
  /** The live counters, when the event stream is connected. */
  counters?: StageCounters
  /** The live percent, when the event stream is connected. */
  percent?: number
  /** The live packet count; the summary is used when it is unknown. */
  packets?: number
  /** The live byte count; the summary is used when it is unknown. */
  bytes?: number
  /** The connection is quiet; the progress has stopped. */
  stale?: boolean
  /** The time of the last update, in milliseconds since the epoch. */
  lastUpdateAt?: number | null
}

/**
 * The processing view (S1, UI_Design.md §8.3): the stage list on the left,
 * the current stage, the progress, the counters and the reassurance line.
 */
export function ProcessingView({
  caseSummary,
  counters,
  percent,
  packets,
  bytes,
  stale = false,
  lastUpdateAt = null,
}: ProcessingViewProps): JSX.Element {
  const now = useNow()

  const serverStage = caseSummary?.stage ?? 'init'
  const live: StageCounters = counters ?? {
    streams: caseSummary?.streams ?? 0,
    files: caseSummary?.files ?? 0,
    timelineReady: false,
  }
  const currentIndex = resolveStageIndex(serverStage, live)
  const current = STAGES[currentIndex]
  const durations = useStageDurations(currentIndex)

  const shownPercent = percent ?? caseSummary?.progress ?? 0
  const started = caseSummary ? Date.parse(caseSummary.startedAt.replace(/(\.\d{3})\d+/, '$1')) : NaN
  const elapsed = Number.isNaN(started) ? 0 : now - started

  // The stale progress shows the age of the last update (§8.7).
  const staleSeconds = stale && lastUpdateAt !== null ? Math.max(0, Math.round((now - lastUpdateAt) / 1000)) : 0

  return (
    <section className="processing" id="case-panel" aria-label="Analysis in progress">
      <ol className="stage-stepper processing__stages">
        {STAGES.map((stage, index) => {
          const state = index < currentIndex ? 'done' : index === currentIndex ? 'current' : 'upcoming'
          return (
            <li key={stage.id} className={`stage-stepper__item stage-stepper__item--${state}`}>
              <span className="stage-stepper__icon" aria-hidden="true">
                {state === 'done' ? (
                  <Icon name="flag" size={16} />
                ) : state === 'current' ? (
                  <span className="spinner" />
                ) : (
                  <span className="stage-stepper__hollow" />
                )}
              </span>
              <span className="stage-stepper__name">{stage.name}</span>
              {state === 'done' && durations[index] !== undefined ? (
                <span className="stage-stepper__time">{formatDuration(durations[index])}</span>
              ) : null}
            </li>
          )
        })}
      </ol>

      <div className="processing__main">
        <h1 className="processing__stage-name">{current.name}</h1>

        <div className="processing__progress">
          <div
            className={stale ? 'progress-bar progress-bar--stalled' : 'progress-bar'}
            role="progressbar"
            aria-valuenow={Math.round(shownPercent)}
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuetext={formatPercent(shownPercent)}
            aria-label="Analysis progress"
          >
            <div className="progress-bar__fill" style={{ width: `${Math.min(100, shownPercent)}%` }} />
          </div>
          <span className={stale ? 'processing__percent processing__percent--stale' : 'processing__percent'}>
            {formatPercent(shownPercent)}
          </span>
        </div>

        {stale ? (
          <p className="processing__stale">{`last update ${staleSeconds} s ago`}</p>
        ) : null}

        <p className="processing__elapsed">Elapsed {formatElapsedShort(elapsed)}</p>

        <div className={stale ? 'counters counters--stale' : 'counters'}>
          <div className="counter">
            <span className="counter__value">{formatCount(packets ?? caseSummary?.packets ?? 0)}</span>
            <span className="counter__label">Packets</span>
          </div>
          <div className="counter">
            <span className="counter__value">{formatBytes(bytes ?? caseSummary?.size ?? 0)}</span>
            <span className="counter__label">Data read</span>
          </div>
          <div className="counter">
            <span className="counter__value">{formatCount(live.streams)}</span>
            <span className="counter__label">Streams</span>
          </div>
          <div className="counter">
            <span className="counter__value">{formatCount(live.files)}</span>
            <span className="counter__label">Files found</span>
          </div>
        </div>

        <p className="processing__reassurance">{current.reassurance}</p>

        <div className="processing__actions">
          <Button
            variant="secondary"
            disabled
            title="RACCOON cannot stop a running analysis in this build."
          >
            Cancel analysis
          </Button>
        </div>
      </div>
    </section>
  )
}
