import type { JSX } from 'react'

export interface ProgressBarProps {
  /** The progress in percent; omit it for an indeterminate bar. */
  percent?: number
  /** The accessible value text, for example "62%". */
  valueText?: string
  /** The bar is striped while the connection is stalled. */
  stalled?: boolean
  /** The hairline variant of the header. */
  hairline?: boolean
  label?: string
}

/**
 * A progress bar (UI_Design.md §11). It always carries `role="progressbar"`
 * and a value text, so the state is never colour alone.
 */
export function ProgressBar({
  percent,
  valueText,
  stalled = false,
  hairline = false,
  label = 'Analysis progress',
}: ProgressBarProps): JSX.Element {
  const classes = ['progress-bar']
  if (hairline) classes.push('progress-bar--hairline')
  if (stalled) classes.push('progress-bar--stalled')
  if (percent === undefined) classes.push('progress-bar--indeterminate')

  return (
    <div
      className={classes.join(' ')}
      role="progressbar"
      aria-label={label}
      aria-valuenow={percent === undefined ? undefined : Math.round(percent)}
      aria-valuemin={percent === undefined ? undefined : 0}
      aria-valuemax={percent === undefined ? undefined : 100}
      aria-valuetext={valueText}
    >
      {percent === undefined ? null : (
        <div
          className="progress-bar__fill"
          style={{ width: `${Math.min(100, Math.max(0, percent))}%` }}
        />
      )}
    </div>
  )
}
