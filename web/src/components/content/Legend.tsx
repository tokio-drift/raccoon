import type { JSX } from 'react'

export interface DirectionLegendProps {
  /** The bytes from the client to the server. */
  c2sLabel?: string
  /** The bytes from the server to the client. */
  s2cLabel?: string
}

/**
 * The direction legend (UI_Design.md §7.4, §11). The rail style and the words
 * carry the direction, not only the tint.
 */
export function DirectionLegend({
  c2sLabel = 'Client to server',
  s2cLabel = 'Server to client',
}: DirectionLegendProps): JSX.Element {
  return (
    <div className="legend legend--direction">
      <span className="legend__item">
        <span className="legend__swatch legend__swatch--c2s" aria-hidden="true" />
        <span>{c2sLabel}</span>
      </span>
      <span className="legend__item">
        <span className="legend__swatch legend__swatch--s2c" aria-hidden="true" />
        <span>{s2cLabel}</span>
      </span>
    </div>
  )
}

export interface SeverityLegendProps {
  counts: { info: number; warning: number; critical: number }
}

/**
 * The severity legend (UI_Design.md §11). The counts are the text version of
 * the chart, so the information never depends on colour alone.
 */
export function SeverityLegend({ counts }: SeverityLegendProps): JSX.Element {
  return (
    <ul className="legend legend--severity">
      <li className="legend__item">
        <span className="legend__swatch legend__swatch--info" aria-hidden="true" />
        <span>{`Info ${counts.info}`}</span>
      </li>
      <li className="legend__item">
        <span className="legend__swatch legend__swatch--warning" aria-hidden="true" />
        <span>{`Warning ${counts.warning}`}</span>
      </li>
      <li className="legend__item">
        <span className="legend__swatch legend__swatch--critical" aria-hidden="true" />
        <span>{`Critical ${counts.critical}`}</span>
      </li>
    </ul>
  )
}
