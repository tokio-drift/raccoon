import type { JSX, ReactNode } from 'react'

export interface KeyValueRowProps {
  label: string
  /** The value; it is rendered as inert text. */
  value?: ReactNode
  /** The value is a credential and stays masked. */
  masked?: boolean
  /** The value is not known. */
  unknown?: boolean
}

/**
 * A key/value row (UI_Design.md §11). The label column is 140 px, the value
 * wraps and is never truncated.
 */
export function KeyValueRow({
  label,
  value,
  masked = false,
  unknown = false,
}: KeyValueRowProps): JSX.Element {
  return (
    <div className="key-value-row">
      <span className="key-value-row__label">{label}</span>
      <span className={masked ? 'key-value-row__value key-value-row__value--masked' : 'key-value-row__value'}>
        {unknown ? 'Not recorded' : masked ? '••••••••' : value}
      </span>
    </div>
  )
}
