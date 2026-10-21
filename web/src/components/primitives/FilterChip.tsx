import type { JSX, ReactNode } from 'react'

import { Icon } from '../../assets/icons'

export interface FilterChipProps {
  label: string
  /** The chip can be removed when a remove handler is given. */
  onRemove?: () => void
  children?: ReactNode
}

/** A filter chip (UI_Design.md §11). It is the only element with a pill radius. */
export function FilterChip({ label, onRemove, children }: FilterChipProps): JSX.Element {
  return (
    <span className="filter-chip">
      {children}
      <span className="filter-chip__label">{label}</span>
      {onRemove ? (
        <button
          type="button"
          className="filter-chip__remove"
          aria-label={`Remove filter ${label}`}
          onClick={onRemove}
        >
          <Icon name="close" size={14} />
        </button>
      ) : null}
    </span>
  )
}
