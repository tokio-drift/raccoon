import type { JSX } from 'react'

import { Icon, type IconName } from '../../assets/icons'

export interface ContextChipProps {
  /** The label of the chip, for example "Back to event 42". */
  label: string
  /** The icon shown in front of the label. */
  icon?: IconName
  /** Called when the chip is dismissed. */
  onDismiss?: () => void
  /** Called when the chip is followed. */
  onFollow?: () => void
}

/**
 * A context chip (UI_Design.md §11): it sits left of the view content and
 * points back to the event, file or stream the user came from.
 */
export function ContextChip({
  label,
  icon = 'chevron-left',
  onDismiss,
  onFollow,
}: ContextChipProps): JSX.Element {
  return (
    <span className="context-chip">
      {onFollow ? (
        <button type="button" className="context-chip__label" onClick={onFollow}>
          <Icon name={icon} size={16} />
          <span>{label}</span>
        </button>
      ) : (
        <span className="context-chip__label">
          <Icon name={icon} size={16} />
          <span>{label}</span>
        </span>
      )}
      {onDismiss ? (
        <button
          type="button"
          className="context-chip__dismiss"
          aria-label={`Dismiss ${label}`}
          onClick={onDismiss}
        >
          <Icon name="close" size={14} />
        </button>
      ) : null}
    </span>
  )
}
