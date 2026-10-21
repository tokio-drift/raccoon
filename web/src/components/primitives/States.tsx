import { useState, type JSX, type ReactNode } from 'react'

import { Icon } from '../../assets/icons'
import { Button } from './Button'
import { CopyButton } from './CopyButton'

export interface EmptyStateAction {
  label: string
  onClick: () => void
  variant?: 'primary' | 'secondary' | 'tertiary'
}

export interface EmptyStateProps {
  /** `no-data` shows the paw mark, `filtered` the magnifier. */
  kind?: 'no-data' | 'filtered' | 'no-selection'
  title: string
  body?: string
  actions?: EmptyStateAction[]
  /** The removable filter chips of a filtered-empty state. */
  children?: ReactNode
}

/**
 * An empty state (UI_Design.md §8.8). The case-has-none state shows the paw
 * mark, the filtered-empty state the magnifier and the active filters.
 */
export function EmptyState({
  kind = 'no-data',
  title,
  body,
  actions,
  children,
}: EmptyStateProps): JSX.Element {
  return (
    <div className={`empty-state empty-state--${kind}`}>
      {kind === 'no-data' ? (
        <span className="empty-state__mark" aria-hidden="true">
          <Icon name="group" size={96} />
        </span>
      ) : kind === 'filtered' ? (
        <span className="empty-state__mark empty-state__mark--inline" aria-hidden="true">
          <Icon name="search" size={40} />
        </span>
      ) : null}
      <h2 className="empty-state__title">{title}</h2>
      {body ? <p className="empty-state__body">{body}</p> : null}
      {children ? <div className="empty-state__filters">{children}</div> : null}
      {actions && actions.length > 0 ? (
        <div className="empty-state__actions">
          {actions.map((action) => (
            <Button
              key={action.label}
              variant={action.variant ?? 'secondary'}
              onClick={action.onClick}
            >
              {action.label}
            </Button>
          ))}
        </div>
      ) : null}
    </div>
  )
}

export interface ErrorStateProps {
  title: string
  /** The plain reason, in one or two sentences. */
  explanation: string
  actions?: EmptyStateAction[]
  /** The code shown in the technical details. */
  code?: string
  /** The original message, shown as text. */
  detail?: string
  /** The diagnostic text the copy button copies. */
  diagnostic?: string
  /** The full-page variant fills the window. */
  fullPage?: boolean
}

/**
 * An error state (UI_Design.md §12.6). Every error has a title, a plain
 * explanation, what the user can do and the technical details behind a
 * disclosure.
 */
export function ErrorState({
  title,
  explanation,
  actions,
  code,
  detail,
  diagnostic,
  fullPage = false,
}: ErrorStateProps): JSX.Element {
  const [open, setOpen] = useState(false)

  return (
    <div className={fullPage ? 'full-page' : 'error-state'} role="alert">
      <h2 className="empty-state__title">{title}</h2>
      <p className="empty-state__body">{explanation}</p>
      {actions && actions.length > 0 ? (
        <div className="empty-state__actions">
          {actions.map((action) => (
            <Button
              key={action.label}
              variant={action.variant ?? 'primary'}
              onClick={action.onClick}
            >
              {action.label}
            </Button>
          ))}
        </div>
      ) : null}
      {code || detail ? (
        <div className="error-state__details">
          <button
            type="button"
            className="button button--tertiary"
            aria-expanded={open}
            onClick={() => setOpen((state) => !state)}
          >
            {open ? 'Hide technical details' : 'Show technical details'}
          </button>
          {open ? (
            <div className="error-state__detail">
              {code ? (
                <p className="error-state__code">
                  <span className="error-state__code-label">Code</span>
                  <code>{code}</code>
                </p>
              ) : null}
              {detail ? (
                <p className="error-state__message">
                  <span className="error-state__code-label">Message</span>
                  <span>{detail}</span>
                </p>
              ) : null}
              {diagnostic ? (
                <CopyButton value={diagnostic} label="Copy diagnostic info" showLabel />
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
