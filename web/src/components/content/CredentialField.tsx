import { useEffect, useRef, useState, type JSX } from 'react'

import { Icon } from '../../assets/icons'
import { CopyButton } from '../primitives/CopyButton'

/** The password is masked again after this many seconds. */
export const REMASK_AFTER_MS = 30000

export interface CredentialFieldProps {
  /** The recorded password; null when it was not recorded. */
  value?: string | null
  /** True when a password was sent but not recorded. */
  presenceOnly?: boolean
  /** Changes with the selection, so a new event masks the password again. */
  selectionKey?: string | number
  /** Called after the password was copied. */
  onCopy?: () => void
}

/**
 * A credential field (UI_Design.md §12.7). The password is masked by default
 * with eight dots, whatever its real length, and is masked again after 30
 * seconds, when the selection changes or when the page loses visibility.
 */
export function CredentialField({
  value,
  presenceOnly = false,
  selectionKey,
  onCopy,
}: CredentialFieldProps): JSX.Element {
  const [revealed, setRevealed] = useState(false)
  const timer = useRef<number | null>(null)

  const mask = () => {
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = null
    setRevealed(false)
  }

  useEffect(() => {
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    }
  }, [])

  // A new selection masks the password again.
  useEffect(() => {
    mask()
  }, [selectionKey])

  // The page losing visibility masks the password again.
  useEffect(() => {
    const onVisibilityChange = () => {
      if (document.hidden) mask()
    }
    document.addEventListener('visibilitychange', onVisibilityChange)
    return () => document.removeEventListener('visibilitychange', onVisibilityChange)
  }, [])

  const reveal = () => {
    setRevealed((state) => {
      const next = !state
      if (next) {
        if (timer.current !== null) window.clearTimeout(timer.current)
        timer.current = window.setTimeout(mask, REMASK_AFTER_MS)
      } else {
        if (timer.current !== null) window.clearTimeout(timer.current)
        timer.current = null
      }
      return next
    })
  }

  if (presenceOnly) {
    return <span className="credential-field__value">A password was sent (not recorded)</span>
  }

  if (!value) {
    return <span className="credential-field__value">No password was seen.</span>
  }

  return (
    <span className="credential-field">
      <span className="credential-field__value">{revealed ? value : '••••••••'}</span>
      <button
        type="button"
        className="icon-button"
        aria-label={revealed ? 'Hide password' : 'Show password'}
        title={revealed ? 'Hide password' : 'Show password'}
        aria-pressed={revealed}
        onClick={reveal}
      >
        <Icon name={revealed ? 'eye-slash' : 'eye'} size={16} />
      </button>
      <CopyButton value={value} label="Copy password" onCopied={onCopy} />
    </span>
  )
}
