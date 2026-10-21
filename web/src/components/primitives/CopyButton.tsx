import { useEffect, useRef, useState, type JSX } from 'react'

import { Icon } from '../../assets/icons'

/** How long the tick stays visible after a copy, in milliseconds. */
export const COPY_FEEDBACK_MS = 1500

export interface CopyButtonProps {
  /** The exact value that is copied; truncation never changes it. */
  value: string
  /** The accessible name and the tooltip. */
  label?: string
  /** Shows the label next to the icon. */
  showLabel?: boolean
  /** Called after the value was copied. */
  onCopied?: () => void
}

/**
 * A copy button (UI_Design.md §11, §12.9). The icon becomes a tick for 1.5 s
 * and a polite live region announces "Copied".
 */
export function CopyButton({
  value,
  label = 'Copy',
  showLabel = false,
  onCopied,
}: CopyButtonProps): JSX.Element {
  const [copied, setCopied] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(() => {
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    }
  }, [])

  const copy = async () => {
    try {
      await navigator.clipboard?.writeText(value)
    } catch {
      // A browser without the clipboard API still confirms the attempt.
    }
    setCopied(true)
    onCopied?.()
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setCopied(false), COPY_FEEDBACK_MS)
  }

  return (
    <>
      <button
        type="button"
        className="copy-button"
        aria-label={label}
        title={label}
        onClick={() => void copy()}
      >
        <Icon name={copied ? 'check' : 'copy'} size={16} />
        {showLabel ? <span>{copied ? 'Copied' : label}</span> : null}
      </button>
      <span className="live-region" role="status" aria-live="polite">
        {copied ? 'Copied' : ''}
      </span>
    </>
  )
}
