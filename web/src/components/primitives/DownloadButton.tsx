import type { JSX } from 'react'

import { Icon } from '../../assets/icons'
import { Button, type ButtonVariant } from './Button'

export interface DownloadButtonProps {
  /** The file name shown in the tooltip; the saved name stays neutral. */
  fileName: string
  onDownload: () => void
  /** The button shows a spinner while the download runs. */
  busy?: boolean
  /** The label of the button while the download runs. */
  busyLabel?: string
  /** The button is disabled when the file is not available. */
  disabled?: boolean
  /** The reason a disabled button cannot be used. */
  disabledReason?: string
  /** The row variant is an icon button, the detail variant a labelled button. */
  variant?: 'row' | 'detail'
  buttonVariant?: ButtonVariant
}

/**
 * A download button (UI_Design.md §6.8, §11). RACCOON never opens or runs a
 * file; it only saves it under a neutral name.
 */
export function DownloadButton({
  fileName,
  onDownload,
  busy = false,
  busyLabel = 'Preparing…',
  disabled = false,
  disabledReason,
  variant = 'detail',
  buttonVariant = 'secondary',
}: DownloadButtonProps): JSX.Element {
  const title = disabled
    ? (disabledReason ?? 'This file is not available any more.')
    : `Download file ${fileName}. RACCOON will never open or run it.`

  if (variant === 'row') {
    return (
      <button
        type="button"
        className="icon-button"
        aria-label={title}
        title={title}
        disabled={disabled || busy}
        aria-busy={busy || undefined}
        onClick={onDownload}
      >
        {busy ? <span className="spinner" aria-hidden="true" /> : <Icon name="download" size={20} />}
      </button>
    )
  }

  return (
    <Button
      variant={buttonVariant}
      icon="download"
      busy={busy}
      disabled={disabled}
      title={title}
      onClick={onDownload}
    >
      {busy ? busyLabel : 'Download file'}
    </Button>
  )
}
