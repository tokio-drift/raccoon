import type { JSX } from 'react'

import { MaskMark } from '../assets/brand'
import { Icon } from '../assets/icons'
import { Dropzone, type DropzoneState } from '../components/content/Dropzone'
import { captureLimitLabel } from '../lib/upload'

export interface EmptyDashboardProps {
  /** The maximum accepted upload size in bytes, when the server reports one. */
  maxBytes?: number | null
  /** The state of the dropzone (UI_Design.md §8.2). */
  state?: DropzoneState
  /** The name of the file that is being uploaded. */
  fileName?: string
  /** The bytes that were sent. */
  uploaded?: number
  /** The size of the file. */
  total?: number
  /** Why the upload failed. */
  reason?: string | null
  /** A one-time note under the dropzone. */
  note?: string | null
  /** The number of files that were ignored in a multi-file drop. */
  ignored?: number
  /** Called with every chosen file; the first one is the one that is used. */
  onFiles?: (files: File[]) => void
  /** Called when the upload is cancelled. */
  onCancel?: () => void
  /** Called when the user retries a failed upload. */
  onRetry?: () => void
  /** Called when the user wants to choose another file. */
  onChooseAnother?: () => void
  /** The sample case is only offered when the server has one. */
  sampleAvailable?: boolean
  onOpenSample?: () => void
}

/**
 * The empty dashboard (S0, UI_Design.md §8.1). The layout and the copy are
 * the ones from the design; the upload itself is driven by the upload hook.
 */
export function EmptyDashboard({
  maxBytes,
  state = 'idle',
  fileName,
  uploaded = 0,
  total = 0,
  reason,
  note,
  ignored = 0,
  onFiles,
  onCancel,
  onRetry,
  onChooseAnother,
  sampleAvailable = false,
  onOpenSample,
}: EmptyDashboardProps): JSX.Element {
  return (
    <section className="empty-dashboard" id="case-panel">
      <div className="empty-dashboard__brand">
        <MaskMark size={56} />
        <span className="wordmark wordmark--large">RACCOON</span>
      </div>

      <h1 className="empty-dashboard__tagline">Follow the trail.</h1>

      <p className="empty-dashboard__intro">
        RACCOON reads a network capture, rebuilds the conversations in it, pulls out the files that
        crossed the wire, and tells the story of what happened. Everything you can check, you can
        check against the raw bytes.
      </p>

      <Dropzone
        state={state}
        fileName={fileName}
        uploaded={uploaded}
        total={total}
        limitBytes={maxBytes ?? undefined}
        reason={reason ?? undefined}
        note={note ?? undefined}
        ignored={ignored}
        onFiles={onFiles}
        onCancel={onCancel}
        onRetry={onRetry}
        onChooseAnother={onChooseAnother}
      />

      <p className="empty-dashboard__formats">{captureLimitLabel(maxBytes)}</p>

      <p className="empty-dashboard__privacy">
        <Icon name="lock" size={16} /> Your capture stays on this computer. There is no account and
        nothing is uploaded to the internet. Only file hashes are sent for threat checks.
      </p>

      {sampleAvailable ? (
        <p className="empty-dashboard__sample">
          <button type="button" className="button button--tertiary" onClick={onOpenSample}>
            No capture handy? Open the sample case (ftp_upload_png.pcap)
          </button>
        </p>
      ) : null}

      <p className="empty-dashboard__footer">
        Reliable and Consistent Cybersecurity Operations Over Network
      </p>
    </section>
  )
}
