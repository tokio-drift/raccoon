import { useRef, useState, type ChangeEvent, type DragEvent, type JSX } from 'react'

import { Icon } from '../../assets/icons'
import { PawMark } from '../../assets/brand'
import { formatBytes, formatBytesExact } from '../../lib/format'
import { prefersReducedMotion } from '../../lib/motion'
import { UPLOAD_LIMIT_BYTES } from '../../lib/upload'
import { Button } from '../primitives/Button'
import { ProgressBar } from '../primitives/ProgressBar'

export type DropzoneState =
  | 'idle'
  | 'dragging'
  | 'invalid'
  | 'too-large'
  | 'uploading'
  | 'failed'

/** The upload limit of the server, in bytes (`limits.UploadMaxBytes`). */
export const DEFAULT_LIMIT_BYTES = UPLOAD_LIMIT_BYTES

export interface DropzoneProps {
  /** The state of the dropzone. */
  state?: DropzoneState
  /** The name of the file that is being uploaded. */
  fileName?: string
  /** The bytes that were sent. */
  uploaded?: number
  /** The total size of the file. */
  total?: number
  /** The size limit of the server. */
  limitBytes?: number
  /** The reason the upload failed. */
  reason?: string
  /** A note under the dropzone, for example "Upload cancelled. Nothing was kept." */
  note?: string
  /** The number of files that were ignored in a multi-file drop. */
  ignored?: number
  /** Called with the chosen file. */
  onFile?: (file: File) => void
  /** Called with every file of a drop; the first one is the one that is used. */
  onFiles?: (files: File[]) => void
  /** Called when the upload is cancelled. */
  onCancel?: () => void
  /** Called when the user retries a failed upload. */
  onRetry?: () => void
  /** Called when the user wants to choose another file. */
  onChooseAnother?: () => void
}

/**
 * The dropzone (UI_Design.md §8.2, §11). It has one state at a time, the
 * copy is the one from the design, and the file name is inert text.
 */
export function Dropzone({
  state = 'idle',
  fileName,
  uploaded = 0,
  total = 0,
  limitBytes,
  reason,
  note,
  ignored = 0,
  onFile,
  onFiles,
  onCancel,
  onRetry,
  onChooseAnother,
}: DropzoneProps): JSX.Element {
  const input = useRef<HTMLInputElement | null>(null)
  const [dragging, setDragging] = useState(false)

  const pick = () => input.current?.click()

  const handleInput = (event: ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files ? Array.from(event.target.files) : []
    if (files.length > 0) {
      if (onFiles) onFiles(files)
      else onFile?.(files[0])
    }
    event.target.value = ''
  }

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault()
    setDragging(false)
    const files = event.dataTransfer.files ? Array.from(event.dataTransfer.files) : []
    if (files.length > 0) {
      if (onFiles) onFiles(files)
      else onFile?.(files[0])
    }
  }

  const over = state === 'dragging' || dragging
  const classes = ['dropzone']
  if (over) classes.push('dropzone--over')
  // The icon bounces once on a valid drag, but not under reduced motion.
  if (over && !prefersReducedMotion()) classes.push('dropzone--bounce')
  if (state === 'invalid') classes.push('dropzone--invalid')
  if (state === 'too-large') classes.push('dropzone--too-large')

  if (state === 'uploading') {
    const percent = total > 0 ? Math.round((uploaded / total) * 100) : 0
    const isDoneUploading = total > 0 && uploaded >= total
    return (
      <div className="dropzone dropzone--uploading">
        <div className="dropzone__progress-card">
          <p className="dropzone__progress-title">
            {isDoneUploading ? `Processing ${fileName ?? ''}…` : `Uploading ${fileName ?? ''}…`}
          </p>
          <p className="dropzone__progress-name">{fileName}</p>
          <ProgressBar percent={percent} label="Upload progress" />
          <p className="dropzone__progress-count">
            {`${formatBytes(uploaded)} of ${formatBytes(total)} (${percent}%)`}
          </p>
          <Button variant="secondary" onClick={onCancel}>
            Cancel upload
          </Button>
        </div>
      </div>
    )
  }

  if (state === 'failed') {
    return (
      <div className="dropzone dropzone--failed">
        <div className="dropzone__error-card">
          <span className="dropzone__icon" aria-hidden="true">
            <Icon name="critical" size={32} />
          </span>
          <p className="dropzone__error-title">The upload didn't finish.</p>
          {reason ? <p className="dropzone__error-reason">{reason}</p> : null}
          <div className="dropzone__actions">
            <Button variant="primary" onClick={onRetry}>
              Try again
            </Button>
            <Button variant="secondary" onClick={onChooseAnother}>
              Choose another file
            </Button>
          </div>
        </div>
      </div>
    )
  }

  const title =
    over
      ? 'Release to analyse this capture'
      : state === 'invalid'
        ? "That doesn't look like a capture file. RACCOON reads .pcap and .pcapng files."
        : state === 'too-large'
          ? `This file is ${total > 0 ? formatBytes(total) : 'too large'}. The limit is ${formatBytes(limitBytes ?? DEFAULT_LIMIT_BYTES)}. Try a smaller capture, or trim it first.`
          : 'Drop a capture file here'

  return (
    <div
      className={classes.join(' ')}
      onDragOver={(event) => {
        event.preventDefault()
        setDragging(true)
      }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
    >
      <span className="dropzone__icon" aria-hidden="true">
        {state === 'invalid' ? (
          <Icon name="critical" size={32} />
        ) : state === 'too-large' ? (
          <Icon name="warning" size={32} />
        ) : (
          <PawMark size={48} />
        )}
      </span>
      <p
        className="dropzone__title"
        title={state === 'too-large' && total > 0 ? formatBytesExact(total) : undefined}
      >
        {title}
      </p>
      <p className="dropzone__or">or</p>
      <Button variant="primary" onClick={pick}>
        Choose a file…
      </Button>
      <p className="dropzone__note">One capture at a time.</p>
      {ignored > 0 && fileName ? (
        <p className="dropzone__note">
          {`RACCOON opens one capture at a time. Using ${fileName}; the other ${ignored} file${ignored === 1 ? ' was' : 's were'} ignored.`}
        </p>
      ) : null}
      {note ? <p className="dropzone__note">{note}</p> : null}
      <input
        ref={input}
        type="file"
        className="visually-hidden"
        accept=".pcap,.pcapng,application/vnd.tcpdump.pcap"
        aria-label="Choose a capture file"
        onChange={handleInput}
      />
    </div>
  )
}
