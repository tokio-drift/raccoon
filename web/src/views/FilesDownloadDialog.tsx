import { useState, type JSX } from 'react'

import type { CarvedFile } from '../api/types'
import { Button } from '../components/primitives/Button'
import { Modal } from '../components/primitives/Overlay'
import { fileVerdict, neutralDownloadName } from '../lib/files'

/**
 * The confirmation dialog of a risky download (UI_Design.md §6.8). A file
 * marked malicious needs the box to be ticked; a suspicious file does not.
 * The focus is trapped, Escape cancels and the focus returns to the control
 * that opened the dialog.
 */

export interface FilesDownloadDialogProps {
  file: CarvedFile
  onCancel: () => void
  onConfirm: () => void
}

export function FilesDownloadDialog({
  file,
  onCancel,
  onConfirm,
}: FilesDownloadDialogProps): JSX.Element {
  const [understood, setUnderstood] = useState(false)
  const status = fileVerdict(file)
  const malicious = status === 'malicious'
  const savedAs = neutralDownloadName(file.sha256)
  const score = file.verdict?.score ?? 0
  const total = file.verdict?.total ?? 0

  const body = malicious
    ? `Threat intelligence marks this file as malicious (${score} of ${total} sources). RACCOON will save it as ${savedAs} and will never open or run it. Don't open it on a computer you care about. If you need to analyse it, use an isolated virtual machine.`
    : `Some sources flagged this file as suspicious (${score} of ${total}). RACCOON will save it as ${savedAs} and will never open or run it. Use an isolated virtual machine if you need to analyse it.`

  return (
    <Modal
      title={malicious ? 'Download a file marked malicious?' : 'Download a suspicious file?'}
      onClose={onCancel}
      risky
      className="dialog--download"
    >
      <p className="overlay__section">{body}</p>
      {malicious ? (
        <label className="dialog__check">
          <input
            type="checkbox"
            checked={understood}
            onChange={(event) => setUnderstood(event.target.checked)}
          />
          <span>I understand this file may be harmful.</span>
        </label>
      ) : null}
      <div className="overlay__actions">
        <Button variant="tertiary" data-overlay-cancel onClick={onCancel}>
          Cancel
        </Button>
        <Button
          variant="destructive"
          disabled={malicious && !understood}
          onClick={onConfirm}
        >
          Download anyway
        </Button>
      </div>
    </Modal>
  )
}
