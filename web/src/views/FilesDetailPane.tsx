import { useState, type JSX } from 'react'

import type { CarvedFile, StreamSummary } from '../api/types'
import { Icon } from '../assets/icons'
import { ConfidenceTag, VerdictBadge } from '../components/content/Badges'
import { DetailSection } from '../components/content/DetailSection'
import { KeyValueRow } from '../components/content/KeyValueRow'
import { Button } from '../components/primitives/Button'
import { CopyButton } from '../components/primitives/CopyButton'
import { DownloadButton } from '../components/primitives/DownloadButton'
import { formatBytes, formatBytesExact, formatClock, formatCount, parseTimestamp } from '../lib/format'
import {
  controlCharacterTokens,
  directionLabel,
  escapeUnicode,
  EXTRACTION_LABEL,
  fileEndpointPair,
  fileVerdict,
  formatLabel,
  hasNonAscii,
  isPathLikeName,
  magicBytesText,
  nameExtension,
  nameMismatch,
  neutralDownloadName,
  unnamedFileLabel,
} from '../lib/files'

/**
 * The detail pane of a file (UI_Design.md §6.7). It shows what is known
 * about a file; it never opens or previews it.
 */

export interface FilesDetailPaneProps {
  file: CarvedFile
  /** The stream the file was carved from. */
  stream?: StreamSummary | null
  /** The event the file was carved in, when there is one. */
  hasSourceEvent?: boolean
  onClose: () => void
  onShowInStream: () => void
  onShowSourceEvent?: () => void
  /** The download is running. */
  busy?: boolean
  /** The download failed; the reason is shown in the pane. */
  error?: string | null
  /** The file is no longer on the computer. */
  missing?: boolean
  onDownload: () => void
  /** Copies the diagnostic text of a failed download. */
  onCopyDiagnostics?: () => void
}

export function FilesDetailPane({
  file,
  stream,
  hasSourceEvent = false,
  onClose,
  onShowInStream,
  onShowSourceEvent,
  busy = false,
  error = null,
  missing = false,
  onDownload,
  onCopyDiagnostics,
}: FilesDetailPaneProps): JSX.Element {
  const [escaped, setEscaped] = useState(false)
  const name = file.displayName?.trim() ? file.displayName : ''
  const tokens = controlCharacterTokens(name)
  const unicode = hasNonAscii(name)
  const pathLike = isPathLikeName(name)
  const mismatch = nameMismatch(name, file.ext)
  const shownName = escaped ? escapeUnicode(name) : name
  const endpointPair = fileEndpointPair(file, stream)
  const savedAs = neutralDownloadName(file.sha256)
  const status = fileVerdict(file)
  const verdict = file.verdict
  const format = formatLabel(file.format, file.ext)
  const checked = verdict?.checkedAt ? parseTimestamp(verdict.checkedAt) : 0

  return (
    <aside className="files-detail" aria-label="File details">
      <header className="files-detail__header">
        <h2 className="files-detail__title">{shownName || unnamedFileLabel(file)}</h2>
        <div className="files-detail__header-tags">
          {pathLike ? (
            <span
              className="tag tag--warning"
              title="The sender supplied a name containing path characters. RACCOON displays it as text and never uses it as a file path."
            >
              Path-like name
            </span>
          ) : null}
          {tokens.length > 0 ? (
            <span
              className="tag tag--warning"
              title="The name holds control or bidirectional characters. They are shown as visible tokens."
            >
              Unusual characters
            </span>
          ) : null}
          {unicode ? <span className="tag tag--plain">Unicode</span> : null}
          {mismatch ? (
            <span
              className="tag tag--warning"
              title={`The name says .${nameExtension(name)} but the content looks like a ${file.format} file.`}
            >
              Name doesn&apos;t match content
            </span>
          ) : null}
        </div>
        <div className="files-detail__header-row">
          <span className="tag tag--plain">{format}</span>
          <VerdictBadge
            status={status}
            score={verdict?.score}
            total={verdict?.total}
            source={verdict?.source}
            checkedAt={verdict?.checkedAt}
          />
          <span className="tag tag--plain">{EXTRACTION_LABEL[file.status]}</span>
          <ConfidenceTag confidence={file.confidence} />
        </div>
        <div className="files-detail__header-actions">
          {unicode ? (
            <button
              type="button"
              className="button button--tertiary"
              aria-pressed={escaped}
              onClick={() => setEscaped((value) => !value)}
            >
              {escaped ? 'Show the name' : 'Show escaped'}
            </button>
          ) : null}
          <CopyButton value={name} label="Copy file name" showLabel />
          <button type="button" className="icon-button" aria-label="Close file details" onClick={onClose}>
            <Icon name="close" size={18} />
          </button>
        </div>
      </header>

      <p className="files-detail__safety">
        RACCOON never opens or previews extracted files. This page shows information about the file, not
        the file itself.
      </p>

      <DetailSection title="Verdict" sectionKey="file-verdict">
        <KeyValueRow
          label="Status"
          value={
            <VerdictBadge
              status={status}
              score={verdict?.score}
              total={verdict?.total}
              source={verdict?.source}
              checkedAt={verdict?.checkedAt}
            />
          }
        />
        <KeyValueRow label="Source" value={verdict?.source ?? 'Not recorded'} unknown={!verdict?.source} />
        <KeyValueRow
          label="Sources"
          value={
            verdict && verdict.total > 0
              ? `${verdict.score} of ${verdict.total} flagged it`
              : 'Not recorded'
          }
          unknown={!verdict || verdict.total === 0}
        />
        <KeyValueRow
          label="Checked"
          value={checked ? `${formatClock(checked, { basis: 'utc', seconds: true })} UTC` : 'Not recorded'}
          unknown={!checked}
        />
        <p className="files-detail__note">
          Only the file&apos;s hash is sent for checking. The file itself is never uploaded.
        </p>
      </DetailSection>

      <DetailSection title="Where it came from" sectionKey="file-source">
        <div className="files-detail__direction">
          <span
            className={
              file.dir === 's2c' ? 'direction-chip direction-chip--s2c' : 'direction-chip direction-chip--c2s'
            }
          >
            <Icon name={file.dir === 's2c' ? 'direction-left' : 'direction-right'} size={14} />
            <span>{directionLabel(file.dir)}</span>
          </span>
        </div>
        <KeyValueRow
          label="Endpoints"
          value={
            endpointPair ? (
              <span className="files-detail__endpoints">
                <span className="files-detail__endpoint">
                  <code>{endpointPair.from}</code>
                  <CopyButton value={endpointPair.from} label="Copy source endpoint" />
                </span>
                <span className="files-detail__endpoint">
                  <code>{endpointPair.to}</code>
                  <CopyButton value={endpointPair.to} label="Copy destination endpoint" />
                </span>
              </span>
            ) : (
              'Not recorded'
            )
          }
          unknown={!endpointPair}
        />
        <KeyValueRow
          label="Stream"
          value={
            <Button variant="tertiary" onClick={onShowInStream}>
              {`Stream ${file.streamId}`}
            </Button>
          }
        />
        <KeyValueRow
          label="Offsets"
          value={`Bytes ${formatCount(file.startOff)}–${formatCount(file.endOff)} (${formatBytes(
            file.endOff - file.startOff,
          )}) of the ${file.dir === 'c2s' ? 'server' : 'client'} data`}
        />
        <div className="files-detail__actions">
          <Button variant="secondary" icon="streams" onClick={onShowInStream}>
            Show in stream
          </Button>
          {hasSourceEvent && onShowSourceEvent ? (
            <Button variant="secondary" icon="storyboard" onClick={onShowSourceEvent}>
              Source event
            </Button>
          ) : null}
        </div>
      </DetailSection>

      <DetailSection title="Hashes" sectionKey="file-hashes">
        <div className="files-detail__hash">
          <span className="files-detail__hash-label">SHA-256</span>
          <code className="files-detail__hash-value">{file.sha256.slice(0, 32)}</code>
          <code className="files-detail__hash-value">{file.sha256.slice(32)}</code>
          <CopyButton value={file.sha256} label="Copy SHA-256" />
        </div>
        <div className="files-detail__hash">
          <span className="files-detail__hash-label">MD5</span>
          <code className="files-detail__hash-value">{file.md5}</code>
          <CopyButton value={file.md5} label="Copy MD5" />
        </div>
        <p className="files-detail__note">
          MD5 is shown for compatibility. Prefer SHA-256.
        </p>
      </DetailSection>

      <DetailSection title="Identification" sectionKey="file-identification">
        <KeyValueRow
          label="Magic bytes"
          value={magicBytesText(file.magicHex) || 'Not recorded'}
          unknown={!file.magicHex}
        />
        <p className="files-detail__note">
          {file.magicHex
            ? `Starts with the bytes that identify ${file.format}.`
            : 'The first bytes of the file are not known.'}
        </p>
        <KeyValueRow label="Format" value={file.format || 'Not recorded'} unknown={!file.format} />
        <KeyValueRow
          label="Extension"
          value={file.ext ? `.${file.ext}` : 'Not recorded'}
          unknown={!file.ext}
        />
        <KeyValueRow
          label="Confidence"
          value={
            file.confidence === 'low'
              ? 'Low — the file matched only a short signature, so it may not be a real file.'
              : file.confidence === 'medium'
                ? 'Medium — the file matched a signature, but a longer one would be certain.'
                : 'High — the file matched a long, specific signature.'
          }
        />
        {mismatch ? (
          <p className="files-detail__note files-detail__note--warning">
            {`The name says .${nameExtension(name)} but the content looks like a ${file.format} file.`}
          </p>
        ) : null}
        <KeyValueRow label="Size" value={formatBytesExact(file.size)} />
      </DetailSection>

      <DetailSection title="Download" sectionKey="file-download">
        {missing ? (
          <p className="files-detail__note files-detail__note--warning">
            This file is no longer available on this computer. The capture may have been moved or the
            analysis folder deleted.
          </p>
        ) : (
          <>
            <DownloadButton
              fileName={name || 'file'}
              onDownload={onDownload}
              busy={busy}
              variant="detail"
              buttonVariant="primary"
            />
            <p className="files-detail__note">
              {`Saved as ${savedAs}. RACCOON saves the file under a neutral name and never opens or runs it.`}
            </p>
            {file.status === 'truncated' ? (
              <p className="files-detail__note files-detail__note--warning">
                This file is incomplete, so it may not open normally.
              </p>
            ) : null}
            {file.status === 'corrupt' ? (
              <p className="files-detail__note files-detail__note--warning">
                This file is incomplete, so it may not open normally.
              </p>
            ) : null}
            {error ? (
              <p className="files-detail__note files-detail__note--warning" role="alert">
                {error}
              </p>
            ) : null}
            {error && onCopyDiagnostics ? (
              <div className="files-detail__actions">
                <Button variant="tertiary" onClick={onCopyDiagnostics}>
                  Copy diagnostic info
                </Button>
              </div>
            ) : null}
          </>
        )}
      </DetailSection>
    </aside>
  )
}
