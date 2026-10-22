import type { JSX } from 'react'

import { Icon } from '../assets/icons'
import { CopyButton } from '../components/primitives/CopyButton'
import { Tooltip } from '../components/primitives/Tooltip'
import type { StreamSummary } from '../api/types'
import { formatBytes, formatClock, formatCount, formatElapsed, parseTimestamp } from '../lib/format'
import { streamEndpoints } from '../lib/streams'

export interface StreamsHeaderCardProps {
  /** The stream that is shown. */
  stream: StreamSummary
  /** The start of the capture, for the elapsed times. */
  captureStart: number
  /** The time basis of the wall clock. */
  basis: 'utc' | 'local'
  /** The parent stream, when the stream is a child. */
  parent?: StreamSummary | null
  /** The related carved files of the stream. */
  relatedFiles?: { id: number; name: string }[]
  /** The reader opens another stream. */
  onOpenStream?: (id: number) => void
  /** The reader opens a file. */
  onOpenFile?: (id: number) => void
  /** The reader opens the jump field. */
  onJump?: () => void
}

/**
 * The header card of the stream inspector (UI_Design.md §7.3): the title, the
 * time and the packets, the byte counts of the two directions and the flags of
 * the stream.
 */
export function StreamsHeaderCard({
  stream,
  captureStart,
  basis,
  parent,
  relatedFiles,
  onOpenStream,
  onOpenFile,
  onJump,
}: StreamsHeaderCardProps): JSX.Element {
  const start = parseTimestamp(stream.startTs)
  const end = parseTimestamp(stream.endTs)
  const total = stream.bytesC2S + stream.bytesS2C
  const summary = [
    `Stream ${stream.id}`,
    stream.proto.toUpperCase(),
    streamEndpoints(stream),
    `Start ${formatElapsed(start - captureStart)}`,
    `End ${formatElapsed(end - captureStart)}`,
    `${formatCount(stream.packets)} packets (pkts ${stream.firstPacket}–${stream.lastPacket})`,
    `Client to server ${formatBytes(stream.bytesC2S)}`,
    `Server to client ${formatBytes(stream.bytesS2C)}`,
  ].join('\n')

  return (
    <section className="streams-header" aria-labelledby="streams-header-title">
      <div className="streams-header__row">
        <h2 className="streams-header__title" id="streams-header-title">
          {`Stream ${stream.id}`}
        </h2>
        <span className="tag tag--plain">{stream.proto.toUpperCase()}</span>
        <span className="streams-header__endpoints">{streamEndpoints(stream)}</span>
        <CopyButton value={streamEndpoints(stream)} label="Copy the endpoints" />
        {parent ? (
          <button
            type="button"
            className="streams-header__link"
            onClick={() => onOpenStream?.(parent.id)}
          >
            {`Parent: Stream ${parent.id}`}
          </button>
        ) : null}
        {(relatedFiles ?? []).map((file) => (
          <button
            key={file.id}
            type="button"
            className="streams-header__link"
            onClick={() => onOpenFile?.(file.id)}
          >
            {`Related file: ${file.name}`}
          </button>
        ))}
      </div>

      <div className="streams-header__row streams-header__row--meta">
        <Tooltip text={`${formatClock(start, { basis, seconds: true })} · ${formatClock(end, { basis, seconds: true })}`}>
          <span className="streams-header__time">
            {`Start ${formatElapsed(start - captureStart)} · End ${formatElapsed(end - captureStart)}`}
          </span>
        </Tooltip>
        <span className="streams-header__packets">
          {`${formatCount(stream.packets)} packets (pkts ${stream.firstPacket}–${stream.lastPacket})`}
        </span>
      </div>

      <div className="streams-header__row streams-header__row--bars">
        <div className="streams-header__bar streams-header__bar--c2s">
          <span className="streams-header__bar-label">{`Client → Server ${formatBytes(stream.bytesC2S)}`}</span>
          <span
            className="streams-header__bar-fill"
            style={{ width: `${total > 0 ? Math.round((stream.bytesC2S / total) * 100) : 0}%` }}
          />
        </div>
        <div className="streams-header__bar streams-header__bar--s2c">
          <span className="streams-header__bar-label">{`Server → Client ${formatBytes(stream.bytesS2C)}`}</span>
          <span
            className="streams-header__bar-fill"
            style={{ width: `${total > 0 ? Math.round((stream.bytesS2C / total) * 100) : 0}%` }}
          />
        </div>
      </div>

      <div className="streams-header__row streams-header__row--flags">
        {stream.hasGaps ? (
          <Tooltip text="Some packets in this conversation are missing, so parts of it can't be rebuilt.">
            <span className="tag tag--warning">
              <Icon name="gap" size={14} />
              Gap in data
            </span>
          </Tooltip>
        ) : null}
        {stream.midstream ? (
          <Tooltip text="The capture began after the conversation had started.">
            <span className="tag tag--plain">
              <Icon name="info" size={14} />
              Started mid-stream
            </span>
          </Tooltip>
        ) : null}
        {stream.udp ? (
          <Tooltip text="UDP has no connection, so RACCOON shows each datagram as a separate block.">
            <span className="tag tag--plain">UDP</span>
          </Tooltip>
        ) : null}
        <span className="streams-header__actions">
          <CopyButton value={summary} label="Copy stream summary" showLabel />
          {onJump ? (
            <button type="button" className="button button--secondary" onClick={onJump}>
              Jump to a byte
            </button>
          ) : null}
        </span>
      </div>
    </section>
  )
}
