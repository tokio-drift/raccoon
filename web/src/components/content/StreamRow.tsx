import type { JSX } from 'react'

import { Icon } from '../../assets/icons'
import { Tooltip } from '../primitives/Tooltip'

export interface StreamRowProps {
  /** The stream id. */
  streamId: number
  /** The protocol tag, for example "FTP". */
  protocol?: string
  /** The endpoints, for example "192.0.2.14:51822 → 192.0.2.50:21". */
  endpoints?: string
  /** The bytes from the client to the server. */
  bytesC2S?: number
  /** The bytes from the server to the client. */
  bytesS2C?: number
  /** The number of packets. */
  packets?: number
  /** The row is the selected stream. */
  selected?: boolean
  /** The row is a child of another stream, for example an FTP data stream. */
  child?: boolean
  /** The label of the parent, for example "FTP data · child of Stream 1". */
  childLabel?: string
  /** The stream has a gap in its data. */
  hasGap?: boolean
  /** The stream started after the capture began. */
  midstream?: boolean
  onSelect?: () => void
}

/**
 * A row of the stream list (UI_Design.md §7.1, §11). The byte counts use the
 * direction glyphs, the uncertainties are shown with an icon and a tooltip.
 */
export function StreamRow({
  streamId,
  protocol,
  endpoints,
  bytesC2S,
  bytesS2C,
  packets,
  selected = false,
  child = false,
  childLabel,
  hasGap = false,
  midstream = false,
  onSelect,
}: StreamRowProps): JSX.Element {
  const classes = ['stream-row']
  if (selected) classes.push('stream-row--selected')
  if (child) classes.push('stream-row--child')

  return (
    <div
      className={classes.join(' ')}
      role="option"
      aria-selected={selected}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault()
          onSelect?.()
        }
      }}
    >
      <div className="stream-row__title">
        <span className="stream-row__name">{`Stream ${streamId}`}</span>
        {protocol ? <span className="tag tag--plain">{protocol}</span> : null}
        {child && childLabel ? (
          <span className="stream-row__child">{childLabel}</span>
        ) : null}
        <span className="stream-row__flags">
          {hasGap ? (
            <Tooltip text="Some packets in this conversation are missing, so parts of it can't be rebuilt.">
              <span className="stream-row__flag">
                <Icon name="gap" size={16} />
                <span className="live-region">Gap in data</span>
              </span>
            </Tooltip>
          ) : null}
          {midstream ? (
            <Tooltip text="The capture began after the conversation had started.">
              <span className="stream-row__flag">
                <Icon name="info" size={16} />
                <span className="live-region">Started mid-stream</span>
              </span>
            </Tooltip>
          ) : null}
        </span>
      </div>
      {endpoints ? <span className="stream-row__endpoints">{endpoints}</span> : null}
      <span className="stream-row__bytes">
        {bytesC2S === undefined ? null : <span>{`${bytesC2S} B ↑`}</span>}
        {bytesS2C === undefined ? null : <span>{`${bytesS2C} B ↓`}</span>}
        {packets === undefined ? null : <span>{`${packets} pkts`}</span>}
      </span>
    </div>
  )
}
