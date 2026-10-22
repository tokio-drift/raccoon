import { useEffect, useRef, useState, type JSX } from 'react'

import { Button } from '../components/primitives/Button'
import { TextInput } from '../components/primitives/Field'
import { formatCount } from '../lib/format'
import { jumpOutOfRangeText, parseJumpOffset, windowRangeText } from '../lib/streams'

export interface StreamsFooterProps {
  /** The offset of the first visible byte. */
  offset: number
  /** The number of bytes that are loaded. */
  length: number
  /** The total number of bytes in the direction. */
  total: number
  /** The reader moves to the previous window. */
  onPrevious: () => void
  /** The reader moves to the next window. */
  onNext: () => void
  /** The reader jumps to an offset. */
  onJump: (offset: number) => void
  /** The reader jumps to a packet. */
  onJumpPacket?: (packetNo: number) => void
  /** The reader loads a larger window. */
  onLoadLarger: () => void
  /** The size of the windows that are loaded. */
  windowSize: number
  /** The note of a large stream. */
  note?: string | null
  /** The jump field is open. */
  jumpOpen: boolean
  /** The reader opens or closes the jump field. */
  onJumpOpenChange: (open: boolean) => void
}

/**
 * The footer strip of the stream inspector (UI_Design.md §7.9): the range
 * that is shown, the paging buttons and the jump field.
 */
export function StreamsFooter({
  offset,
  length,
  total,
  onPrevious,
  onNext,
  onJump,
  onJumpPacket,
  onLoadLarger,
  windowSize,
  note,
  jumpOpen,
  onJumpOpenChange,
}: StreamsFooterProps): JSX.Element {
  const [offsetText, setOffsetText] = useState('')
  const [packetText, setPacketText] = useState('')
  const [error, setError] = useState<string | null>(null)
  const root = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!jumpOpen) return
    const onDocumentClick = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) onJumpOpenChange(false)
    }
    document.addEventListener('mousedown', onDocumentClick)
    return () => document.removeEventListener('mousedown', onDocumentClick)
  }, [jumpOpen, onJumpOpenChange])

  const atEnd = total > 0 && offset + length >= total

  const jump = (): void => {
    const packet = Number.parseInt(packetText.trim(), 10)
    if (packetText.trim() !== '' && Number.isFinite(packet) && onJumpPacket) {
      onJumpPacket(packet)
      onJumpOpenChange(false)
      return
    }
    const parsed = parseJumpOffset(offsetText)
    if (parsed === null) {
      setError('Enter a byte offset as a number or in hexadecimal, for example 4096 or 0x1000.')
      return
    }
    if (total > 0 && parsed >= total) {
      setError(jumpOutOfRangeText(total))
      return
    }
    setError(null)
    onJump(parsed)
    onJumpOpenChange(false)
  }

  return (
    <div className="streams-footer">
      <span className="streams-footer__range">{windowRangeText(offset, length, total)}</span>
      {note ? <span className="streams-footer__note">{note}</span> : null}
      <span className="streams-footer__actions">
        <Button
          variant="secondary"
          disabled={offset <= 0}
          onClick={onPrevious}
        >
          {`Previous ${windowLabel(windowSize)}`}
        </Button>
        <Button variant="secondary" disabled={atEnd} onClick={onNext}>
          {`Next ${windowLabel(windowSize)}`}
        </Button>
        {windowSize < 65536 ? (
          <Button variant="tertiary" onClick={onLoadLarger}>
            Load larger window (64 KB)
          </Button>
        ) : null}
        <span className="streams-footer__jump" ref={root}>
          <Button variant="secondary" onClick={() => onJumpOpenChange(!jumpOpen)}>
            Jump to…
          </Button>
          {jumpOpen ? (
            <div className="streams-jump" role="group" aria-label="Jump to a position">
              <TextInput
                label="Offset"
                value={offsetText}
                placeholder="4096 or 0x1000"
                error={error ?? undefined}
                onChange={(event) => {
                  setOffsetText(event.target.value)
                  setError(null)
                }}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') jump()
                }}
              />
              <TextInput
                label="Packet"
                value={packetText}
                placeholder="14"
                onChange={(event) => setPacketText(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter') jump()
                }}
              />
              <Button variant="primary" onClick={jump}>
                Jump
              </Button>
            </div>
          ) : null}
        </span>
      </span>
      {atEnd ? <span className="streams-footer__end">End of data</span> : null}
      <span className="streams-footer__total">{`${formatCount(total)} bytes in this direction`}</span>
    </div>
  )
}

/** The name of a window size: "4 KB" or "64 KB". */
function windowLabel(size: number): string {
  return size >= 65536 ? '64 KB' : '4 KB'
}
