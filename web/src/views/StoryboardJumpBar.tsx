import { useState, type JSX } from 'react'

import { Icon } from '../assets/icons'
import { Button } from '../components/primitives/Button'
import { findEventByPacket, findEventByTime, parseJumpTime } from '../lib/storyboard'
import type { CaseEvent } from '../api/types'

/**
 * The jump controls of the list (UI_Design.md §5.16). The list is one long
 * scroll, so the reader needs a way into the middle of it: the **Start**
 * button, a jump-to-time field and a jump-to-packet field.
 */

export interface StoryboardJumpBarProps {
  events: CaseEvent[]
  /** The start of the capture in milliseconds since the epoch. */
  captureStart: number
  /** The id of the selected event. */
  selectedId: number | null
  onSelect: (id: number) => void
}

export function StoryboardJumpBar({
  events,
  captureStart,
  selectedId,
  onSelect,
}: StoryboardJumpBarProps): JSX.Element {
  const [time, setTime] = useState('')
  const [packet, setPacket] = useState('')
  const [note, setNote] = useState<string | null>(null)

  const jumpToTime = () => {
    const parsed = parseJumpTime(time)
    if (!parsed) {
      setNote('Use 00:41 for the elapsed time or 14:03:07 for the clock.')
      return
    }
    const id = findEventByTime(events, parsed.time, parsed.kind, captureStart)
    if (id === null) {
      setNote('No event is near that time.')
      return
    }
    setNote(null)
    onSelect(id)
  }

  const jumpToPacket = () => {
    const number = Number(packet.trim())
    if (!Number.isInteger(number) || number <= 0) {
      setNote('Use the packet number, for example 142.')
      return
    }
    const id = findEventByPacket(events, number)
    if (id === null) {
      setNote('No event carries a packet number.')
      return
    }
    setNote(null)
    onSelect(id)
  }

  return (
    <div className="storyboard-jump">
      <Button
        variant="tertiary"
        onClick={() => {
          const first = events[0]
          if (first) onSelect(first.id)
        }}
        disabled={events.length === 0}
      >
        Start
      </Button>

      <label className="storyboard-jump__field">
        <span className="visually-hidden">Jump to time</span>
        <input
          type="text"
          className="text-input storyboard-jump__input"
          placeholder="00:41"
          value={time}
          onChange={(event) => setTime(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault()
              jumpToTime()
            }
          }}
        />
      </label>

      <label className="storyboard-jump__field">
        <span className="visually-hidden">Jump to packet</span>
        <input
          type="text"
          className="text-input storyboard-jump__input"
          placeholder="Packet 142"
          value={packet}
          onChange={(event) => setPacket(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter') {
              event.preventDefault()
              jumpToPacket()
            }
          }}
        />
      </label>

      {note ? (
        <span className="storyboard-jump__note" role="status">
          <Icon name="info" size={14} />
          <span>{note}</span>
        </span>
      ) : null}

      {selectedId !== null ? (
        <span className="visually-hidden">{`Event ${selectedId} is selected.`}</span>
      ) : null}
    </div>
  )
}
