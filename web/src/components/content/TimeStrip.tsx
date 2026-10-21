import { useRef, type JSX, type MouseEvent } from 'react'

export interface TimeStripTick {
  id: number
  /** The offset of the event from the start of the capture, in milliseconds. */
  time: number
  severity: 'info' | 'warning' | 'critical'
}

export interface TimeStripProps {
  ticks: TimeStripTick[]
  /** The total length of the capture in milliseconds. */
  duration: number
  /** The id of the selected event. */
  selectedId?: number
  /** The selected range in milliseconds, as [from, to]. */
  range?: [number, number] | null
  onSelect?: (id: number) => void
  /** Called while the user drags a range over the strip. */
  onRangeChange?: (range: [number, number] | null) => void
  /** Called when the user clears the range with Escape. */
  onRangeClear?: () => void
}

/**
 * The time strip (UI_Design.md §5.2, §11). Every event is a tick whose height
 * carries the severity, so the strip reads without colour. Dragging over it
 * selects a time range; Escape clears the range.
 */
export function TimeStrip({
  ticks,
  duration,
  selectedId,
  range,
  onSelect,
  onRangeChange,
  onRangeClear,
}: TimeStripProps): JSX.Element {
  const strip = useRef<HTMLDivElement | null>(null)
  const dragStart = useRef<number | null>(null)

  const positionOf = (time: number): number => {
    if (duration <= 0) return 0
    return Math.min(100, Math.max(0, (time / duration) * 100))
  }

  const timeAt = (clientX: number): number => {
    const element = strip.current
    if (!element || duration <= 0) return 0
    const box = element.getBoundingClientRect()
    const ratio = (clientX - box.left) / box.width
    return Math.min(duration, Math.max(0, ratio * duration))
  }

  const onMouseDown = (event: MouseEvent<HTMLDivElement>) => {
    if (!onRangeChange) return
    dragStart.current = timeAt(event.clientX)
  }

  const onMouseMove = (event: MouseEvent<HTMLDivElement>) => {
    if (dragStart.current === null || !onRangeChange) return
    const current = timeAt(event.clientX)
    onRangeChange([Math.min(dragStart.current, current), Math.max(dragStart.current, current)])
  }

  const onMouseUp = () => {
    dragStart.current = null
  }

  const onKeyDown = (event: React.KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'Escape' && range) {
      event.stopPropagation()
      onRangeClear?.()
    }
  }

  return (
    <div
      className="time-strip"
      ref={strip}
      role="group"
      aria-label="Capture time strip"
      tabIndex={0}
      onMouseDown={onMouseDown}
      onMouseMove={onMouseMove}
      onMouseUp={onMouseUp}
      onMouseLeave={onMouseUp}
      onKeyDown={onKeyDown}
    >
      {range ? (
        <span
          className="time-strip__range"
          style={{
            left: `${positionOf(range[0])}%`,
            width: `${positionOf(range[1]) - positionOf(range[0])}%`,
          }}
        />
      ) : null}
      {ticks.map((tick) => (
        <button
          key={tick.id}
          type="button"
          className={
            tick.id === selectedId
              ? `time-strip__tick time-strip__tick--${tick.severity} time-strip__tick--selected`
              : `time-strip__tick time-strip__tick--${tick.severity}`
          }
          style={{ left: `${positionOf(tick.time)}%` }}
          aria-label={`Event ${tick.id}`}
          aria-pressed={tick.id === selectedId}
          onClick={() => onSelect?.(tick.id)}
        />
      ))}
    </div>
  )
}
