import { useRef, type JSX, type PointerEvent as ReactPointerEvent, type KeyboardEvent } from 'react'

export interface PaneResizerProps {
  /** The width of the pane on the left of the resizer, in pixels. */
  value: number
  /** The smallest width of the pane, in pixels. */
  min: number
  /** The largest width of the pane, in pixels. */
  max: number
  /** The reader resizes the pane. */
  onChange: (value: number) => void
  /** The name of the separator, for the screen reader. */
  label: string
  /** The step of the arrow keys, in pixels. */
  step?: number
}

/**
 * The handle between two panes (UI_Design.md §14.2). It can be dragged with
 * the pointer and moved with the arrow keys, and it tells the screen reader
 * how wide the pane is.
 */
export function PaneResizer({
  value,
  min,
  max,
  onChange,
  label,
  step = 16,
}: PaneResizerProps): JSX.Element {
  const drag = useRef<{ startX: number; startValue: number } | null>(null)

  const clamp = (next: number): number => Math.min(max, Math.max(min, Math.round(next)))

  const onPointerDown = (event: ReactPointerEvent<HTMLDivElement>) => {
    drag.current = { startX: event.clientX, startValue: value }
    event.currentTarget.setPointerCapture(event.pointerId)
    event.preventDefault()
  }

  const onPointerMove = (event: ReactPointerEvent<HTMLDivElement>) => {
    const start = drag.current
    if (!start) return
    onChange(clamp(start.startValue + (event.clientX - start.startX)))
  }

  const endDrag = (event: ReactPointerEvent<HTMLDivElement>) => {
    drag.current = null
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId)
    }
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.key === 'ArrowLeft') {
      event.preventDefault()
      onChange(clamp(value - step))
    } else if (event.key === 'ArrowRight') {
      event.preventDefault()
      onChange(clamp(value + step))
    } else if (event.key === 'Home') {
      event.preventDefault()
      onChange(min)
    } else if (event.key === 'End') {
      event.preventDefault()
      onChange(max)
    }
  }

  return (
    <div
      className="pane-resizer"
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={value}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={endDrag}
      onPointerCancel={endDrag}
      onKeyDown={onKeyDown}
    >
      <span className="pane-resizer__grip" aria-hidden="true" />
    </div>
  )
}
