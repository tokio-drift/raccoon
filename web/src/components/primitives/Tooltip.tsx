import { cloneElement, isValidElement, useEffect, useId, useRef, useState, type JSX, type ReactNode } from 'react'

export interface TooltipProps {
  /** The control the tooltip describes. */
  children: ReactNode
  /** The plain tooltip text. */
  text?: string
  /** A rich tooltip: a heading and a body. */
  title?: string
  body?: string
  /** The delay before the tooltip opens, in milliseconds. */
  delay?: number
}

/**
 * A tooltip (UI_Design.md §11). It opens on hover and on focus after 300 ms,
 * closes on Escape and on blur, and never carries the only copy of a piece of
 * information.
 */
export function Tooltip({ children, text, title, body, delay = 300 }: TooltipProps): JSX.Element {
  const id = useId()
  const [open, setOpen] = useState(false)
  const timer = useRef<number | null>(null)

  const cancel = () => {
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = null
  }

  const show = () => {
    cancel()
    timer.current = window.setTimeout(() => setOpen(true), delay)
  }

  const hide = () => {
    cancel()
    setOpen(false)
  }

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      cancel()
    }
  }, [])

  const trigger = isValidElement(children)
    ? cloneElement(children as JSX.Element, { 'aria-describedby': open ? id : undefined })
    : children

  return (
    <span
      className="tooltip-wrap"
      onMouseEnter={show}
      onMouseLeave={hide}
      onFocus={show}
      onBlur={hide}
    >
      {trigger}
      {open ? (
        <span className="tooltip" role="tooltip" id={id}>
          {title ? <strong className="tooltip__title">{title}</strong> : null}
          {body ?? text}
        </span>
      ) : null}
    </span>
  )
}
