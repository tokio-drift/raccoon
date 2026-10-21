import { useEffect, useRef, type JSX, type ReactNode } from 'react'

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'

/**
 * Traps the keyboard inside an overlay, closes it on Escape and returns the
 * focus to whatever opened it (UI_Design.md §11, §13.2).
 */
export function useFocusTrap(
  container: React.RefObject<HTMLElement>,
  onClose: () => void,
  options?: { initialFocus?: 'first' | 'cancel' },
): void {
  const opener = useRef<HTMLElement | null>(null)
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  const initialFocus = options?.initialFocus

  useEffect(() => {
    opener.current = document.activeElement as HTMLElement | null
    const node = container.current
    if (node) {
      const preferred =
        initialFocus === 'cancel' ? node.querySelector<HTMLElement>('[data-overlay-cancel]') : null
      const target = preferred ?? node.querySelector<HTMLElement>(FOCUSABLE)
      target?.focus()
    }

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        closeRef.current()
        return
      }
      if (event.key !== 'Tab') return
      const focusable = Array.from(node?.querySelectorAll<HTMLElement>(FOCUSABLE) ?? [])
      if (focusable.length === 0) return
      const first = focusable[0]
      const last = focusable[focusable.length - 1]
      const active = document.activeElement
      if (event.shiftKey && active === first) {
        event.preventDefault()
        last.focus()
      } else if (!event.shiftKey && active === last) {
        event.preventDefault()
        first.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown, true)
    return () => {
      document.removeEventListener('keydown', onKeyDown, true)
      opener.current?.focus?.()
    }
  }, [container, initialFocus])
}

export interface ModalProps {
  title: string
  children: ReactNode
  onClose: () => void
  /** Puts the focus on the cancel button first, for risky actions. */
  risky?: boolean
  className?: string
}

/** A modal dialog with a scrim (UI_Design.md §11). */
export function Modal({ title, children, onClose, risky = false, className }: ModalProps): JSX.Element {
  const ref = useRef<HTMLDivElement>(null)
  useFocusTrap(ref, onClose, { initialFocus: risky ? 'cancel' : 'first' })
  const headingId = `dialog-${title.replace(/\s+/g, '-').toLowerCase()}`

  return (
    <>
      <div className="scrim" onClick={onClose} aria-hidden="true" />
      <div
        className={className ? `dialog ${className}` : 'dialog'}
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        ref={ref}
      >
        <h2 className="overlay__title" id={headingId}>
          {title}
        </h2>
        {children}
      </div>
    </>
  )
}

export interface DrawerProps {
  title: string
  children: ReactNode
  onClose: () => void
  className?: string
}

/** A right-hand drawer with a scrim (UI_Design.md §11). */
export function Drawer({ title, children, onClose, className }: DrawerProps): JSX.Element {
  const ref = useRef<HTMLElement>(null)
  useFocusTrap(ref, onClose)
  const headingId = `drawer-${title.replace(/\s+/g, '-').toLowerCase()}`

  return (
    <>
      <div className="drawer-scrim" onClick={onClose} aria-hidden="true" />
      <aside
        className={className ? `drawer ${className}` : 'drawer'}
        role="dialog"
        aria-modal="true"
        aria-labelledby={headingId}
        ref={ref}
      >
        <h2 className="overlay__title" id={headingId}>
          {title}
        </h2>
        {children}
      </aside>
    </>
  )
}
