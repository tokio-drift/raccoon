import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type ReactNode,
} from 'react'

import { Icon } from '../../assets/icons'

export type ToastTone = 'info' | 'success' | 'error'

export interface ToastAction {
  label: string
  onClick: () => void
}

export interface ToastItem {
  id: number
  tone: ToastTone
  message: string
  action?: ToastAction
}

export interface ToastApi {
  /** Shows a toast; error toasts stay until they are dismissed. */
  push: (toast: {
    tone?: ToastTone
    message: string
    action?: ToastAction
    /** The lifetime in milliseconds; error toasts never expire. */
    duration?: number
  }) => void
  dismiss: (id: number) => void
  /** Pauses the timer of a toast while the reader looks at it. */
  pause: (id: number) => void
  /** Continues the timer of a toast. */
  resume: (id: number) => void
}

const ToastContext = createContext<ToastApi | null>(null)

/** The API outside a provider, so a component never crashes on a missing one. */
const NO_TOAST: ToastApi = {
  push: () => undefined,
  dismiss: () => undefined,
  pause: () => undefined,
  resume: () => undefined,
}

/** The lifetime of a toast in milliseconds; error toasts never expire. */
export const TOAST_TIMEOUT_MS = 6000

/** The number of toasts that are shown at the same time (§8.10). */
export const MAX_TOASTS = 3

export interface ToastProviderProps {
  children: ReactNode
}

/** Holds the toasts of the app. */
export function ToastProvider({ children }: ToastProviderProps): JSX.Element {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)
  const timers = useRef(new Map<number, number>())
  const durations = useRef(new Map<number, number>())
  const remaining = useRef(new Map<number, number>())
  const startedAt = useRef(new Map<number, number>())

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer !== undefined) window.clearTimeout(timer)
    timers.current.delete(id)
    durations.current.delete(id)
    remaining.current.delete(id)
    startedAt.current.delete(id)
    setToasts((items) => items.filter((item) => item.id !== id))
  }, [])

  const push = useCallback<ToastApi['push']>(
    ({ tone = 'info', message, action, duration = TOAST_TIMEOUT_MS }) => {
      const id = nextId.current
      nextId.current += 1
      setToasts((items) => {
        const next = [...items, { id, tone, message, action }]
        // At most three toasts are shown; the oldest one goes (§8.10).
        return next.length > MAX_TOASTS ? next.slice(next.length - MAX_TOASTS) : next
      })
      if (tone !== 'error') {
        durations.current.set(id, duration)
        startedAt.current.set(id, Date.now())
        const timer = window.setTimeout(() => dismiss(id), duration)
        timers.current.set(id, timer)
      }
    },
    [dismiss],
  )

  // The timer of a toast stops while the reader looks at it (§8.10).
  const pause = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer === undefined) return
    window.clearTimeout(timer)
    timers.current.delete(id)
    const started = startedAt.current.get(id) ?? Date.now()
    const duration = durations.current.get(id) ?? TOAST_TIMEOUT_MS
    remaining.current.set(id, Math.max(0, duration - (Date.now() - started)))
  }, [])

  const resume = useCallback(
    (id: number) => {
      if (timers.current.has(id)) return
      const left = remaining.current.get(id)
      if (left === undefined) return
      remaining.current.delete(id)
      if (left <= 0) {
        dismiss(id)
        return
      }
      startedAt.current.set(id, Date.now())
      const timer = window.setTimeout(() => dismiss(id), left)
      timers.current.set(id, timer)
    },
    [dismiss],
  )

  useEffect(() => {
    const pending = timers.current
    return () => {
      for (const timer of pending.values()) window.clearTimeout(timer)
      pending.clear()
    }
  }, [])

  const api = useMemo<ToastApi>(
    () => ({ push, dismiss, pause, resume }),
    [dismiss, pause, push, resume],
  )

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismiss} onPause={pause} onResume={resume} />
    </ToastContext.Provider>
  )
}

/** The toast API of the app. */
export function useToast(): ToastApi {
  const api = useContext(ToastContext)
  return api ?? NO_TOAST
}

export interface ToastStackProps {
  toasts: ToastItem[]
  onDismiss: (id: number) => void
  /** The timer of a toast stops while the reader looks at it. */
  onPause?: (id: number) => void
  /** The timer of a toast continues. */
  onResume?: (id: number) => void
}

/** The toast stack (UI_Design.md §11); it sits at the bottom left. */
export function ToastStack({ toasts, onDismiss, onPause, onResume }: ToastStackProps): JSX.Element {
  return (
    <div className="toast-stack" role="status" aria-live="polite">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`toast toast--${toast.tone}`}
          tabIndex={0}
          onMouseEnter={() => onPause?.(toast.id)}
          onMouseLeave={() => onResume?.(toast.id)}
          onFocus={() => onPause?.(toast.id)}
          onBlur={() => onResume?.(toast.id)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.stopPropagation()
              onDismiss(toast.id)
            }
          }}
        >
          <Icon
            name={toast.tone === 'error' ? 'critical' : toast.tone === 'success' ? 'check' : 'info'}
            size={18}
          />
          <span className="toast__message">{toast.message}</span>
          {toast.action ? (
            <button
              type="button"
              className="button button--tertiary"
              onClick={() => {
                toast.action?.onClick()
                onDismiss(toast.id)
              }}
            >
              {toast.action.label}
            </button>
          ) : null}
          <button
            type="button"
            className="icon-button"
            aria-label="Dismiss"
            onClick={() => onDismiss(toast.id)}
          >
            <Icon name="close" size={16} />
          </button>
        </div>
      ))}
    </div>
  )
}
