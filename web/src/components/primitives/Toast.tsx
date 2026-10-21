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
}

const ToastContext = createContext<ToastApi | null>(null)

/** The API outside a provider, so a component never crashes on a missing one. */
const NO_TOAST: ToastApi = {
  push: () => undefined,
  dismiss: () => undefined,
}

/** The lifetime of a toast in milliseconds; error toasts never expire. */
export const TOAST_TIMEOUT_MS = 6000

export interface ToastProviderProps {
  children: ReactNode
}

/** Holds the toasts of the app. */
export function ToastProvider({ children }: ToastProviderProps): JSX.Element {
  const [toasts, setToasts] = useState<ToastItem[]>([])
  const nextId = useRef(1)
  const timers = useRef(new Map<number, number>())

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id)
    if (timer !== undefined) window.clearTimeout(timer)
    timers.current.delete(id)
    setToasts((items) => items.filter((item) => item.id !== id))
  }, [])

  const push = useCallback<ToastApi['push']>(
    ({ tone = 'info', message, action, duration = TOAST_TIMEOUT_MS }) => {
      const id = nextId.current
      nextId.current += 1
      setToasts((items) => [...items, { id, tone, message, action }])
      if (tone !== 'error') {
        const timer = window.setTimeout(() => dismiss(id), duration)
        timers.current.set(id, timer)
      }
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

  const api = useMemo<ToastApi>(() => ({ push, dismiss }), [push, dismiss])

  return (
    <ToastContext.Provider value={api}>
      {children}
      <ToastStack toasts={toasts} onDismiss={dismiss} />
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
}

/** The toast stack (UI_Design.md §11); it sits at the bottom left. */
export function ToastStack({ toasts, onDismiss }: ToastStackProps): JSX.Element {
  return (
    <div className="toast-stack" role="status" aria-live="polite">
      {toasts.map((toast) => (
        <div key={toast.id} className={`toast toast--${toast.tone}`}>
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
