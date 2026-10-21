import { useCallback, useSyncExternalStore } from 'react'

/** Manual theme choice (§10.2). "system" follows the operating system. */
export type ThemePreference = 'system' | 'light' | 'dark'
/** Resolved theme actually applied to the document. */
export type ResolvedTheme = 'light' | 'dark'
/** Row and card density (§10.5). */
export type Density = 'comfortable' | 'compact'
/** Time basis for the views (§12.4). */
export type TimeBasis = 'utc' | 'local'

export interface Preferences {
  theme: ThemePreference
  density: Density
  timeBasis: TimeBasis
  projectorText: boolean
}

const KEYS = {
  theme: 'raccoon.theme',
  density: 'raccoon.density',
  timeBasis: 'raccoon.timeBasis',
  projectorText: 'raccoon.projectorText',
} as const

const DEFAULTS: Preferences = {
  theme: 'system',
  density: 'comfortable',
  timeBasis: 'utc',
  projectorText: false,
}

const listeners = new Set<() => void>()
let current: Preferences = DEFAULTS

function readStored<T extends string>(key: string, allowed: readonly T[], fallback: T): T {
  try {
    const raw = window.localStorage.getItem(key)
    if (raw !== null && (allowed as readonly string[]).includes(raw)) {
      return raw as T
    }
  } catch {
    // Storage can be unavailable (private mode); fall back to the default.
  }
  return fallback
}

function systemPrefersDark(): boolean {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )
}

/** Resolves a theme preference against the system setting. */
export function resolveTheme(preference: ThemePreference, systemDark: boolean): ResolvedTheme {
  if (preference === 'dark') return 'dark'
  if (preference === 'light') return 'light'
  return systemDark ? 'dark' : 'light'
}

function readAll(): Preferences {
  return {
    theme: readStored<ThemePreference>(KEYS.theme, ['system', 'light', 'dark'], DEFAULTS.theme),
    density: readStored<Density>(KEYS.density, ['comfortable', 'compact'], DEFAULTS.density),
    timeBasis: readStored<TimeBasis>(KEYS.timeBasis, ['utc', 'local'], DEFAULTS.timeBasis),
    projectorText: readStored<'on' | 'off'>(
      KEYS.projectorText,
      ['on', 'off'],
      DEFAULTS.projectorText ? 'on' : 'off',
    ) === 'on',
  }
}

function store(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    // A missing localStorage must not break the UI; the choice is then session-only.
  }
}

/** Writes the resolved theme onto the document so CSS variables switch. */
export function applyThemeToDocument(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-theme', resolved)
}

/** Writes the density and projector-text flags onto the document. */
export function applyLayoutToDocument(density: Density, projectorText: boolean): void {
  if (typeof document === 'undefined') return
  document.documentElement.setAttribute('data-density', density)
  document.documentElement.setAttribute('data-projector', projectorText ? 'on' : 'off')
}

function emit(): void {
  for (const listener of listeners) listener()
}

function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => {
    listeners.delete(listener)
  }
}

function getSnapshot(): Preferences {
  return current
}

/** Reads the stored preferences once, applying the theme to the document. */
export function loadPreferences(): Preferences {
  current = readAll()
  applyThemeToDocument(resolveTheme(current.theme, systemPrefersDark()))
  applyLayoutToDocument(current.density, current.projectorText)
  return current
}

/** Updates one preference, persists it and notifies subscribers. */
export function setPreference<K extends keyof Preferences>(key: K, value: Preferences[K]): void {
  current = { ...current, [key]: value }
  switch (key) {
    case 'theme':
      store(KEYS.theme, value as string)
      applyThemeToDocument(resolveTheme(current.theme, systemPrefersDark()))
      break
    case 'density':
      store(KEYS.density, value as string)
      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-density', value as string)
      }
      break
    case 'timeBasis':
      store(KEYS.timeBasis, value as string)
      break
    case 'projectorText':
      store(KEYS.projectorText, value ? 'on' : 'off')
      if (typeof document !== 'undefined') {
        document.documentElement.setAttribute('data-projector', value ? 'on' : 'off')
      }
      break
  }
  emit()
}

/** The live preferences, plus a setter for one preference. */
export function usePreferences(): [Preferences, <K extends keyof Preferences>(
  key: K,
  value: Preferences[K],
) => void] {
  const preferences = useSyncExternalStore(subscribe, getSnapshot, getSnapshot)
  const update = useCallback(
    <K extends keyof Preferences>(key: K, value: Preferences[K]) => setPreference(key, value),
    [],
  )
  return [preferences, update]
}
