import { act, renderHook } from '@testing-library/react'
import { beforeEach, describe, expect, it } from 'vitest'

import {
  applyThemeToDocument,
  loadPreferences,
  resolveTheme,
  setPreference,
  usePreferences,
} from '../lib/preferences'

describe('theme resolution', () => {
  it('follows the system when the preference is "system"', () => {
    expect(resolveTheme('system', true)).toBe('dark')
    expect(resolveTheme('system', false)).toBe('light')
  })

  it('honours a manual choice regardless of the system setting', () => {
    expect(resolveTheme('light', true)).toBe('light')
    expect(resolveTheme('dark', false)).toBe('dark')
  })
})

describe('preference persistence', () => {
  beforeEach(() => {
    window.localStorage.clear()
    loadPreferences()
  })

  it('stores the manual theme choice in local storage', () => {
    setPreference('theme', 'dark')
    expect(window.localStorage.getItem('raccoon.theme')).toBe('dark')

    setPreference('theme', 'light')
    expect(window.localStorage.getItem('raccoon.theme')).toBe('light')
  })

  it('applies the resolved theme to the document', () => {
    setPreference('theme', 'dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')

    setPreference('theme', 'light')
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('applies a stored theme when the preferences are loaded', () => {
    window.localStorage.setItem('raccoon.theme', 'dark')
    loadPreferences()
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })

  it('falls back to light when the stored value is not understood', () => {
    window.localStorage.setItem('raccoon.theme', 'neon')
    loadPreferences()
    expect(document.documentElement.getAttribute('data-theme')).toBe('light')
  })

  it('stores density, time basis and projector text', () => {
    setPreference('density', 'compact')
    setPreference('timeBasis', 'local')
    setPreference('projectorText', true)

    expect(window.localStorage.getItem('raccoon.density')).toBe('compact')
    expect(window.localStorage.getItem('raccoon.timeBasis')).toBe('local')
    expect(window.localStorage.getItem('raccoon.projectorText')).toBe('on')
    expect(document.documentElement.getAttribute('data-density')).toBe('compact')
  })

  it('exposes the preferences through the hook', () => {
    const { result } = renderHook(() => usePreferences())
    expect(result.current[0].theme).toBe('system')

    act(() => {
      result.current[1]('theme', 'dark')
    })
    expect(result.current[0].theme).toBe('dark')
  })
})

describe('applyThemeToDocument', () => {
  it('writes the theme attribute', () => {
    applyThemeToDocument('dark')
    expect(document.documentElement.getAttribute('data-theme')).toBe('dark')
  })
})
