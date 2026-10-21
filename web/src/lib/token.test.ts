import { beforeEach, describe, expect, it } from 'vitest'

import { captureTokenFromLocation, getSessionToken, setSessionToken } from './token'

describe('session token', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    setSessionToken(null)
  })

  it('takes the token out of the address bar and keeps it in memory', () => {
    window.history.replaceState({}, '', '/case/abc?t=secret-token&x=1')
    expect(captureTokenFromLocation()).toBe('secret-token')
    expect(getSessionToken()).toBe('secret-token')
    expect(window.location.search).toBe('?x=1')
    expect(window.location.href).not.toContain('secret-token')
  })

  it('keeps the rest of the path and the hash', () => {
    window.history.replaceState({}, '', '/case/abc?t=secret-token#top')
    captureTokenFromLocation()
    expect(window.location.pathname).toBe('/case/abc')
    expect(window.location.hash).toBe('#top')
  })

  it('returns null when the URL carries no token', () => {
    window.history.replaceState({}, '', '/case/abc')
    expect(captureTokenFromLocation()).toBeNull()
    expect(getSessionToken()).toBeNull()
  })
})
