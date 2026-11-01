import { describe, expect, it } from 'vitest'

import { parseRoute } from './router'

describe('route parsing', () => {
  it('treats the root as the empty dashboard', () => {
    const { route, ignored } = parseRoute('/', '')
    expect(route).toEqual({ kind: 'empty' })
    expect(ignored).toBe(false)
  })

  it('reads a case route without a tab', () => {
    const { route } = parseRoute('/case/20260101-120000-abcdef', '')
    expect(route).toEqual({
      kind: 'case',
      caseId: '20260101-120000-abcdef',
      tab: null,
      params: {},
    })
  })

  it('reads the three case tabs', () => {
    for (const tab of ['storyboard', 'files', 'streams'] as const) {
      const { route } = parseRoute(`/case/abc/${tab}`, '')
      expect(route).toEqual({ kind: 'case', caseId: 'abc', tab, params: {} })
    }
  })

  it('keeps the graph route unavailable', () => {
    const { route } = parseRoute('/case/abc/graph', '')
    expect(route).toEqual({ kind: 'not-found', path: '/case/abc/graph' })
  })

  it('rejects unknown paths and malformed case ids', () => {
    expect(parseRoute('/nope', '').route.kind).toBe('not-found')
    expect(parseRoute('/case', '').route.kind).toBe('not-found')
    expect(parseRoute('/case/abc/extra/more', '').route.kind).toBe('not-found')
    expect(parseRoute('/case/has space', '').route.kind).toBe('not-found')
    expect(parseRoute('/case/../etc', '').route.kind).toBe('not-found')
  })

  it('keeps valid deep-link parameters', () => {
    const { route, ignored } = parseRoute('/case/abc/storyboard', '?event=12&sev=critical&q=login')
    expect(ignored).toBe(false)
    expect(route).toEqual({
      kind: 'case',
      caseId: 'abc',
      tab: 'storyboard',
      params: { event: '12', sev: 'critical', q: 'login' },
    })
  })

  it('drops invalid parameters and reports them', () => {
    const { route, ignored } = parseRoute('/case/abc/files', '?file=0&verdict=weird&sort=name')
    expect(ignored).toBe(true)
    expect(route).toEqual({
      kind: 'case',
      caseId: 'abc',
      tab: 'files',
      params: { sort: 'name' },
    })
  })

  it('drops parameters that do not belong to the view', () => {
    const { route, ignored } = parseRoute('/case/abc/streams', '?file=3')
    expect(ignored).toBe(true)
    expect(route).toEqual({ kind: 'case', caseId: 'abc', tab: 'streams', params: {} })
  })

  it('accepts the low-confidence flag only as 0 or 1', () => {
    expect(parseRoute('/case/abc/files', '?low=1').ignored).toBe(false)
    expect(parseRoute('/case/abc/files', '?low=0').ignored).toBe(false)
    expect(parseRoute('/case/abc/files', '?low=2').ignored).toBe(true)
  })

  it('handles query strings embedded directly in the pathname', () => {
    const { route, ignored } = parseRoute('/case/abc/storyboard?type=TCP_ANOMALY', '')
    expect(ignored).toBe(false)
    expect(route).toEqual({
      kind: 'case',
      caseId: 'abc',
      tab: 'storyboard',
      params: { type: 'TCP_ANOMALY' },
    })
  })

  it('redirects root with goto parameter to the target case path', () => {
    const { route, ignored } = parseRoute('/', '?goto=/case/abc/storyboard')
    expect(ignored).toBe(false)
    expect(route).toEqual({
      kind: 'case',
      caseId: 'abc',
      tab: 'storyboard',
      params: {},
    })
  })
})
