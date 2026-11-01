import { useCallback, useEffect, useState } from 'react'

/**
 * A minimal History API router (UI_Design.md §3.1–§3.2, PLAN 2.3: no routing
 * library). It understands the four case routes, the reserved graph route and
 * the deep-link parameters of each view.
 */

export type CaseTab = 'storyboard' | 'files' | 'streams'

export type Route =
  | { kind: 'empty' }
  | { kind: 'case'; caseId: string; tab: CaseTab | null; params: URLParams }
  | { kind: 'not-found'; path: string }

export interface URLParams {
  [name: string]: string
}

export interface RouteState {
  route: Route
  /** True when a deep-link parameter was dropped because it was not valid. */
  ignored: boolean
  navigate: (to: string, options?: { replace?: boolean }) => void
}

const CASE_ID_PATTERN = /^[A-Za-z0-9._-]{1,64}$/

const SEVERITIES = ['info', 'warning', 'critical']
const PHASES = ['recon', 'access', 'action', 'exfil', 'c2']
const PROTOCOLS = ['ftp', 'ftp-data', 'http', 'dns', 'tcp', 'udp', 'unknown']
const DIRECTIONS = ['c2s', 's2c', 'both']
const VERDICTS = ['malicious', 'suspicious', 'no_detections', 'unknown', 'not_checked']

type ParamRule = 'int' | 'text' | 'enum'

const VIEW_PARAMS: Record<CaseTab, Record<string, ParamRule>> = {
  storyboard: {
    event: 'int',
    sev: 'enum',
    type: 'text',
    proto: 'enum',
    phase: 'enum',
    q: 'text',
    from: 'text',
    to: 'text',
  },
  files: {
    file: 'int',
    verdict: 'enum',
    format: 'text',
    dir: 'enum',
    q: 'text',
    low: 'int',
    sort: 'text',
  },
  streams: {
    stream: 'int',
    dir: 'enum',
    offset: 'int',
    q: 'text',
  },
}

const ENUM_VALUES: Record<string, string[]> = {
  sev: SEVERITIES,
  phase: PHASES,
  proto: PROTOCOLS,
  verdict: VERDICTS,
  dir: DIRECTIONS,
}

function validParam(name: string, value: string, rule: ParamRule): boolean {
  switch (rule) {
    case 'int': {
      if (!/^\d+$/.test(value)) return false
      const parsed = Number(value)
      if (name === 'low') return parsed === 0 || parsed === 1
      return parsed > 0
    }
    case 'enum': {
      const allowed = ENUM_VALUES[name]
      const parts = value.split(',').map((part) => part.trim())
      if (parts.length === 0 || parts.some((part) => part.length === 0)) return false
      if (!allowed) return value.length > 0 && value.length <= 64
      return parts.every((part) => allowed.includes(part))
    }
    case 'text':
    default:
      return value.length <= 400
  }
}

/**
 * Parses a location into a route. Unrecognised paths and the reserved graph
 * route become "not found"; invalid deep-link parameters are dropped and
 * reported so the view can show the "Ignored an unrecognised filter" note.
 */
export function parseRoute(pathname: string, search: string): { route: Route; ignored: boolean } {
  const qIndex = pathname.indexOf('?')
  const cleanPath = qIndex >= 0 ? pathname.slice(0, qIndex) : pathname
  const searchPart = qIndex >= 0 && !search ? pathname.slice(qIndex) : search
  const segments = cleanPath.split('/').filter((segment) => segment.length > 0)

  if (segments.length === 0) {
    return { route: { kind: 'empty' }, ignored: false }
  }

  if (segments[0] !== 'case' || segments.length < 2 || segments.length > 3) {
    return { route: { kind: 'not-found', path: pathname }, ignored: false }
  }

  const caseId = decodeURIComponent(segments[1])
  if (!CASE_ID_PATTERN.test(caseId)) {
    return { route: { kind: 'not-found', path: pathname }, ignored: false }
  }

  let tab: CaseTab | null = null
  if (segments.length === 3) {
    const candidate = segments[2]
    if (candidate === 'storyboard' || candidate === 'files' || candidate === 'streams') {
      tab = candidate
    } else {
      // The graph route is reserved for a later version and is not available.
      return { route: { kind: 'not-found', path: pathname }, ignored: false }
    }
  }

  const params: URLParams = {}
  let ignored = false
  const query = new URLSearchParams(searchPart)
  const rules = tab ? VIEW_PARAMS[tab] : {}
  for (const [name, value] of query.entries()) {
    const rule = rules[name]
    if (!rule) {
      ignored = true
      continue
    }
    if (!validParam(name, value, rule)) {
      ignored = true
      continue
    }
    params[name] = value
  }

  return { route: { kind: 'case', caseId, tab, params }, ignored }
}

/** The current route, kept in sync with the browser history. */
export function useRoute(): RouteState {
  const [state, setState] = useState(() => {
    const parsed = parseRoute(window.location.pathname, window.location.search)
    return { route: parsed.route, ignored: parsed.ignored }
  })

  useEffect(() => {
    const onPopState = () => {
      const parsed = parseRoute(window.location.pathname, window.location.search)
      setState({ route: parsed.route, ignored: parsed.ignored })
    }
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const navigate = useCallback((to: string, options?: { replace?: boolean }) => {
    const qIndex = to.indexOf('?')
    const pathOnly = qIndex >= 0 ? to.slice(0, qIndex) : to
    const searchOnly = qIndex >= 0 ? to.slice(qIndex) : ''
    const parsed = parseRoute(pathOnly, searchOnly)
    if (options?.replace) {
      window.history.replaceState(window.history.state, '', to)
    } else {
      window.history.pushState(null, '', to)
    }
    setState({ route: parsed.route, ignored: parsed.ignored })
  }, [])

  return { ...state, navigate }
}
