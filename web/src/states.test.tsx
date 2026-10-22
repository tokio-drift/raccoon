import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App } from './App'
import { ToastProvider } from './components/primitives/Toast'
import type { CaseSummary } from './api/types'
import { loadPreferences } from './lib/preferences'

/**
 * The state matrix of UI_Design.md §14.5. Every state of a case has its own
 * header actions and its own affordances in the three views.
 */

const READY_CASE: CaseSummary = {
  id: '20260101-120000-abcdef',
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
  status: 'ready',
  stage: 'done',
  progress: 100,
  durationNs: 2_450_000_000,
  packets: 42,
  streams: 3,
  files: 1,
  events: 1,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '2026-01-01T12:00:02.450000000Z',
  error: '',
}

const RUNNING_CASE: CaseSummary = {
  ...READY_CASE,
  status: 'running',
  stage: 'process',
  progress: 40,
  durationNs: 0,
  files: 0,
  events: 0,
  finishedAt: '',
}

const EVENT = {
  id: 1,
  ts: '2026-01-01T12:00:01.000000000Z',
  packetNo: 1,
  packetEnd: 1,
  type: 'HTTP_TRANSACTION',
  severity: 'info',
  phase: 'access',
  streamId: 1,
  src: '192.0.2.14:51822',
  dst: '192.0.2.50:80',
  proto: 'http',
  title: 'A request was made',
  details: {},
  explain: '',
  parentId: 0,
  fileId: 0,
  findingIds: [],
}

const FILE = {
  id: 1,
  streamId: 1,
  dir: 'c2s',
  startOff: 0,
  endOff: 1024,
  format: 'PNG',
  ext: 'png',
  status: 'complete',
  confidence: 'high',
  size: 1024,
  md5: 'd41d8cd98f00b204e9800998ecf8427e',
  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
  displayName: 'invoice.png',
  path: 'carved/invoice.png',
  magicHex: '89504e47',
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'test',
    json: async () => body,
  } as unknown as Response
}

function sseResponse(): Response {
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(new TextEncoder().encode(': heartbeat\n\n'))
    },
  })
  return {
    ok: true,
    status: 200,
    statusText: 'test',
    body,
    json: async () => ({}),
  } as unknown as Response
}

interface StubOptions {
  summary?: CaseSummary
  events?: unknown[]
  files?: unknown[]
  /** The file list fails. */
  filesFail?: boolean
  /** The live connection cannot be opened. */
  streamFails?: boolean
}

function stubFetch(options: StubOptions = {}) {
  const summary = options.summary ?? READY_CASE
  const events = options.events ?? [EVENT]
  const files = options.files ?? [FILE]
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/events/stream')) {
        if (options.streamFails) return jsonResponse({}, 500)
        return sseResponse()
      }
      if (url.includes('/events') && !url.includes('/events/stream')) {
        return jsonResponse({ items: events, nextCursor: null })
      }
      if (url.includes('/files')) {
        if (options.filesFail) return jsonResponse({ message: 'boom' }, 500)
        return jsonResponse({ items: files, nextCursor: null })
      }
      if (url.includes('/streams')) return jsonResponse({ items: [], nextCursor: null })
      return jsonResponse(summary)
    }),
  )
}

function renderApp(): void {
  render(
    <ToastProvider>
      <App />
    </ToastProvider>,
  )
}

beforeEach(() => {
  window.localStorage.clear()
  loadPreferences()
  window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('the state matrix of a case', () => {
  it('shows the empty dashboard with only the wordmark, Settings and Help', async () => {
    window.history.replaceState({}, '', '/')
    stubFetch()
    renderApp()

    expect(await screen.findByRole('heading', { name: 'Follow the trail.' })).toBeInTheDocument()
    const banner = screen.getByRole('banner')
    expect(within(banner).getByRole('button', { name: 'Settings' })).toBeInTheDocument()
    expect(within(banner).getByRole('button', { name: 'Help' })).toBeInTheDocument()
    expect(screen.queryByRole('tab', { name: 'Storyboard' })).toBeNull()
    expect(screen.queryByRole('tab', { name: 'Files' })).toBeNull()
    expect(screen.queryByRole('tab', { name: 'Streams' })).toBeNull()
  })

  it('keeps the tabs interactive while the case is loading', async () => {
    stubFetch()
    renderApp()

    const tab = await screen.findByRole('tab', { name: /Storyboard/ })
    expect(tab).toBeEnabled()
    expect(screen.getAllByRole('tab')).toHaveLength(3)
  })

  it('shows the processing view while the analysis runs', async () => {
    stubFetch({ summary: RUNNING_CASE })
    renderApp()

    expect(await screen.findByText(/Analysing/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Export report' })).toBeDisabled()
  })

  it('keeps the results of a running analysis usable', async () => {
    stubFetch({ summary: { ...RUNNING_CASE, events: 1, files: 1 } })
    renderApp()

    await screen.findByText(/Analysing/)
    expect(screen.getByRole('tab', { name: /Files/ })).toBeEnabled()
  })

  it('marks the results of a stopped analysis as partial', async () => {
    stubFetch({ summary: { ...READY_CASE, status: 'failed', stage: 'extract', progress: 41 } })
    renderApp()

    expect(await screen.findByText(/Results below are partial/)).toBeInTheDocument()
    expect(await screen.findByText('Partial')).toBeInTheDocument()
  })

  it('offers the filters and a way back when nothing matches', async () => {
    stubFetch()
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef/storyboard?sev=critical')
    renderApp()

    const empty = await screen.findByText('No events match these filters')
    expect(empty).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Clear all filters' })).toBeInTheDocument()
  })

  it('offers a retry when a view fails, and keeps the other tabs', async () => {
    stubFetch({ filesFail: true })
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef/files')
    renderApp()

    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    })
    expect(screen.getByRole('tab', { name: /Storyboard/ })).toBeEnabled()
  })

  it('shows the reconnecting banner and stops the upload when the connection is lost', async () => {
    stubFetch({ streamFails: true })
    renderApp()

    expect(await screen.findByText(/Connection lost/)).toBeInTheDocument()
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Upload new capture' })).toBeDisabled()
    })
    expect(screen.getByRole('button', { name: 'Export report' })).toBeDisabled()
  })

  it('marks the report of a stopped analysis as partial', async () => {
    stubFetch({ summary: { ...READY_CASE, status: 'failed', stage: 'extract', progress: 41 } })
    renderApp()

    await screen.findByText(/Results below are partial/)
    await userEvent.keyboard('{Control>}{Shift>}e{/Shift}{/Control}')

    const dialog = await screen.findByRole('dialog', { name: 'Export report' })
    expect(within(dialog).getByText('Report will be marked as partial.')).toBeInTheDocument()
  })

  it('counts the files that were never checked in the export dialog', async () => {
    stubFetch({ files: [{ ...FILE, verdict: undefined }] })
    renderApp()

    await screen.findByText('ftp_upload_png.pcap')
    await userEvent.keyboard('{Control>}{Shift>}e{/Shift}{/Control}')

    const dialog = await screen.findByRole('dialog', { name: 'Export report' })
    expect(within(dialog).getByText('1 files are still marked Not checked.')).toBeInTheDocument()
  })

  it('says in the file detail that a field was not recorded', async () => {
    stubFetch({
      files: [{ ...FILE, md5: '', sha256: '', magicHex: '' }],
    })
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef/files?file=1')
    renderApp()

    expect((await screen.findAllByText('Not recorded')).length).toBeGreaterThan(0)
  })
})
