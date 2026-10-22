import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App } from './App'
import { ToastProvider } from './components/primitives/Toast'
import type { RaccoonApi } from './api/api'
import type { CarvedFile, CaseSummary, EventQuery, FileQuery, Page } from './api/types'
import { loadPreferences } from './lib/preferences'
import { FilesView } from './views/FilesView'

/**
 * The interaction rules of UI_Design.md §16: what the reader reaches in two
 * actions, what a view keeps, and what the export and the theme do.
 */

const CASE_ID = '20260101-120000-abcdef'

const READY_CASE: CaseSummary = {
  id: CASE_ID,
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
  status: 'ready',
  stage: 'done',
  progress: 100,
  durationNs: 2_450_000_000,
  packets: 42,
  streams: 1,
  files: 1,
  events: 1,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '2026-01-01T12:00:02.450000000Z',
  error: '',
}

const CRITICAL_EVENT = {
  id: 7,
  ts: '2026-01-01T12:00:01.000000000Z',
  packetNo: 1,
  packetEnd: 1,
  type: 'FTP_FILE_TRANSFER',
  severity: 'critical',
  phase: 'transfer',
  streamId: 1,
  src: '192.0.2.14:51822',
  dst: '192.0.2.50:21',
  proto: 'ftp',
  title: 'A file was uploaded',
  details: { filename: 'secret.png' },
  explain: '',
  parentId: 0,
  fileId: 1,
  findingIds: [],
}

const FILE: CarvedFile = {
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
  displayName: 'secret.png',
  path: 'carved/secret.png',
  magicHex: '89504e47',
  verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' },
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

function stubFetch() {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/events/stream')) return sseResponse()
      if (url.includes('/events') && !url.includes('/events/stream')) {
        return jsonResponse({ items: [CRITICAL_EVENT], nextCursor: null })
      }
      if (url.includes('/files')) return jsonResponse({ items: [FILE], nextCursor: null })
      if (url.includes('/streams')) return jsonResponse({ items: [], nextCursor: null })
      return jsonResponse(READY_CASE)
    }),
  )
}

function renderApp(): { unmount: () => void } {
  return render(
    <ToastProvider>
      <App />
    </ToastProvider>,
  )
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function makeApi(files: CarvedFile[] = [FILE]) {
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page([]))
  const api = {
    listFiles,
    listEvents,
    listStreams: vi.fn(async () => page([])),
    downloadFile: vi.fn(async () => ({ blob: new Blob(['x']), filename: 'server.exe' })),
  } as unknown as RaccoonApi
  return { api, listFiles }
}

function renderFilesView(api: RaccoonApi, overrides: Partial<React.ComponentProps<typeof FilesView>> = {}) {
  const onParamsChange = vi.fn()
  const onOpenStreams = vi.fn()
  const view = render(
    <FilesView
      caseId={CASE_ID}
      api={api}
      params={{}}
      onParamsChange={onParamsChange}
      verdicts={{}}
      onOpenStreams={onOpenStreams}
      {...overrides}
    />,
  )
  return { ...view, onParamsChange, onOpenStreams }
}

function rows(): HTMLElement[] {
  return screen.getAllByRole('row').filter((row) => row.dataset.fileId !== undefined)
}

beforeEach(() => {
  window.localStorage.clear()
  loadPreferences()
  window.history.replaceState({}, '', `/case/${CASE_ID}/storyboard`)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('the evidence is two actions away (UI_Design.md §16)', () => {
  it('opens a finished case on the storyboard with the first critical event selected', async () => {
    stubFetch()
    renderApp()

    const tab = await screen.findByRole('tab', { name: /Storyboard/ })
    expect(tab).toHaveAttribute('aria-selected', 'true')
    const detail = await screen.findByRole('complementary', { name: 'Event details' })
    expect(within(detail).getByText('A file was uploaded')).toBeInTheDocument()
  })

  it('opens the bytes of a file in the streams view, from the file gallery', async () => {
    const user = userEvent.setup()
    const { api } = makeApi()
    renderFilesView(api)
    await waitFor(() => expect(rows().length).toBe(1))

    await user.click(screen.getByTitle('secret.png'))
    await user.click(await screen.findByRole('button', { name: 'Show in stream' }))

    // The view asks for the stream, the direction and the byte of the file.
    expect(window.location.pathname).toBe(`/case/${CASE_ID}/streams`)
    expect(window.location.search).toBe('?stream=1&dir=c2s&offset=0')
  })

  it('keeps the selection of a file when the gallery is opened again', async () => {
    const user = userEvent.setup()
    const { api } = makeApi()
    const first = renderFilesView(api)
    await waitFor(() => expect(rows().length).toBe(1))

    await user.click(screen.getByTitle('secret.png'))
    expect(screen.getByRole('complementary', { name: 'File details' })).toBeInTheDocument()
    // The selection is remembered per case, so it survives a reload (§6.7).
    first.unmount()
    renderFilesView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByRole('complementary', { name: 'File details' })).toBeInTheDocument()
  })

  it('resets the file gallery: the filters, the search and the selection', async () => {
    const user = userEvent.setup()
    const { api } = makeApi()
    renderFilesView(api)
    await waitFor(() => expect(rows().length).toBe(1))

    await user.click(screen.getByTitle('secret.png'))
    expect(screen.getByRole('complementary', { name: 'File details' })).toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Reset view' }))
    expect(screen.queryByRole('complementary', { name: 'File details' })).toBeNull()
    expect(rows().length).toBe(1)
  })
})

describe('the export and the theme (UI_Design.md §16)', () => {
  it('returns the focus to the export control when the dialog closes', async () => {
    stubFetch()
    const user = userEvent.setup()
    renderApp()
    await screen.findByText('ftp_upload_png.pcap')

    const exportButton = screen.getByRole('button', { name: /Export report/ })
    await user.click(exportButton)
    const dialog = await screen.findByRole('dialog', { name: 'Export report' })
    await user.keyboard('{Escape}')
    await waitFor(() => expect(dialog).not.toBeInTheDocument())
    expect(document.activeElement).toBe(exportButton)
  })

  it('keeps the theme choice when the app is opened again', async () => {
    stubFetch()
    const user = userEvent.setup()
    const first = renderApp()
    await screen.findByText('ftp_upload_png.pcap')

    await user.click(within(screen.getByRole('banner')).getByRole('button', { name: 'Settings' }))
    await user.click(await screen.findByRole('radio', { name: 'Dark' }))
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
    first.unmount()

    renderApp()
    await screen.findByText('ftp_upload_png.pcap')
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
  })
})
