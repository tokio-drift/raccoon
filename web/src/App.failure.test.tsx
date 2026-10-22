import { act, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App } from './App'
import { ToastProvider } from './components/primitives/Toast'
import type { RaccoonApi } from './api/api'
import { ApiError } from './api/client'
import { ManualEventStream } from './api/events'
import type { CarvedFile, CaseSummary, ServerEvent } from './api/types'
import { loadPreferences } from './lib/preferences'
import { setSessionToken } from './lib/token'

const FAILED_CASE: CaseSummary = {
  id: '20260101-120000-abcdef',
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
  status: 'failed',
  stage: 'extract',
  progress: 41,
  durationNs: 12_000_000_000,
  packets: 18230,
  streams: 0,
  files: 0,
  events: 0,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '2026-01-01T12:00:12.000000000Z',
  error: 'extractor_failed',
}

const FAILED_CASE_WITH_DATA: CaseSummary = {
  ...FAILED_CASE,
  files: 2,
  events: 18,
  streams: 3,
}

interface FakeApi {
  api: RaccoonApi
  stream: ManualEventStream
  files: CarvedFile[]
}

function makeApi(summary: CaseSummary = FAILED_CASE): FakeApi {
  const stream = new ManualEventStream()
  const files: CarvedFile[] = [
    {
      id: 4,
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
      displayName: 'invoice.zip',
      path: 'carved/invoice.zip',
      magicHex: '89504e47',
    },
  ]
  const api = {
    getCase: async () => summary,
    listEvents: async () => ({ items: [], nextCursor: null }),
    listFiles: async () => ({ items: files, nextCursor: null }),
    listStreams: async () => ({ items: [], nextCursor: null }),
    getStreamBytes: async () => ({
      streamId: 0,
      dir: 'c2s',
      offset: 0,
      length: 0,
      total: 0,
      dataBase64: '',
      segments: [],
      gaps: [],
      carved: [],
    }),
    getGraph: async () => ({ nodes: [], edges: [] }),
    getReportUrl: () => '/report.html',
    uploadCapture: async () => ({ caseId: '20260101-130000-newcase' }),
    downloadFile: async () => ({ blob: new Blob(), filename: 'file.bin' }),
    openEventStream: () => stream,
  } as unknown as RaccoonApi
  return { api, stream, files }
}

function renderApp(api: RaccoonApi): void {
  render(
    <ToastProvider>
      <App api={api} />
    </ToastProvider>,
  )
}

describe('the failure states of a case', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    window.localStorage.clear()
    loadPreferences()
    setSessionToken(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setSessionToken(null)
  })

  it('shows the failure page when the analysis failed without usable data', async () => {
    const { api } = makeApi(FAILED_CASE)
    renderApp(api)

    expect(await screen.findByRole('heading', { name: 'Analysis failed' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Choose another capture' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy diagnostic info' })).toBeInTheDocument()
  })

  it('hides the tabs of a case that failed', async () => {
    const { api } = makeApi(FAILED_CASE)
    renderApp(api)

    await screen.findByRole('heading', { name: 'Analysis failed' })
    expect(screen.queryByRole('tab', { name: 'Storyboard' })).toBeNull()
    expect(screen.queryByRole('tab', { name: 'Files' })).toBeNull()
  })

  it('keeps the technical details of the failure behind a toggle', async () => {
    const { api } = makeApi(FAILED_CASE)
    renderApp(api)

    await screen.findByRole('heading', { name: 'Analysis failed' })
    expect(screen.queryByText('extractor_failed')).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: /Technical details/ }))

    expect(await screen.findByText('extractor_failed')).toBeInTheDocument()
    expect(screen.getAllByText('ftp_upload_png.pcap').length).toBeGreaterThan(0)
  })

  it('keeps the results and shows the partial banner when some data survived', async () => {
    const { api } = makeApi(FAILED_CASE_WITH_DATA)
    renderApp(api)

    expect(
      await screen.findByText(/Analysis stopped at "extract"/),
    ).toBeInTheDocument()
    expect(screen.getByText(/Results below are partial/)).toBeInTheDocument()
    expect(screen.queryByRole('heading', { name: 'Analysis failed' })).toBeNull()
  })

  it('shows the technical detail of the partial failure when the reader asks for it', async () => {
    const { api } = makeApi(FAILED_CASE_WITH_DATA)
    renderApp(api)

    await screen.findByText(/Analysis stopped at "extract"/)
    await userEvent.click(screen.getByRole('button', { name: 'See what went wrong' }))

    expect(await screen.findByText(/extractor_failed/)).toBeInTheDocument()
  })

  it('marks the views of a stopped analysis as partial', async () => {
    const { api } = makeApi(FAILED_CASE_WITH_DATA)
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef/files')
    renderApp(api)

    expect(await screen.findByText('Partial')).toBeInTheDocument()
  })

  it('raises the incident strip when a file becomes malicious', async () => {
    const { api, stream } = makeApi({
      ...FAILED_CASE_WITH_DATA,
      status: 'ready',
      stage: 'done',
      progress: 100,
    })
    renderApp(api)

    await screen.findByText('ftp_upload_png.pcap')
    act(() => {
      stream.emit({
        name: 'verdict',
        data: { fileId: 4, sha256: 'abc', status: 'malicious' },
      } as ServerEvent)
    })

    const strip = await screen.findByRole('alert')
    expect(strip.textContent).toContain('Critical: invoice.zip now has a Malicious verdict.')
    expect(screen.getByRole('button', { name: 'View' })).toBeInTheDocument()
  })

  it('keeps the incident strip until the reader dismisses it', async () => {
    const { api, stream } = makeApi({
      ...FAILED_CASE_WITH_DATA,
      status: 'ready',
      stage: 'done',
      progress: 100,
    })
    renderApp(api)

    await screen.findByText('ftp_upload_png.pcap')
    act(() => {
      stream.emit({
        name: 'verdict',
        data: { fileId: 4, sha256: 'abc', status: 'malicious' },
      } as ServerEvent)
    })

    await screen.findByRole('alert')
    await userEvent.click(screen.getByRole('button', { name: 'Dismiss' }))

    await waitFor(() => {
      expect(screen.queryByRole('alert')).toBeNull()
    })
  })
})

describe('the session states', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    window.localStorage.clear()
    loadPreferences()
    setSessionToken(null)
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    setSessionToken(null)
  })

  it('asks for the private link when the page was opened without a token', async () => {
    const { api } = makeApi()
    vi.spyOn(console, 'error').mockImplementation(() => undefined)
    vi.spyOn(api, 'getCase').mockRejectedValue(
      new ApiError(401, 'unauthorized', 'the session token is not valid'),
    )

    renderApp(api)

    expect(
      await screen.findByRole('heading', { name: 'This dashboard needs its private link' }),
    ).toBeInTheDocument()
  })

  it('says that the session has ended when the token was refused', async () => {
    const { api } = makeApi()
    setSessionToken('old-token')
    vi.spyOn(api, 'getCase').mockRejectedValue(
      new ApiError(401, 'unauthorized', 'the session token is not valid'),
    )

    renderApp(api)

    expect(
      await screen.findByRole('heading', { name: 'This dashboard session has ended' }),
    ).toBeInTheDocument()
  })

  it('never puts the token in the diagnostic text of the session page', async () => {
    const { api } = makeApi()
    setSessionToken('secret-token')
    vi.spyOn(api, 'getCase').mockRejectedValue(
      new ApiError(401, 'unauthorized', 'the session token is not valid'),
    )
    const writeText = vi.fn(async (_text: string) => undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })

    renderApp(api)

    await screen.findByRole('heading', { name: 'This dashboard session has ended' })
    await userEvent.click(screen.getByRole('button', { name: 'Copy diagnostic info' }))

    await waitFor(() => {
      expect(writeText).toHaveBeenCalled()
    })
    const copied = String(writeText.mock.calls[0]?.[0] ?? '')
    expect(copied).not.toContain('secret-token')
    expect(document.body.innerHTML).not.toContain('secret-token')
  })
})
