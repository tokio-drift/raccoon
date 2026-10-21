import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App } from './App'
import { ToastProvider } from './components/primitives/Toast'
import type { RaccoonApi } from './api/api'
import { ManualEventStream } from './api/events'
import type { CaseEvent, CaseSummary, Page, ServerEvent } from './api/types'
import { loadPreferences } from './lib/preferences'

const RUNNING_CASE: CaseSummary = {
  id: '20260101-120000-abcdef',
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
  status: 'running',
  stage: 'process',
  progress: 62,
  durationNs: 0,
  packets: 18230,
  streams: 3,
  files: 5,
  events: 0,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '',
  error: '',
}

const READY_CASE: CaseSummary = {
  ...RUNNING_CASE,
  status: 'ready',
  stage: 'done',
  progress: 100,
  durationNs: 41_000_000_000,
  events: 43,
  finishedAt: '2026-01-01T12:00:41.000000000Z',
}

const CRITICAL_EVENT: CaseEvent = {
  id: 7,
  ts: '2026-01-01T12:00:10.000000000Z',
  packetNo: 10,
  packetEnd: 12,
  type: 'http.request',
  severity: 'critical',
  phase: 'action',
  streamId: 2,
  src: '10.0.0.1:51234',
  dst: '10.0.0.2:80',
  proto: 'http',
  title: 'Suspicious download',
  details: {},
  explain: 'The download matches a known threat.',
  parentId: 0,
  fileId: 0,
  findingIds: [],
}

interface FakeApi {
  api: RaccoonApi
  stream: ManualEventStream
  summary: () => CaseSummary
  setSummary: (summary: CaseSummary) => void
  upload: (file: File) => Promise<{ caseId: string }>
}

function makeApi(initial: CaseSummary = RUNNING_CASE): FakeApi {
  const stream = new ManualEventStream()
  let summary = initial
  const api = {
    getCase: async () => summary,
    listEvents: async (): Promise<Page<CaseEvent>> => ({
      items: [CRITICAL_EVENT],
      nextCursor: null,
    }),
    listFiles: async () => ({ items: [], nextCursor: null }),
    listStreams: async () => ({ items: [], nextCursor: null }),
    getStreamBytes: async () => ({
      streamId: 0,
      dir: 'c2s',
      offset: 0,
      length: 0,
      total: 0,
      dataBase64: '',
      segments: [],
      carved: [],
    }),
    getGraph: async () => ({ nodes: [], edges: [] }),
    getReportUrl: () => '/report.html',
    uploadCapture: async () => ({ caseId: '20260101-130000-newcase' }),
    downloadFile: async () => ({ blob: new Blob(), filename: 'file.bin' }),
    openEventStream: () => stream,
  } as unknown as RaccoonApi
  return {
    api,
    stream,
    summary: () => summary,
    setSummary: (next) => {
      summary = next
    },
    upload: async () => ({ caseId: '20260101-130000-newcase' }),
  }
}

describe('the upload flow of the empty dashboard', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    window.localStorage.clear()
    loadPreferences()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('opens the new case after the upload finished', async () => {
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )

    const input = screen.getByLabelText('Choose a capture file')
    fireEvent.change(input, { target: { files: [new File([new Uint8Array(16)], 'capture.pcap')] } })

    await waitFor(() =>
      expect(window.location.pathname).toBe('/case/20260101-130000-newcase/storyboard'),
    )
  })

  it('refuses a file that is not a capture', async () => {
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )

    const input = screen.getByLabelText('Choose a capture file')
    fireEvent.change(input, { target: { files: [new File([new Uint8Array(16)], 'notes.txt')] } })

    expect(
      await screen.findByText(
        "That doesn't look like a capture file. RACCOON reads .pcap and .pcapng files.",
      ),
    ).toBeInTheDocument()
    expect(window.location.pathname).toBe('/')
  })
})

describe('the live connection of a case', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    window.localStorage.clear()
    loadPreferences()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('warns when the connection drops and shows the attempt number', async () => {
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.stream.setState({ status: 'reconnecting', attempt: 2 })
    })

    expect(
      await screen.findByText('Connection lost. Reconnecting… (attempt 2)'),
    ).toBeInTheDocument()
    expect(within(screen.getByRole('banner')).getByRole('status')).toHaveTextContent(
      'Reconnecting…',
    )
  })

  it('asks for help when the connection does not come back', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.stream.setState({ status: 'reconnecting', attempt: 3 })
    })
    expect(await screen.findByText(/Connection lost/)).toBeInTheDocument()

    act(() => {
      vi.advanceTimersByTime(31000)
    })

    expect(await screen.findByText("Still can't reach RACCOON.")).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try now' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Copy diagnostic info' })).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('tries the connection again when the reader asks for it', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const fake = makeApi()
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.stream.setState({ status: 'reconnecting', attempt: 1 })
    })
    await screen.findByText(/Connection lost/)

    act(() => {
      vi.advanceTimersByTime(31000)
    })
    const reconnect = vi.spyOn(fake.stream, 'reconnect')
    await user.click(await screen.findByRole('button', { name: 'Try now' }))

    expect(reconnect).toHaveBeenCalled()
    vi.useRealTimers()
  })

  it('shows the age of the data in the status bar when the connection is quiet', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.stream.emit({
        name: 'progress',
        data: { stage: 'process', percent: 40, packets: 10, bytes: 100, streams: 1, files: 0 },
      } as ServerEvent)
      vi.advanceTimersByTime(600)
    })
    act(() => {
      vi.advanceTimersByTime(16000)
    })

    expect(await screen.findByText(/^Data as of \d\d:\d\d:\d\d UTC$/)).toBeInTheDocument()
    vi.useRealTimers()
  })

  it('shows the checking-files state while the timeline is ready', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.stream.emit({ name: 'ready', data: { events: 43, files: 5 } } as ServerEvent)
      vi.advanceTimersByTime(600)
    })

    expect(
      await screen.findByText('Timeline ready · checking files 0 of 5'),
    ).toBeInTheDocument()
    vi.useRealTimers()
  })
})

describe('the completion of an analysis', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    window.localStorage.clear()
    loadPreferences()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('announces the result and offers the first critical event', async () => {
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.setSummary(READY_CASE)
      fake.stream.emit({ name: 'done', data: { caseId: READY_CASE.id } } as ServerEvent)
    })

    expect(
      await screen.findByText(
        'Analysis complete. 43 events, 5 files, 3 streams, 1 critical event.',
        { exact: false },
      ),
    ).toBeInTheDocument()

    const banner = await screen.findByText(/Analysis finished in/)
    expect(banner).toBeInTheDocument()
    const button = screen.getByRole('button', { name: 'Go to first critical event' })
    await userEvent.setup().click(button)
    await waitFor(() =>
      expect(window.location.pathname).toBe('/case/20260101-120000-abcdef/storyboard'),
    )
    expect(window.location.search).toBe('?event=7')
  })

  it('points at the storyboard with a toast when the reader is on another tab', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef/files')
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    act(() => {
      fake.setSummary(READY_CASE)
      fake.stream.emit({ name: 'done', data: { caseId: READY_CASE.id } } as ServerEvent)
    })

    const toast = await screen.findByText('Analysis complete')
    expect(toast).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Open Storyboard' })).toBeInTheDocument()
  })

  it('moves the focus to the storyboard heading when the analysis finishes', async () => {
    const fake = makeApi()
    render(
      <ToastProvider>
        <App api={fake.api} />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')
    expect(screen.getByRole('heading', { name: 'Extracting files' })).toBeInTheDocument()

    act(() => {
      fake.setSummary(READY_CASE)
      fake.stream.emit({ name: 'done', data: { caseId: READY_CASE.id } } as ServerEvent)
    })

    const heading = await screen.findByRole('heading', { name: 'Storyboard' })
    await waitFor(() => expect(heading).toHaveFocus())
  })
})
