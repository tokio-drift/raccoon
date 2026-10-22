import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from './api/api'
import type { CaseEvent, CarvedFile, EventQuery, FileQuery, Page } from './api/types'
import { App } from './App'
import { ToastProvider } from './components/primitives/Toast'
import { FilesView } from './views/FilesView'
import { StoryboardView } from './views/StoryboardView'

/**
 * The edge cases of UI_Design.md §16: what the views show when the data is
 * incomplete, unknown or hostile, and the promise that nothing leaves the
 * machine.
 */

const CASE_ID = '20260101-120000-abcdef'
const START = Date.parse('2026-01-01T12:00:00.000Z')

function event(id: number, overrides: Partial<CaseEvent> = {}): CaseEvent {
  return {
    id,
    ts: new Date(START + id * 1000).toISOString().replace('Z', '000000Z'),
    packetNo: id,
    packetEnd: id,
    type: 'HTTP_TRANSACTION',
    severity: 'info',
    phase: 'access',
    streamId: 1,
    src: '192.0.2.14:51822',
    dst: '192.0.2.50:80',
    proto: 'http',
    title: `Event ${id}`,
    details: {},
    explain: '',
    parentId: 0,
    fileId: 0,
    findingIds: [],
    ...overrides,
  }
}

function carvedFile(id: number, overrides: Partial<CarvedFile> = {}): CarvedFile {
  return {
    id,
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
    ...overrides,
  }
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function makeApi(events: CaseEvent[] = [], files: CarvedFile[] = []) {
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page(events))
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const api = { listEvents, listFiles, listStreams: vi.fn(async () => page([])) } as unknown as RaccoonApi
  return { api, listEvents, listFiles }
}

function renderStoryboard(api: RaccoonApi) {
  return render(
    <StoryboardView
      caseId={CASE_ID}
      api={api}
      totalEvents={null}
      params={{}}
      onParamsChange={vi.fn()}
      onOpenStreams={vi.fn()}
    />,
  )
}

function renderFiles(api: RaccoonApi) {
  return render(
    <FilesView
      caseId={CASE_ID}
      api={api}
      params={{}}
      onParamsChange={vi.fn()}
      verdicts={{}}
      onOpenStreams={vi.fn()}
    />,
  )
}

function rows(): HTMLElement[] {
  return screen.getAllByRole('row').filter((row) => row.dataset.fileId !== undefined)
}

/** Opens the detail pane of the only event of the list. */
async function openPane(): Promise<HTMLElement> {
  const card = await screen.findByRole('listitem')
  await userEvent.setup().click(card)
  const pane = await screen.findByRole('complementary', { name: 'Event details' })
  await within(pane).findByRole('heading', { level: 2 })
  return pane
}

beforeEach(() => {
  window.localStorage.clear()
  window.history.replaceState(null, '', `/case/${CASE_ID}/storyboard`)
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('unknown event types (UI_Design.md §5.12, §16)', () => {
  it('shows a generic card with a dashed mark and the raw type in the pane', async () => {
    const { api } = makeApi([event(1, { type: 'WEIRD_PACKET_KIND', title: 'Something happened' })])
    renderStoryboard(api)

    const card = await screen.findByText('Something happened')
    expect(card.closest('article')).not.toBeNull()
    // The type chip shows the raw type in plain words.
    expect(screen.getAllByText('WEIRD PACKET KIND').length).toBeGreaterThan(0)
    // The generic card carries the dashed mark of an unknown type.
    const mark = document.querySelector('.event-card__unknown-type')
    expect(mark).not.toBeNull()

    const pane = await openPane()
    const other = within(pane).getByText('Other details')
    expect(other).toBeInTheDocument()
    expect(within(pane).getByRole('rowheader', { name: 'type' })).toBeInTheDocument()
    expect(within(pane).getByText('WEIRD_PACKET_KIND')).toBeInTheDocument()
  })

  it('shows a type that is not a plain name as "Other event"', async () => {
    const scripts = document.querySelectorAll('script').length
    const { api } = makeApi([event(1, { type: '<script>alert(1)</script>' })])
    renderStoryboard(api)

    expect(await screen.findByText('Other event')).toBeInTheDocument()
    // The raw type is inert text in the detail pane and never markup.
    const pane = await openPane()
    expect(within(pane).getAllByText('<script>alert(1)</script>').length).toBeGreaterThan(0)
    expect(document.querySelectorAll('script')).toHaveLength(scripts)
  })

  it('lists the unknown detail keys in alphabetical order', async () => {
    const { api } = makeApi([
      event(1, { type: 'WEIRD_PACKET_KIND', details: { zebra: 'z', alpha: 'a', middle: 'm' } }),
    ])
    renderStoryboard(api)

    const pane = await openPane()
    const headers = within(pane).getAllByRole('rowheader').map((cell) => cell.textContent)
    expect(headers).toEqual(['alpha', 'middle', 'zebra', 'type'])
  })
})

describe('missing timestamps, titles and severities (UI_Design.md §5.12, §16)', () => {
  it('says "Time unknown" and puts the event under a "Not dated" separator', async () => {
    const { api } = makeApi([
      event(1, { id: 2, ts: '', packetNo: 4, title: 'An undated event' }),
    ])
    renderStoryboard(api)

    expect(await screen.findByText('Time unknown')).toBeInTheDocument()
    expect(screen.getByText('Not dated')).toBeInTheDocument()
  })

  it('shows the type words in the title slot when the event has no title', async () => {
    const { api } = makeApi([event(1, { title: '' })])
    renderStoryboard(api)

    const pane = await openPane()
    const heading = within(pane).getByRole('heading', { level: 2 })
    expect(heading).toHaveTextContent('HTTP transaction')
    expect(heading.className).toContain('storyboard-detail__title--muted')
  })

  it('labels a missing severity as "Info (not specified)"', async () => {
    const { api } = makeApi([event(1, { severity: '' as never })])
    renderStoryboard(api)

    const pane = await openPane()
    expect(within(pane).getByText('Info (not specified)')).toBeInTheDocument()
  })

  it('says when no packet evidence was recorded', async () => {
    const { api } = makeApi([event(1, { packetNo: 0, packetEnd: 0, streamId: 0 })])
    renderStoryboard(api)

    const pane = await openPane()
    expect(
      within(pane).getByText('No packet evidence was recorded for this event.'),
    ).toBeInTheDocument()
  })
})

describe('incomplete files (UI_Design.md §16)', () => {
  it('names a truncated file "Incomplete" and a corrupt file "Corrupt"', async () => {
    const { api } = makeApi([], [
      carvedFile(1, { displayName: 'cut.png', status: 'truncated' }),
      carvedFile(2, { displayName: 'broken.png', status: 'corrupt' }),
    ])
    renderFiles(api)
    await waitFor(() => expect(rows().length).toBe(2))

    expect(screen.getByText('Incomplete')).toBeInTheDocument()
    expect(screen.getByText('Corrupt')).toBeInTheDocument()
  })

  it('hides the low-confidence files and offers to show them', async () => {
    const { api } = makeApi([], [carvedFile(1, { displayName: 'maybe.png', confidence: 'low' })])
    renderFiles(api)
    await waitFor(() => expect(screen.getByText(/hidden/)).toBeInTheDocument())

    await userEvent.setup().click(screen.getByRole('button', { name: 'Show low-confidence files' }))
    await waitFor(() => expect(rows().length).toBe(1))
  })
})

describe('hostile and long values (UI_Design.md §12.9, §16)', () => {
  it('shows a long IPv6 address elided in the middle, with the full value in the tooltip', async () => {
    const address = '[2001:0db8:85a3:0000:0000:8a2e:0370:7334]:443'
    const { api } = makeApi([event(1, { src: address, dst: '192.0.2.50:80' })])
    renderStoryboard(api)

    const card = await screen.findByText(/2001:0db8/)
    expect(card.textContent).toContain('…')
    expect(card.textContent).toContain(':7334]:443')
    // The full value is still available in the tooltip.
    const tooltip = document.querySelector('[title*="2001:0db8:85a3:0000"]')
    expect(tooltip?.getAttribute('title')).toContain(address)
  })

  it('shows a long URL as inert text and never as a link', async () => {
    const url = `http://files.test/${'a'.repeat(120)}/report.php?id=7`
    const { api } = makeApi([
      event(1, { type: 'HTTP_TRANSACTION', details: { method: 'GET', url } }),
    ])
    renderStoryboard(api)

    const pane = await openPane()
    expect(within(pane).getByText(/report\.php\?id=7/)).toBeInTheDocument()
    expect(within(pane).queryByRole('link')).toBeNull()
    expect(document.querySelector('a[href^="http"]')).toBeNull()
  })

  it('keeps a path-like file name as text and never as a path', async () => {
    const { api } = makeApi([], [carvedFile(1, { displayName: '../../etc/passwd' })])
    renderFiles(api)
    await waitFor(() => expect(rows().length).toBe(1))

    expect(screen.getByText('Path-like name')).toBeInTheDocument()
    expect(document.querySelector('a[href*="etc/passwd"]')).toBeNull()
  })
})

describe('nothing leaves the machine (UI_Design.md §16)', () => {
  it('calls the local server and nothing else, and loads no remote asset', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/events/stream')) {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(': heartbeat\n\n'))
          },
        })
        return { ok: true, status: 200, statusText: 'test', body, json: async () => ({}) } as unknown as Response
      }
      if (url.includes('/events')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      if (url.includes('/files')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      if (url.includes('/streams')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      return {
        ok: true,
        status: 200,
        statusText: 'test',
        json: async () => ({
          id: CASE_ID,
          fileName: 'ftp_upload_png.pcap',
          size: 48213,
          pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
          status: 'ready',
          stage: 'done',
          progress: 100,
          durationNs: 2450000000,
          packets: 42,
          streams: 1,
          files: 1,
          events: 1,
          toolVersion: 'devel',
          startedAt: '2026-01-01T12:00:00.000000000Z',
          finishedAt: '2026-01-01T12:00:02.450000000Z',
          error: '',
        }),
      } as unknown as Response
    })
    vi.stubGlobal('fetch', fetchMock)

    render(
      <ToastProvider>
        <App />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')
    await waitFor(() => expect(fetchMock).toHaveBeenCalled())

    for (const call of fetchMock.mock.calls) {
      const url = String(call[0])
      expect(url.startsWith('/') || url.startsWith(window.location.origin)).toBe(true)
    }
    for (const node of document.querySelectorAll('script[src], link[href], img[src]')) {
      const source = node.getAttribute('src') ?? node.getAttribute('href') ?? ''
      expect(source.startsWith('http')).toBe(false)
    }
  })

  it('shows the time basis and never a time relative to now', async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/events/stream')) {
        const body = new ReadableStream<Uint8Array>({
          start(controller) {
            controller.enqueue(new TextEncoder().encode(': heartbeat\n\n'))
          },
        })
        return { ok: true, status: 200, statusText: 'test', body, json: async () => ({}) } as unknown as Response
      }
      if (url.includes('/events')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      if (url.includes('/files')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      if (url.includes('/streams')) return { ok: true, status: 200, statusText: 'test', json: async () => page([]) } as unknown as Response
      return {
        ok: true,
        status: 200,
        statusText: 'test',
        json: async () => ({
          id: CASE_ID,
          fileName: 'ftp_upload_png.pcap',
          size: 48213,
          pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
          status: 'ready',
          stage: 'done',
          progress: 100,
          durationNs: 2450000000,
          packets: 42,
          streams: 1,
          files: 1,
          events: 1,
          toolVersion: 'devel',
          startedAt: '2026-01-01T12:00:00.000000000Z',
          finishedAt: '2026-01-01T12:00:02.450000000Z',
          error: '',
        }),
      } as unknown as Response
    })
    vi.stubGlobal('fetch', fetchMock)

    render(
      <ToastProvider>
        <App />
      </ToastProvider>,
    )
    await screen.findByText('ftp_upload_png.pcap')

    const status = document.querySelector('.status-bar') as HTMLElement
    expect(status).not.toBeNull()
    expect(status).toHaveTextContent(/UTC|local/)
    expect(status.textContent).not.toMatch(/ago|just now/)
  })
})
