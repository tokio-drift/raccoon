import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from '../api/api'
import type { CaseEvent, CarvedFile, EventQuery, FileQuery, Page } from '../api/types'
import { StoryboardView } from './StoryboardView'

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

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function carvedFile(id: number): CarvedFile {
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
    verdict: {
      status: 'malicious',
      score: 12,
      total: 60,
      source: 'virustotal',
      checkedAt: '2026-01-01T12:00:00.000000000Z',
    },
  }
}

function makeApi(events: CaseEvent[], files: CarvedFile[] = []) {
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page(events))
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const api = { listEvents, listFiles } as unknown as RaccoonApi
  return { api, listEvents, listFiles }
}

function paneTitle(): string {
  const pane = screen.getByRole('complementary', { name: 'Event details' })
  return within(pane).getByRole('heading', { level: 2 }).textContent ?? ''
}

function renderView(
  api: RaccoonApi,
  overrides: Partial<React.ComponentProps<typeof StoryboardView>> = {},
) {
  const onParamsChange = vi.fn()
  const onOpenStreams = vi.fn()
  const view = render(
    <StoryboardView
      caseId={CASE_ID}
      api={api}
      totalEvents={null}
      params={{}}
      onParamsChange={onParamsChange}
      onOpenStreams={onOpenStreams}
      {...overrides}
    />,
  )
  return { ...view, onParamsChange, onOpenStreams }
}

beforeEach(() => {
  window.localStorage.clear()
  window.history.replaceState(null, '', `/case/${CASE_ID}/storyboard`)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('the storyboard view', () => {
  it('shows the events of the case in time order', async () => {
    const { api } = makeApi([event(1), event(2), event(3)])
    renderView(api)
    await waitFor(() => expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0))
    expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Event 2').length).toBeGreaterThan(0)
  })

  it('selects the first critical event and shows it in the detail pane', async () => {
    const { api } = makeApi([event(1, { severity: 'info' }), event(2, { severity: 'critical' })])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 2').length).toBeGreaterThan(0))
    expect(paneTitle()).toBe('Event 2')
  })

  it('shows the severity with a label and an icon, never with colour alone', async () => {
    const { api } = makeApi([event(1, { severity: 'critical' })])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    expect(screen.getAllByText('Critical').length).toBeGreaterThan(0)
  })

  it('shows the ordered sections of the detail pane', async () => {
    const { api } = makeApi(
      [
        event(1, {
          severity: 'critical',
          explain: 'The client sent a password in cleartext.',
          details: { method: 'GET', url: 'http://example.test/secret' },
          fileId: 7,
          findingIds: [9],
        }),
        event(9, { type: 'FINDING', title: 'Brute force', findingIds: [] }),
      ],
      [carvedFile(7)],
    )
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    const pane = screen.getByRole('complementary', { name: 'Event details' })
    const headings = within(pane)
      .getAllByRole('heading', { level: 3 })
      .map((heading) => heading.textContent)
    expect(headings).toEqual([
      'In plain words',
      'Details',
      'Evidence',
      'Related file',
      'Related findings',
    ])
  })

  it('shows the related file with its verdict and a way to open it', async () => {
    const { api } = makeApi([event(1, { fileId: 7 })], [carvedFile(7)])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    const pane = screen.getByRole('complementary', { name: 'Event details' })
    expect(within(pane).getByText('secret.png')).toBeInTheDocument()
    expect(within(pane).getByText('Malicious')).toBeInTheDocument()
    expect(within(pane).getByRole('button', { name: 'Open file' })).toBeInTheDocument()
  })

  it('shows the evidence chips of the event', async () => {
    const { api } = makeApi([event(1, { packetNo: 42, packetEnd: 44, streamId: 3 })])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    const pane = screen.getByRole('complementary', { name: 'Event details' })
    expect(within(pane).getByRole('button', { name: /pkts 42/ })).toBeInTheDocument()
    expect(within(pane).getByRole('button', { name: /Stream 3/ })).toBeInTheDocument()
  })

  it('opens the stream of the event from its evidence chip', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([event(1, { packetNo: 42, packetEnd: 44, streamId: 3 })])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    const pane = screen.getByRole('complementary', { name: 'Event details' })
    await user.click(within(pane).getByRole('button', { name: /pkts 42/ }))
    expect(window.location.pathname).toBe(`/case/${CASE_ID}/streams`)
    expect(window.location.search).toContain('stream=3')
  })

  it('renders a hostile title as inert text', async () => {
    const { api } = makeApi([
      event(1, { title: '<script>window.__pwned = true</script>' }),
    ])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText(/<script>/).length).toBeGreaterThan(0))
    expect((window as unknown as { __pwned?: boolean }).__pwned).toBeUndefined()
  })

  it('masks a credential in the details and can reveal it', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([
      event(1, { type: 'FTP_LOGIN_FAILED', details: { user: 'bob', password: 'hunter2' } }),
    ])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    expect(screen.queryByText('hunter2')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Show password' })).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(screen.getByText('hunter2')).toBeInTheDocument()
  })

  it('shows the empty state when the case has no events', async () => {
    const { api } = makeApi([])
    const { onOpenStreams } = renderView(api)
    await waitFor(() => expect(screen.getByText('No events in this capture')).toBeInTheDocument())
    screen.getByRole('button', { name: 'Open Streams' }).click()
    expect(onOpenStreams).toHaveBeenCalled()
  })

  it('shows the partial banner while the analysis is still running', async () => {
    const { api } = makeApi([event(1)])
    renderView(api, { partial: true })
    await waitFor(() => expect(screen.getByText(/Showing partial results/)).toBeInTheDocument())
    expect(screen.getByText(/1 events so far/)).toBeInTheDocument()
  })

  it('writes the filters into the address bar and keeps the deep link', async () => {
    const { api } = makeApi([event(1, { severity: 'critical' })])
    const { onParamsChange } = renderView(api, { params: { event: '1', sev: 'critical' } })
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    expect(onParamsChange).toHaveBeenCalled()
    const last = onParamsChange.mock.calls.at(-1)?.[0] as Record<string, string>
    expect(last.sev).toBe('critical')
    // The deep link is not part of the filter parameters.
    expect(last.event).toBeUndefined()
  })

  it('waits 250 ms before the search filters the list', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([event(1), event(2, { title: 'Login failed' })])
    const onParamsChange = vi.fn()
    renderView(api, { onParamsChange })
    await waitFor(() => expect(screen.getAllByText('Login failed').length).toBeGreaterThan(0))
    const before = onParamsChange.mock.calls.length
    await user.type(screen.getByRole('searchbox', { name: 'Search events' }), 'login')
    expect(onParamsChange.mock.calls.length).toBe(before)
    await waitFor(() => expect(onParamsChange.mock.calls.length).toBeGreaterThan(before), {
      timeout: 2000,
    })
    const last = onParamsChange.mock.calls.at(-1)?.[0] as Record<string, string>
    expect(last.q).toBe('login')
  })

  it('moves the selection with the keyboard', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([event(1), event(2), event(3)])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    await user.keyboard('{ArrowDown}')
    expect(paneTitle()).toBe('Event 2')
    await user.keyboard('j')
    expect(paneTitle()).toBe('Event 3')
    await user.keyboard('k')
    expect(paneTitle()).toBe('Event 2')
  })

  it('moves the focus into the detail pane with Enter and back with Escape', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([event(1)])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    const pane = screen.getByRole('complementary', { name: 'Event details' })
    await user.keyboard('{Enter}')
    expect(pane).toHaveFocus()
    await user.keyboard('{Escape}')
    expect(pane).not.toHaveFocus()
  })

  it('focuses the search field with the slash key', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([event(1)])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    await user.keyboard('/')
    expect(screen.getByRole('searchbox', { name: 'Search events' })).toHaveFocus()
  })

  it('jumps to the next critical event with the bracket keys', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([
      event(1, { severity: 'info' }),
      event(2, { severity: 'critical' }),
      event(3, { severity: 'critical' }),
    ])
    renderView(api)
    await waitFor(() => expect(screen.getAllByText('Event 1').length).toBeGreaterThan(0))
    // The first critical event is selected when the view opens.
    expect(paneTitle()).toBe('Event 2')
    await user.keyboard(']')
    expect(paneTitle()).toBe('Event 3')
    fireEvent.keyDown(document.body, { key: '[' })
    await waitFor(() => expect(paneTitle()).toBe('Event 2'))
  })

  it('renders a capture of five thousand events without rendering every card', async () => {
    const events = Array.from({ length: 5000 }, (_, index) => event(index + 1))
    const { api } = makeApi(events)
    const started = Date.now()
    renderView(api)
    await waitFor(() => expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0), {
      timeout: 10_000,
    })
    const elapsed = Date.now() - started
    // The feed is virtualised: the DOM holds a window, not the whole case.
    expect(screen.getAllByRole('listitem').length).toBeLessThan(200)
    expect(elapsed).toBeLessThan(8000)
  }, 20_000)

  it('filters a capture of five thousand events in one pass', async () => {
    const events = Array.from({ length: 5000 }, (_, index) =>
      event(index + 1, { severity: index % 50 === 0 ? 'critical' : 'info' }),
    )
    const { api } = makeApi(events)
    renderView(api, { params: { sev: 'critical' } })
    await waitFor(() => expect(screen.getAllByRole('listitem').length).toBeGreaterThan(0), {
      timeout: 10_000,
    })
    expect(screen.getByText('100 of 5000 events')).toBeInTheDocument()
  }, 20_000)
})
