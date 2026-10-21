import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { App } from './App'
import type { CaseSummary } from './api/types'
import { loadPreferences } from './lib/preferences'

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
  files: 5,
  events: 40,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '2026-01-01T12:00:02.450000000Z',
  error: '',
}

function jsonResponse(body: unknown, status = 200): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'test',
    json: async () => body,
  } as unknown as Response
}

/** A response that stays open, like the event stream of the server. */
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

function stubFetch(handler: (url: string) => Response | Promise<Response>) {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input)
      if (url.includes('/events/stream')) return sseResponse()
      return handler(url)
    }),
  )
}

describe('app shell', () => {
  beforeEach(() => {
    window.history.replaceState({}, '', '/')
    window.localStorage.clear()
    loadPreferences()
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('shows the empty dashboard at the root', () => {
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Follow the trail.' })).toBeInTheDocument()
  })

  it('keeps the empty dashboard header to the wordmark, Settings and Help', () => {
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    const banner = screen.getByRole('banner')
    expect(within(banner).getByText('RACCOON')).toBeInTheDocument()
    expect(within(banner).getByRole('button', { name: 'Settings' })).toBeInTheDocument()
    expect(within(banner).getByRole('button', { name: 'Help' })).toBeInTheDocument()
    expect(within(banner).queryByRole('button', { name: /Upload new capture/ })).not.toBeInTheDocument()
    expect(within(banner).queryByRole('button', { name: /Export report/ })).not.toBeInTheDocument()
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument()
  })

  it('applies the theme chosen in the settings popover', async () => {
    stubFetch(() => jsonResponse(READY_CASE))
    const user = userEvent.setup()
    render(<App />)

    await user.click(within(screen.getByRole('banner')).getByRole('button', { name: 'Settings' }))
    expect(await screen.findByRole('dialog', { name: 'Settings' })).toBeInTheDocument()
    await user.click(screen.getByRole('radio', { name: 'Dark' }))
    expect(document.documentElement).toHaveAttribute('data-theme', 'dark')
  })

  it('shows the case name, the tabs and the status pill', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)

    expect(await screen.findByText('ftp_upload_png.pcap')).toBeInTheDocument()
    const tabs = screen.getByRole('tablist', { name: 'Case views' })
    expect(within(tabs).getByRole('tab', { name: /Storyboard/ })).toBeInTheDocument()
    expect(within(tabs).getByRole('tab', { name: /Files/ })).toBeInTheDocument()
    expect(within(tabs).getByRole('tab', { name: /Streams/ })).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveTextContent('Ready')
  })

  it('never offers the reserved graph tab', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')
    expect(screen.queryByRole('tab', { name: /Graph/ })).not.toBeInTheDocument()
  })

  it('keeps the export control disabled until the report exists', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')
    expect(screen.getByRole('button', { name: /Export report/ })).toBeDisabled()
  })

  it('navigates between the case tabs', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    stubFetch(() => jsonResponse(READY_CASE))
    const user = userEvent.setup()
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')

    await user.click(screen.getByRole('tab', { name: /Files/ }))
    await waitFor(() => expect(window.location.pathname).toBe('/case/20260101-120000-abcdef/files'))
    expect(screen.getByRole('tab', { name: /Files/ })).toHaveAttribute('aria-selected', 'true')
  })

  it('opens the help drawer, closes it with Escape and returns the focus', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    stubFetch(() => jsonResponse(READY_CASE))
    const user = userEvent.setup()
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')

    const helpButton = within(screen.getByRole('banner')).getByRole('button', { name: 'Help' })
    await user.click(helpButton)
    expect(await screen.findByRole('dialog', { name: 'Help' })).toBeInTheDocument()
    expect(screen.getByText('Quick start')).toBeInTheDocument()

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Help' })).not.toBeInTheDocument())
    expect(helpButton).toHaveFocus()
  })

  it('shows the unknown route page', () => {
    window.history.replaceState({}, '', '/nowhere')
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Nothing here' })).toBeInTheDocument()
    expect(screen.getByText("That page doesn't exist.")).toBeInTheDocument()
  })

  it('shows the case-not-found message for an unknown case', async () => {
    window.history.replaceState({}, '', '/case/missing')
    stubFetch(() => jsonResponse({ error: { code: 'not_found', message: 'no such case' } }, 404))
    render(<App />)
    expect(
      await screen.findByText(/We can't find that case\./),
    ).toBeInTheDocument()
  })

  it('shows the connection page when the local server does not answer', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef')
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        throw new TypeError('failed to fetch')
      }),
    )
    render(<App />)
    expect(
      await screen.findByRole('heading', { name: "Can't reach RACCOON on this computer" }),
    ).toBeInTheDocument()
  })

  it('keeps the session token out of the page', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef?t=secret-token')
    stubFetch(() => jsonResponse(READY_CASE))
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')
    expect(document.body.innerHTML).not.toContain('secret-token')
    expect(window.location.search).toBe('')
  })

  it('sends the session token as a header, never in the URL', async () => {
    window.history.replaceState({}, '', '/case/20260101-120000-abcdef?t=secret-token')
    const fetchMock = vi.fn(async (_input: RequestInfo | URL, _init?: RequestInit) =>
      jsonResponse(READY_CASE),
    )
    vi.stubGlobal('fetch', fetchMock)
    render(<App />)
    await screen.findByText('ftp_upload_png.pcap')

    const [url, init] = fetchMock.mock.calls[0]
    expect(url).not.toContain('secret-token')
    expect(new Headers(init?.headers).get('X-Raccoon-Token')).toBe('secret-token')
  })
})
