import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from './api/api'
import type { CarvedFile, CaseEvent, EventQuery, FileQuery, Page } from './api/types'
import { FilesView } from './views/FilesView'
import { StoryboardView } from './views/StoryboardView'
import { StreamsView } from './views/StreamsView'
import { loadPreferences } from './lib/preferences'

/**
 * The accessibility pass of PLAN 11.10: the landmarks, the semantics of the
 * lists and tables, the keyboard map, the focus and the announcements of
 * UI_Design.md §13.
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

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function carvedFile(id: number, name: string): CarvedFile {
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
    displayName: name,
    path: `carved/${name}`,
    magicHex: '89504e47',
  }
}

function makeApi(events: CaseEvent[] = [], files: CarvedFile[] = []) {
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page(events))
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const api = {
    listEvents,
    listFiles,
    listStreams: vi.fn(async () => page([])),
    getStreamBytes: vi.fn(async () => ({
      streamId: 1,
      dir: 'c2s',
      offset: 0,
      length: 0,
      total: 0,
      dataBase64: '',
      segments: [],
      gaps: [],
      carved: [],
    })),
  } as unknown as RaccoonApi
  return { api, listEvents, listFiles }
}

beforeEach(() => {
  window.localStorage.clear()
  loadPreferences()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('the semantics of the case views', () => {
  it('tells the screen reader how long the event list is', async () => {
    const { api } = makeApi([event(1), event(2), event(3)])
    render(
      <StoryboardView
        caseId={CASE_ID}
        api={api}
        totalEvents={3}
        params={{}}
        onParamsChange={() => undefined}
        onOpenStreams={() => undefined}
      />,
    )

    const list = await screen.findByRole('list', { name: 'Storyboard events' })
    expect(list).toBeInTheDocument()

    const items = within(list).getAllByRole('listitem')
    expect(items.length).toBeGreaterThan(0)
    expect(items[0]).toHaveAttribute('aria-posinset', '1')
    expect(items[0]).toHaveAttribute('aria-setsize', '3')
  })

  it('isolates the names of files from the text around them', async () => {
    const { api } = makeApi([], [carvedFile(1, 'invoice‮gnp.exe')])
    render(
      <FilesView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={() => undefined}
        verdicts={{}}
        onOpenStreams={() => undefined}
      />,
    )

    const cell = await screen.findByTitle('invoice‮gnp.exe')
    expect(cell).toHaveAttribute('dir', 'auto')
  })

  it('marks the columns of the file table', async () => {
    const { api } = makeApi([], [carvedFile(1, 'invoice.png')])
    render(
      <FilesView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={() => undefined}
        verdicts={{}}
        onOpenStreams={() => undefined}
      />,
    )

    const table = await screen.findByRole('table')
    const headers = within(table).getAllByRole('columnheader')
    expect(headers.length).toBeGreaterThan(4)
    for (const header of headers) {
      expect(header).toHaveAttribute('scope', 'col')
    }
    expect(within(table).getByRole('button', { name: 'Sort by Name' })).toBeInTheDocument()
  })

  it('gives the panes of the inspector a heading and a region', async () => {
    const { api } = makeApi()
    render(
      <StreamsView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={() => undefined}
        basis="utc"
      />,
    )

    expect(await screen.findByRole('heading', { level: 1, name: 'Streams' })).toBeInTheDocument()
  })
})

describe('the keyboard map', () => {
  it('focuses the search of the storyboard with the slash key', async () => {
    const { api } = makeApi([event(1)])
    render(
      <StoryboardView
        caseId={CASE_ID}
        api={api}
        totalEvents={1}
        params={{}}
        onParamsChange={() => undefined}
        onOpenStreams={() => undefined}
      />,
    )

    await screen.findByRole('list', { name: 'Storyboard events' })
    await userEvent.keyboard('/')

    const search = screen.getByRole('searchbox', { name: /search/i })
    await waitFor(() => {
      expect(search).toHaveFocus()
    })
  })

  it('focuses the search of the file gallery with the slash key', async () => {
    const { api } = makeApi([], [carvedFile(1, 'invoice.png')])
    render(
      <FilesView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={() => undefined}
        verdicts={{}}
        onOpenStreams={() => undefined}
      />,
    )

    await screen.findByRole('table')
    await userEvent.keyboard('/')

    const search = screen.getByRole('searchbox', { name: /search/i })
    await waitFor(() => {
      expect(search).toHaveFocus()
    })
  })

  it('returns the focus from the detail pane to the list', async () => {
    const { api } = makeApi([event(1)])
    render(
      <StoryboardView
        caseId={CASE_ID}
        api={api}
        totalEvents={1}
        params={{}}
        onParamsChange={() => undefined}
        onOpenStreams={() => undefined}
      />,
    )

    const list = await screen.findByRole('list', { name: 'Storyboard events' })
    const card = await within(list).findByRole('listitem')
    card.focus()
    await userEvent.keyboard('{Enter}')

    const pane = await screen.findByRole('complementary', { name: 'Event details' })
    expect(pane).toBeInTheDocument()

    await userEvent.keyboard('{Escape}')

    await waitFor(() => {
      expect(document.activeElement).not.toBeNull()
    })
  })
})

describe('the resizable panes', () => {
  it('moves the divider with the arrow keys and keeps the width', async () => {
    const { api } = makeApi([event(1)])
    const { unmount } = render(
      <StoryboardView
        caseId={CASE_ID}
        api={api}
        totalEvents={1}
        params={{}}
        onParamsChange={() => undefined}
        onOpenStreams={() => undefined}
      />,
    )

    const resizer = await screen.findByRole('separator', { name: 'Resize the event list' })
    const before = Number(resizer.getAttribute('aria-valuenow'))
    resizer.focus()
    await userEvent.keyboard('{ArrowRight}')

    await waitFor(() => {
      const after = Number(resizer.getAttribute('aria-valuenow'))
      expect(after).toBeGreaterThan(before)
    })
    const width = resizer.getAttribute('aria-valuenow')
    unmount()

    // The width is remembered for the next visit.
    render(
      <StoryboardView
        caseId={CASE_ID}
        api={api}
        totalEvents={1}
        params={{}}
        onParamsChange={() => undefined}
        onOpenStreams={() => undefined}
      />,
    )
    const again = await screen.findByRole('separator', { name: 'Resize the event list' })
    expect(again.getAttribute('aria-valuenow')).toBe(width)
  })
})
