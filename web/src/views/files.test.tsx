import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from '../api/api'
import type { CarvedFile, EventQuery, FileQuery, Page, StreamSummary, VerdictEvent } from '../api/types'
import { FilesView } from './FilesView'

const CASE_ID = '20260101-120000-abcdef'

function file(id: number, overrides: Partial<CarvedFile> = {}): CarvedFile {
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
    displayName: `file-${id}.png`,
    path: `carved/file-${id}.png`,
    magicHex: '89504e47',
    ...overrides,
  }
}

const STREAM: StreamSummary = {
  id: 1,
  parentId: 0,
  proto: 'ftp',
  srcIp: '192.0.2.14',
  srcPort: 51822,
  dstIp: '192.0.2.50',
  dstPort: 21,
  startTs: '2026-01-01T12:00:00.000000000Z',
  endTs: '2026-01-01T12:00:05.000000000Z',
  bytesC2S: 4096,
  bytesS2C: 0,
  packets: 4,
  firstPacket: 1,
  lastPacket: 4,
  midstream: false,
  hasGaps: false,
  udp: false,
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

function makeApi(files: CarvedFile[] = [], streams: StreamSummary[] = [STREAM]) {
  const listFiles = vi.fn(async (_caseId: string, _query: FileQuery) => page(files))
  const listStreams = vi.fn(async (_caseId: string, _query: unknown) => page(streams))
  const listEvents = vi.fn(async (_caseId: string, _query: EventQuery) => page([]))
  const downloadFile = vi.fn(async (_caseId: string, _fileId: number) => ({
    blob: new Blob(['hello']),
    filename: 'server-name.exe',
  }))
  const api = { listFiles, listStreams, listEvents, downloadFile } as unknown as RaccoonApi
  return { api, listFiles, listStreams, listEvents, downloadFile }
}

function renderView(
  api: RaccoonApi,
  overrides: Partial<React.ComponentProps<typeof FilesView>> = {},
) {
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
  window.history.replaceState(null, '', `/case/${CASE_ID}/files`)
  // jsdom cannot follow a download link; the click is recorded instead.
  vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined)
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('the files view', () => {
  it('lists the files of the case with their format, size and verdict', async () => {
    const { api } = makeApi([file(1), file(2)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(2))
    expect(screen.getByTitle('file-1.png')).toBeInTheDocument()
    expect(screen.getAllByText('PNG image · .png').length).toBeGreaterThan(0)
    expect(screen.getAllByText('1,024 B').length).toBe(2)
  })

  it('shows the endpoints with the direction chip', async () => {
    const { api } = makeApi([file(1)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByText('192.0.2.14:51822 → 192.0.2.50:21')).toBeInTheDocument()
    expect(screen.getByText('Sent to server')).toBeInTheDocument()
  })

  it('hides the low-confidence files and says how many are hidden', async () => {
    const { api } = makeApi([file(1), file(2, { confidence: 'low' })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByText(/1 low-confidence file is hidden/)).toBeInTheDocument()
  })

  it('shows the low-confidence files when the reader asks for them', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([file(1), file(2, { confidence: 'low' })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByRole('button', { name: 'Show them' }))
    await waitFor(() => expect(rows().length).toBe(2))
  })

  it('puts the most serious verdict first', async () => {
    const { api } = makeApi([
      file(1, { verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' } }),
      file(2, { verdict: { source: 'yara', status: 'malicious', score: 2, total: 70, checkedAt: '' } }),
      file(3, { verdict: { source: 'yara', status: 'suspicious', score: 1, total: 70, checkedAt: '' } }),
    ])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(3))
    expect(rows().map((row) => row.dataset.fileId)).toEqual(['2', '3', '1'])
  })

  it('sorts by a column when the reader asks for it', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([file(1, { displayName: 'b.png' }), file(2, { displayName: 'a.png' })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(2))
    await user.click(screen.getByRole('button', { name: 'Sort by Name' }))
    await waitFor(() => expect(rows().map((row) => row.dataset.fileId)).toEqual(['2', '1']))
  })

  it('shows the detail pane of a selected file with its seven sections', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([file(1)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByTitle('file-1.png'))

    const pane = await screen.findByRole('complementary', { name: 'File details' })
    const headings = within(pane)
      .getAllByRole('heading', { level: 3 })
      .map((heading) => heading.textContent)
    expect(headings).toEqual([
      'Verdict',
      'Where it came from',
      'Hashes',
      'Identification',
      'Download',
    ])
    expect(within(pane).getByText(/RACCOON never opens or previews extracted files/)).toBeInTheDocument()
  })

  it('shows the hash of the file and the bytes it came from', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([file(1, { startOff: 1204, endOff: 6498 })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByTitle('file-1.png'))
    const pane = await screen.findByRole('complementary', { name: 'File details' })
    expect(within(pane).getByText('e3b0c44298fc1c149afbf4c8996fb924')).toBeInTheDocument()
    expect(within(pane).getByText('27ae41e4649b934ca495991b7852b855')).toBeInTheDocument()
    expect(within(pane).getByText(/Bytes 1,204–6,498/)).toBeInTheDocument()
  })

  it('shows the name of a file as text and never as a path', async () => {
    const { api } = makeApi([file(1, { displayName: '../../etc/passwd' })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByText('Path-like name')).toBeInTheDocument()
  })

  it('warns when the name does not match the content', async () => {
    const { api } = makeApi([file(1, { displayName: 'photo.jpg', ext: 'zip', format: 'ZIP' })])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByText("Name doesn't match content")).toBeInTheDocument()
  })

  it('saves a file under a neutral name', async () => {
    const user = userEvent.setup()
    const { api, downloadFile } = makeApi([file(1)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByRole('button', { name: 'Download file-1.png' }))
    await waitFor(() => expect(downloadFile).toHaveBeenCalledWith(CASE_ID, 1))
    const click = vi.mocked(HTMLAnchorElement.prototype.click)
    const anchor = click.mock.instances[0] as unknown as HTMLAnchorElement
    expect(anchor.download).toBe('e3b0c44298fc.bin')
  })

  it('asks before a file marked malicious is downloaded', async () => {
    const user = userEvent.setup()
    const { api, downloadFile } = makeApi([
      file(1, { verdict: { source: 'virustotal', status: 'malicious', score: 12, total: 60, checkedAt: '' } }),
    ])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByRole('button', { name: 'Download file-1.png' }))

    const dialog = await screen.findByRole('dialog', { name: 'Download a file marked malicious?' })
    expect(within(dialog).getByText(/12 of 60 sources/)).toBeInTheDocument()
    const confirm = within(dialog).getByRole('button', { name: 'Download anyway' })
    expect(confirm).toBeDisabled()
    await user.click(within(dialog).getByRole('checkbox'))
    expect(confirm).toBeEnabled()
    await user.click(confirm)
    await waitFor(() => expect(downloadFile).toHaveBeenCalled())
  })

  it('does not ask before a file with no detections is downloaded', async () => {
    const user = userEvent.setup()
    const { api, downloadFile } = makeApi([
      file(1, { verdict: { source: 'virustotal', status: 'no_detections', score: 0, total: 60, checkedAt: '' } }),
    ])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByRole('button', { name: 'Download file-1.png' }))
    await waitFor(() => expect(downloadFile).toHaveBeenCalled())
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('says when no file was extracted', async () => {
    const { api } = makeApi([])
    renderView(api)
    await waitFor(() => expect(screen.getByText('No files were extracted')).toBeInTheDocument())
  })

  it('says when the filters hide every file', async () => {
    const { api } = makeApi([file(1)])
    renderView(api, { params: { verdict: 'malicious' } })
    await waitFor(() => expect(screen.getByText('No files match these filters')).toBeInTheDocument())
  })

  it('shows that the threat checks are still arriving', async () => {
    const { api } = makeApi([file(1)])
    renderView(api, { partial: true })
    await waitFor(() => expect(rows().length).toBe(1))
    expect(screen.getByText(/Threat checks are still arriving/)).toBeInTheDocument()
  })

  it('keeps the rows in place when a live verdict arrives and offers a re-sort', async () => {
    const { api } = makeApi([
      file(1, { verdict: { source: 'yara', status: 'not_checked', score: 0, total: 70, checkedAt: '' } }),
      file(2, { verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' } }),
    ])
    const verdicts: Record<number, VerdictEvent> = {
      1: { fileId: 1, sha256: 'abc', status: 'malicious' },
    }
    const { rerender } = renderView(api)
    await waitFor(() => expect(rows().length).toBe(2))
    rerender(
      <FilesView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={vi.fn()}
        verdicts={verdicts}
        onOpenStreams={vi.fn()}
      />,
    )
    await waitFor(() => expect(screen.getByText('Order changed')).toBeInTheDocument())
    expect(rows().map((row) => row.dataset.fileId)).toEqual(['1', '2'])
  })

  it('moves the rows when the reader asks for a re-sort', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([
      file(1, { verdict: { source: 'yara', status: 'not_checked', score: 0, total: 70, checkedAt: '' } }),
      file(2, { verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' } }),
    ])
    const verdicts: Record<number, VerdictEvent> = {
      1: { fileId: 1, sha256: 'abc', status: 'malicious' },
    }
    const { rerender } = renderView(api)
    await waitFor(() => expect(rows().length).toBe(2))
    rerender(
      <FilesView
        caseId={CASE_ID}
        api={api}
        params={{}}
        onParamsChange={vi.fn()}
        verdicts={verdicts}
        onOpenStreams={vi.fn()}
      />,
    )
    await waitFor(() => expect(screen.getByText('Order changed')).toBeInTheDocument())
    await user.click(screen.getByRole('button', { name: 'Re-sort' }))
    await waitFor(() => expect(rows().map((row) => row.dataset.fileId)).toEqual(['1', '2']))
  })

  it('shows the detail pane of a file the deep link names', async () => {
    const { api } = makeApi([file(1), file(2)])
    renderView(api, { params: { file: '2' } })
    await waitFor(() => expect(rows().length).toBe(2))
    const pane = await screen.findByRole('complementary', { name: 'File details' })
    expect(within(pane).getByRole('heading', { level: 2 })).toHaveTextContent('file-2.png')
  })

  it('writes the filters and the sort to the address bar', async () => {
    const { api } = makeApi([file(1)])
    const { onParamsChange } = renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await userEvent.setup().click(screen.getByRole('button', { name: 'Sort by Name' }))
    await waitFor(() => {
      const last = onParamsChange.mock.calls.at(-1)?.[0] as Record<string, string>
      expect(last.sort).toBe('name')
    })
  })

  it('closes the detail pane with Escape', async () => {
    const user = userEvent.setup()
    const { api } = makeApi([file(1)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByTitle('file-1.png'))
    expect(await screen.findByRole('complementary', { name: 'File details' })).toBeInTheDocument()
    await user.keyboard('{Escape}')
    await waitFor(() =>
      expect(screen.queryByRole('complementary', { name: 'File details' })).not.toBeInTheDocument(),
    )
  })

  it('shows the detail pane beside the table on a wide screen', async () => {
    const user = userEvent.setup()
    vi.stubGlobal(
      'matchMedia',
      vi.fn((query: string) => ({
        matches: true,
        media: query,
        onchange: null,
        addEventListener: () => undefined,
        removeEventListener: () => undefined,
        addListener: () => undefined,
        removeListener: () => undefined,
        dispatchEvent: () => false,
      })),
    )
    const { api } = makeApi([file(1)])
    renderView(api)
    await waitFor(() => expect(rows().length).toBe(1))
    await user.click(screen.getByTitle('file-1.png'))
    const pane = await screen.findByRole('complementary', { name: 'File details' })
    expect(pane).toBeInTheDocument()
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    vi.unstubAllGlobals()
  })
})
