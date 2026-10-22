import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { RaccoonApi } from '../api/api'
import type { CarvedFile, Direction, Page, StreamBytes, StreamSummary } from '../api/types'
import { StreamsView } from './StreamsView'

const CASE_ID = '20260101-120000-abcdef'

function bytes(...values: number[]): Uint8Array {
  return new Uint8Array(values)
}

function base64(data: Uint8Array): string {
  let binary = ''
  for (const byte of data) binary += String.fromCharCode(byte)
  return btoa(binary)
}

function stream(id: number, overrides: Partial<StreamSummary> = {}): StreamSummary {
  return {
    id,
    parentId: 0,
    proto: 'http',
    srcIp: '192.0.2.14',
    srcPort: 51822,
    dstIp: '192.0.2.50',
    dstPort: 80,
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
    ...overrides,
  }
}

function carvedFile(id: number, overrides: Partial<CarvedFile> = {}): CarvedFile {
  return {
    id,
    streamId: 1,
    dir: 'c2s',
    startOff: 32,
    endOff: 96,
    format: 'PNG',
    ext: 'png',
    status: 'complete',
    confidence: 'high',
    size: 64,
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    displayName: 'invoice.png',
    path: 'carved/invoice.png',
    magicHex: '89504e47',
    ...overrides,
  }
}

function page<T extends { id: number }>(items: T[]): Page<T> {
  return { items, nextCursor: null }
}

interface ApiOptions {
  streams?: StreamSummary[]
  files?: CarvedFile[]
  bytes?: (dir: Direction, offset: number, len: number) => StreamBytes
}

function makeApi(options: ApiOptions = {}) {
  const streams = options.streams ?? [stream(1)]
  const files = options.files ?? []
  const listStreams = vi.fn(async (_caseId: string, _query: unknown) => page(streams))
  const listFiles = vi.fn(async (_caseId: string, _query: unknown) => page(files))
  const getStreamBytes = vi.fn(
    async (_caseId: string, _streamId: number, query: { dir: Direction; offset?: number; len?: number }) =>
      options.bytes
        ? options.bytes(query.dir, query.offset ?? 0, query.len ?? 4096)
        : emptyBytes(query.dir, query.offset ?? 0, query.len ?? 4096),
  )
  const api = { listStreams, listFiles, getStreamBytes } as unknown as RaccoonApi
  return { api, listStreams, listFiles, getStreamBytes }
}

function emptyBytes(dir: Direction, offset: number, len: number): StreamBytes {
  return {
    streamId: 1,
    dir,
    offset,
    length: len,
    total: len,
    dataBase64: base64(new Uint8Array(0)),
    segments: [],
    gaps: [],
    carved: [],
  }
}

/**
 * The width of the window. The list sits beside the panes from 1280 px and
 * becomes a drawer below it (§7.1).
 */
function setViewport(width: number): void {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    configurable: true,
    value: (query: string) => ({
      matches: query.includes('1280px') ? width >= 1280 : false,
      media: query,
      onchange: null,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
      addListener: () => undefined,
      removeListener: () => undefined,
      dispatchEvent: () => false,
    }),
  })
}

function renderView(
  api: RaccoonApi,
  overrides: Partial<React.ComponentProps<typeof StreamsView>> = {},
) {
  const onParamsChange = vi.fn()
  const view = render(
    <StreamsView
      caseId={CASE_ID}
      api={api}
      params={{}}
      onParamsChange={onParamsChange}
      basis="utc"
      captureStart={Date.parse('2026-01-01T12:00:00Z')}
      {...overrides}
    />,
  )
  return { ...view, onParamsChange }
}

describe('the stream inspector', () => {
  beforeEach(() => {
    setViewport(1440)
  })

  it('lists the streams of the case and lets the reader pick one', async () => {
    const { api } = makeApi({
      streams: [stream(1, { proto: 'http' }), stream(2, { proto: 'ftp', parentId: 0 })],
    })
    renderView(api)

    expect(await screen.findByText('Stream 1')).toBeTruthy()
    expect(screen.getByText('Stream 2')).toBeTruthy()

    await userEvent.click(screen.getByText('Stream 2'))
    expect(await screen.findByRole('heading', { name: /Stream 2/ })).toBeTruthy()
  })

  it('nests the FTP data stream under its control stream and folds it away', async () => {
    const { api } = makeApi({
      streams: [stream(1, { proto: 'ftp' }), stream(2, { proto: 'ftp', parentId: 1 })],
    })
    renderView(api)

    expect(await screen.findByText('Stream 1')).toBeTruthy()
    expect(screen.getByText('FTP data · child of Stream 1')).toBeTruthy()

    await userEvent.click(screen.getByRole('button', { name: 'Hide the child streams of Stream 1' }))
    await waitFor(() => {
      expect(screen.queryByText('FTP data · child of Stream 1')).toBeNull()
    })
  })

  it('writes the chosen stream into the deep link', async () => {
    const { api } = makeApi({ streams: [stream(1), stream(2)] })
    const { onParamsChange } = renderView(api)

    expect(await screen.findByText('Stream 1')).toBeTruthy()
    await userEvent.click(screen.getByText('Stream 2'))

    await waitFor(() => {
      expect(onParamsChange).toHaveBeenCalledWith(expect.objectContaining({ stream: '2' }))
    })
  })

  it('keeps the search of the list when the stream changes', async () => {
    const { api } = makeApi({ streams: [stream(1), stream(2)] })
    const { onParamsChange } = renderView(api, { params: { q: 'http' } })

    expect(await screen.findByText('Stream 1')).toBeTruthy()
    await userEvent.click(screen.getByText('Stream 2'))

    await waitFor(() => {
      expect(onParamsChange).toHaveBeenCalledWith(expect.objectContaining({ q: 'http' }))
    })
  })

  it('shows the escape of the bytes, never the byte itself', async () => {
    const { api } = makeApi({
      bytes: (dir) => ({
        ...emptyBytes(dir, 0, 4096),
        dataBase64: base64(bytes(0x48, 0x69, 0xff, 0x00, 0x09, 0xe2, 0x80, 0xae)),
      }),
    })
    renderView(api, { params: { stream: '1' } })

    expect(await screen.findByText(/Hi/)).toBeTruthy()
    expect(screen.getByText(/\\xFF/)).toBeTruthy()
    expect(screen.getByText(/U\+202E/)).toBeTruthy()
  })

  it('shows the gap of a missing range instead of zero bytes', async () => {
    const payload = new Uint8Array(64)
    payload.fill(0x48)
    const { api } = makeApi({
      streams: [stream(1, { hasGaps: true })],
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        dataBase64: base64(payload),
        segments: [
          { off: 0, len: 32, ts: '2026-01-01T12:00:00Z', packetNo: 7 },
          { off: 32, len: 32, ts: '2026-01-01T12:00:01Z', packetNo: 9 },
        ],
        gaps: [{ off: 32, len: 1460 }],
      }),
    })
    renderView(api, { params: { stream: '1' } })

    expect(
      await screen.findByText('Missing 1,460 bytes. These packets are not in the capture.'),
    ).toBeTruthy()
    // The gap is never filled with zeroes.
    expect(screen.queryAllByText('00')).toHaveLength(0)
    // The bytes after the gap are still there.
    expect(screen.getAllByText('48').length).toBeGreaterThan(0)
  })

  it('shows the packet number in the gutter of the hex pane', async () => {
    const { api } = makeApi({
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        dataBase64: base64(bytes(0x48, 0x69)),
        segments: [{ off: 0, len: 2, ts: '2026-01-01T12:00:00Z', packetNo: 7 }],
      }),
    })
    renderView(api, { params: { stream: '1' } })

    expect(await screen.findByText('#7')).toBeTruthy()
  })

  it('marks a carved range and opens the file of the range', async () => {
    const onOpenFile = vi.fn()
    const { api } = makeApi({
      files: [carvedFile(7, { id: 7, displayName: 'invoice.png' })],
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        dataBase64: base64(bytes(0x48, 0x69, 0x89, 0x50)),
        segments: [{ off: 0, len: 4, ts: '2026-01-01T12:00:00Z', packetNo: 3 }],
        carved: [{ fileId: 7, start: 0, end: 4 }],
      }),
    })
    renderView(api, { params: { stream: '1' }, onOpenFile })

    expect(await screen.findByText(/invoice\.png/)).toBeTruthy()
    await userEvent.click(screen.getByRole('button', { name: 'Open the file' }))
    expect(onOpenFile).toHaveBeenCalledWith(7)
  })

  it('shows the chip of the file the reader came from and follows it back', async () => {
    const onFollowOrigin = vi.fn()
    const onDismissOrigin = vi.fn()
    const { api } = makeApi()
    renderView(api, {
      params: { stream: '1' },
      origin: { kind: 'file', id: 7, label: 'invoice.png' },
      onFollowOrigin,
      onDismissOrigin,
    })

    const chip = await screen.findByRole('button', { name: /^Back to file invoice\.png$/ })
    await userEvent.click(chip)
    expect(onFollowOrigin).toHaveBeenCalled()

    await userEvent.click(screen.getByRole('button', { name: 'Dismiss Back to file invoice.png' }))
    expect(onDismissOrigin).toHaveBeenCalled()
  })

  it('switches the direction of the panes and writes it into the deep link', async () => {
    const { api } = makeApi({
      streams: [stream(1, { bytesC2S: 128, bytesS2C: 64 })],
    })
    const { onParamsChange } = renderView(api, { params: { stream: '1' } })

    await screen.findByRole('heading', { name: /Stream 1/ })
    await userEvent.click(screen.getByRole('button', { name: 'Server → Client' }))

    await waitFor(() => {
      expect(onParamsChange).toHaveBeenCalledWith(expect.objectContaining({ dir: 's2c' }))
    })
  })

  it('offers the Both mode for the streams that are small enough', async () => {
    const { api } = makeApi({ streams: [stream(1, { bytesC2S: 128, bytesS2C: 64 })] })
    renderView(api, { params: { stream: '1' } })

    const both = await screen.findByRole('button', { name: 'Both' })
    expect(both).toHaveProperty('disabled', false)
  })

  it('locks the Both mode for a stream that is too large', async () => {
    const { api } = makeApi({
      streams: [stream(1, { bytesC2S: 200000, bytesS2C: 64 })],
    })
    renderView(api, { params: { stream: '1' } })

    const both = await screen.findByRole('button', { name: 'Both' })
    expect(both).toHaveProperty('disabled', true)
  })

  it('moves to the next window of 4 KB and back', async () => {
    const { api, getStreamBytes } = makeApi({
      streams: [stream(1, { bytesC2S: 9000 })],
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        total: 9000,
        dataBase64: base64(new Uint8Array(Math.min(len, Math.max(0, 9000 - offset)))),
      }),
    })
    const { onParamsChange } = renderView(api, { params: { stream: '1' } })

    await screen.findByRole('heading', { name: /Stream 1/ })
    await userEvent.click(screen.getByRole('button', { name: 'Next 4 KB' }))

    await waitFor(() => {
      expect(onParamsChange).toHaveBeenCalledWith(expect.objectContaining({ offset: '4096' }))
    })
    await waitFor(() => {
      expect(getStreamBytes).toHaveBeenCalledWith(
        CASE_ID,
        1,
        expect.objectContaining({ offset: 4096, len: 4096 }),
      )
    })
  })

  it('keeps at most three windows in memory', async () => {
    const { api, getStreamBytes } = makeApi({
      streams: [stream(1, { bytesC2S: 90000 })],
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        total: 90000,
        dataBase64: base64(new Uint8Array(Math.min(len, Math.max(0, 90000 - offset)))),
      }),
    })
    renderView(api, { params: { stream: '1' } })

    await screen.findByRole('heading', { name: /Stream 1/ })
    for (let step = 0; step < 5; step += 1) {
      await userEvent.click(screen.getByRole('button', { name: 'Next 4 KB' }))
    }
    await waitFor(() => {
      expect(getStreamBytes.mock.calls.length).toBeGreaterThanOrEqual(6)
    })
  })

  it('rejects an offset that is not a number and one that is beyond the stream', async () => {
    const { api } = makeApi({ streams: [stream(1, { bytesC2S: 4096 })] })
    renderView(api, { params: { stream: '1' } })

    await screen.findByRole('heading', { name: /Stream 1/ })
    await userEvent.click(screen.getByRole('button', { name: 'Jump to…' }))

    const field = screen.getByLabelText(/offset/i)
    await userEvent.clear(field)
    await userEvent.type(field, 'nope')
    await userEvent.click(screen.getByRole('button', { name: 'Jump' }))

    expect(
      await screen.findByText('Enter a byte offset as a number or in hexadecimal, for example 4096 or 0x1000.'),
    ).toBeTruthy()

    await userEvent.clear(field)
    await userEvent.type(field, '999999')
    await userEvent.click(screen.getByRole('button', { name: 'Jump' }))

    expect(
      await screen.findByText('That offset is beyond the end of this stream (4,096 bytes).'),
    ).toBeTruthy()
  })

  it('jumps to a hexadecimal offset', async () => {
    const { api } = makeApi({ streams: [stream(1, { bytesC2S: 40960 })] })
    const { onParamsChange } = renderView(api, { params: { stream: '1' } })

    await screen.findByRole('heading', { name: /Stream 1/ })
    await userEvent.click(screen.getByRole('button', { name: 'Jump to…' }))
    const field = screen.getByLabelText(/offset/i)
    await userEvent.clear(field)
    await userEvent.type(field, '0x1000')
    await userEvent.click(screen.getByRole('button', { name: 'Jump' }))

    await waitFor(() => {
      expect(onParamsChange).toHaveBeenCalledWith(expect.objectContaining({ offset: '4096' }))
    })
  })

  it('says that a deep-linked stream does not exist in the case', async () => {
    const { api } = makeApi({ streams: [stream(1)] })
    renderView(api, { params: { stream: '99' } })

    expect(
      await screen.findByText("Stream 99 doesn't exist in this case."),
    ).toBeTruthy()
  })

  it('shows the error of the bytes without hiding the rest of the view', async () => {
    const api = {
      listStreams: vi.fn(async () => page([stream(1)])),
      listFiles: vi.fn(async () => page([])),
      getStreamBytes: vi.fn(async () => {
        throw new Error('boom')
      }),
    } as unknown as RaccoonApi
    renderView(api, { params: { stream: '1' } })

    expect(await screen.findByText("Couldn't load these bytes.")).toBeTruthy()
    expect(screen.getAllByText('Stream 1').length).toBeGreaterThan(0)
  })

  it('shows the empty state of a direction without data', async () => {
    const { api } = makeApi({
      streams: [stream(1, { bytesC2S: 4096, bytesS2C: 0 })],
    })
    renderView(api, { params: { stream: '1', dir: 's2c' } })

    expect(
      (await screen.findAllByText('No data was sent in this direction.')).length,
    ).toBeGreaterThan(0)
  })

  it('keeps the hex table navigable with the keyboard', async () => {
    const { api } = makeApi({
      bytes: (dir, offset, len) => ({
        ...emptyBytes(dir, offset, len),
        dataBase64: base64(bytes(0x48, 0x69, 0x21)),
      }),
    })
    renderView(api, { params: { stream: '1' } })

    const table = await screen.findByRole('grid', { name: 'Bytes of the stream' })
    const cell = within(table).getByText('48').closest('td')
    expect(cell).toBeTruthy()
    cell?.focus()
    await userEvent.keyboard('{ArrowRight}')

    const selected = within(table).getByText('69').closest('td')
    expect(selected?.getAttribute('aria-selected')).toBe('true')
  })
})
