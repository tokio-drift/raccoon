import {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type JSX,
  type KeyboardEvent as ReactKeyboardEvent,
} from 'react'

import { offsetText } from '../components/content/HexRow'
import type { StreamWindow } from '../hooks/useStreams'
import {
  HEX_ROW_HEIGHT,
  TEXT_LINE_HEIGHT,
  buildTextLines,
  type HexRowModel,
  type TextLine,
} from '../lib/streams'

/** A range of bytes the reader has selected. */
export interface ByteSelection {
  /** The first byte of the selection. */
  start: number
  /** The byte after the last byte of the selection. */
  end: number
}

export interface StreamsPanesProps {
  /** The window that is shown. */
  window: StreamWindow | null
  /** The window of the other direction, in the Both mode. */
  otherWindow: StreamWindow | null
  /** The linked scrolling is on. */
  linked: boolean
  /** The text wraps at the pane width. */
  wrap: boolean
  /** The offsets are shown in hexadecimal; otherwise they are decimal. */
  hexOffsets: boolean
  /** The selected bytes. */
  selection: ByteSelection | null
  /** Called when the reader selects bytes. */
  onSelect: (selection: ByteSelection | null) => void
  /** Called when the reader opens a carved file. */
  onOpenCarved?: (fileId: number, start: number) => void
  /** Called when the reader limits the view to a carved range. */
  onFilterCarved?: (fileId: number, start: number, end: number) => void
  /** The label of the direction, for the caption of the panes. */
  directionLabel: string
}

/** The number of pixels a scroll container shows at least. */
const MIN_VIEWPORT = 240

/** The width of one character of the 13 px monospace font, in pixels. */
const CHAR_WIDTH = 7.8

/**
 * The text pane and the hex pane of the stream inspector
 * (UI_Design.md §7.2, §7.5–§7.7). Both panes show the same bytes, they scroll
 * on their own and, with the linked scrolling on, one moves the other to the
 * same byte offset.
 */
export function StreamsPanes({
  window: streamWindow,
  otherWindow,
  linked,
  wrap,
  hexOffsets,
  selection,
  onSelect,
  onOpenCarved,
  onFilterCarved,
  directionLabel,
}: StreamsPanesProps): JSX.Element {
  const textRef = useRef<HTMLDivElement>(null)
  const hexRef = useRef<HTMLDivElement>(null)
  const syncing = useRef(false)
  const [textScroll, setTextScroll] = useState(0)
  const [hexScroll, setHexScroll] = useState(0)
  const [columns, setColumns] = useState(0)

  const lines = useMemo(() => {
    if (!streamWindow) return []
    return buildTextLines(streamWindow.model.runs, wrap ? columns : 0)
  }, [streamWindow, wrap, columns])

  const rows = useMemo(() => streamWindow?.model.rows ?? [], [streamWindow])

  // The pane width decides how many characters fit on a line.
  useEffect(() => {
    const node = textRef.current
    if (!node) return
    const measure = (): void => {
      const width = node.clientWidth
      if (width <= 0) return
      const next = Math.max(20, Math.floor(width / CHAR_WIDTH))
      setColumns((current) => (current === next ? current : next))
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return
    const observer = new ResizeObserver(measure)
    observer.observe(node)
    return () => observer.disconnect()
  }, [])

  const textViewport = Math.max(textRef.current?.clientHeight ?? 0, MIN_VIEWPORT)
  const hexViewport = Math.max(hexRef.current?.clientHeight ?? 0, MIN_VIEWPORT)

  const firstLine = Math.max(0, Math.floor(textScroll / TEXT_LINE_HEIGHT) - 4)
  const lastLine = Math.min(lines.length, firstLine + Math.ceil(textViewport / TEXT_LINE_HEIGHT) + 8)
  const firstRow = Math.max(0, Math.floor(hexScroll / HEX_ROW_HEIGHT) - 4)
  const lastRow = Math.min(rows.length, firstRow + Math.ceil(hexViewport / HEX_ROW_HEIGHT) + 8)

  const scrollTextTo = useCallback((offset: number) => {
    const node = textRef.current
    if (!node) return
    const index = lines.findIndex((line) => line.offset >= offset)
    const target = index < 0 ? lines.length - 1 : index
    if (target < 0) return
    node.scrollTop = target * TEXT_LINE_HEIGHT
  }, [lines])

  const scrollHexTo = useCallback((offset: number) => {
    const node = hexRef.current
    if (!node) return
    const index = rows.findIndex((row) => row.offset >= offset)
    const target = index < 0 ? rows.length - 1 : index
    if (target < 0) return
    node.scrollTop = target * HEX_ROW_HEIGHT
  }, [rows])

  const onTextScroll = useCallback(() => {
    const node = textRef.current
    if (!node) return
    setTextScroll(node.scrollTop)
    if (!linked || syncing.current || lines.length === 0) return
    const index = Math.min(lines.length - 1, Math.floor(node.scrollTop / TEXT_LINE_HEIGHT))
    const line = lines[index]
    if (!line) return
    syncing.current = true
    scrollHexTo(line.offset)
    window.requestAnimationFrame(() => {
      syncing.current = false
    })
  }, [linked, lines, scrollHexTo])

  const onHexScroll = useCallback(() => {
    const node = hexRef.current
    if (!node) return
    setHexScroll(node.scrollTop)
    if (!linked || syncing.current || rows.length === 0) return
    const index = Math.min(rows.length - 1, Math.floor(node.scrollTop / HEX_ROW_HEIGHT))
    const row = rows[index]
    if (!row) return
    syncing.current = true
    scrollTextTo(row.offset)
    window.requestAnimationFrame(() => {
      syncing.current = false
    })
  }, [linked, rows, scrollTextTo])

  // A selection that comes from elsewhere, for example a carved range, brings
  // both panes to the byte of the selection.
  useEffect(() => {
    if (!selection) return
    const base = streamWindow?.model.offset ?? 0
    if (selection.start < base) return
    if (selection.start > base + (streamWindow?.model.bytes.length ?? 0)) return
    scrollTextTo(selection.start)
    scrollHexTo(selection.start)
  }, [selection, scrollHexTo, scrollTextTo, streamWindow])

  const selectByte = useCallback(
    (offset: number, extend: boolean) => {
      if (!selection || !extend) {
        onSelect({ start: offset, end: offset + 1 })
        return
      }
      const start = Math.min(selection.start, offset)
      const end = Math.max(selection.end, offset + 1)
      onSelect({ start, end })
    },
    [onSelect, selection],
  )

  const onHexKeyDown = useCallback(
    (event: ReactKeyboardEvent<HTMLTableElement>) => {
      if (!streamWindow) return
      const base = streamWindow.model.offset
      const current = selection?.start ?? base
      let next = current
      const extend = event.shiftKey
      switch (event.key) {
        case 'ArrowRight':
          next = current + 1
          break
        case 'ArrowLeft':
          next = current - 1
          break
        case 'ArrowDown':
          next = current + 16
          break
        case 'ArrowUp':
          next = current - 16
          break
        case 'Home':
          next = event.ctrlKey ? base : base + (current - base) % 16
          break
        case 'End':
          next = event.ctrlKey
            ? base + streamWindow.model.bytes.length - 1
            : base + (current - base) - ((current - base) % 16) + 15
          break
        default:
          return
      }
      event.preventDefault()
      const limit = base + streamWindow.model.bytes.length
      const clamped = Math.max(base, Math.min(limit - 1, next))
      selectByte(clamped, extend)
      const cell = event.currentTarget.querySelector<HTMLElement>(
        `[data-offset="${clamped}"]`,
      )
      cell?.focus()
    },
    [selectByte, selection, streamWindow],
  )

  const textPane = (
    <section className="streams-pane streams-pane--text" aria-labelledby="streams-text-heading">
      <h2 className="streams-pane__heading" id="streams-text-heading">
        Text
      </h2>
      <div
        className="streams-pane__scroll"
        ref={textRef}
        onScroll={onTextScroll}
        tabIndex={0}
        role="region"
        aria-label={`Text of the ${directionLabel} direction`}
      >
        {lines.length === 0 ? (
          <p className="streams-pane__empty">No data was sent in this direction.</p>
        ) : (
          <div className="streams-text" style={{ height: lines.length * TEXT_LINE_HEIGHT }}>
            {lines.slice(firstLine, lastLine).map((line, index) => (
              <TextLineView key={`${firstLine + index}`} line={line} index={firstLine + index} />
            ))}
          </div>
        )}
      </div>
    </section>
  )

  const hexPane = (
    <section className="streams-pane streams-pane--hex" aria-labelledby="streams-hex-heading">
      <h2 className="streams-pane__heading" id="streams-hex-heading">
        Hex
      </h2>
      <div
        className="streams-pane__scroll"
        ref={hexRef}
        onScroll={onHexScroll}
        role="region"
        aria-label={`Bytes of the ${directionLabel} direction`}
      >
        {rows.length === 0 ? (
          <p className="streams-pane__empty">No data was sent in this direction.</p>
        ) : (
          <table
            className="hex-table"
            role="grid"
            aria-label="Bytes of the stream"
            onKeyDown={onHexKeyDown}
          >
            <caption className="visually-hidden">
              {`The bytes of the ${directionLabel} direction, sixteen to a row.`}
            </caption>
            <thead>
              <tr>
                <th scope="col" className="hex-table__gutter">
                  Packet
                </th>
                <th scope="col" className="hex-table__offset">
                  Offset
                </th>
                <th scope="col" colSpan={16} className="hex-table__bytes">
                  Bytes
                </th>
                <th scope="col" colSpan={16} className="hex-table__text">
                  Text (for reading only)
                </th>
              </tr>
            </thead>
            <tbody>
              {rows.slice(firstRow, lastRow).map((row, index) => (
                <HexRowView
                  key={`${firstRow + index}-${row.offset}`}
                  row={row}
                  index={firstRow + index}
                  selection={selection}
                  hexOffsets={hexOffsets}
                  onSelect={selectByte}
                  onOpenCarved={onOpenCarved}
                  onFilterCarved={onFilterCarved}
                />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  )

  return (
    <div className="streams-panes">
      {textPane}
      {hexPane}
      {otherWindow ? (
        <p className="streams-panes__other" role="note">
          {`The other direction is shown in the ${otherWindow.dir === 'c2s' ? 'client to server' : 'server to client'} block below.`}
        </p>
      ) : null}
    </div>
  )
}

/** One line of the text pane. */
function TextLineView({ line, index }: { line: TextLine; index: number }): JSX.Element {
  return (
    <div
      className={line.continuation ? 'streams-line streams-line--continuation' : 'streams-line'}
      style={{ top: index * TEXT_LINE_HEIGHT }}
      data-offset={line.offset}
    >
      {line.continuation ? <span className="streams-line__marker">⤷</span> : null}
      {line.parts.map((part, partIndex) => (
        <span key={partIndex} className={`streams-text__${part.kind}`}>
          {part.text}
        </span>
      ))}
    </div>
  )
}

/** One row of the hex pane, with the carved-range chip above it. */
function HexRowView({
  row,
  index,
  selection,
  hexOffsets,
  onSelect,
  onOpenCarved,
  onFilterCarved,
}: {
  row: HexRowModel
  index: number
  selection: ByteSelection | null
  hexOffsets: boolean
  onSelect: (offset: number, extend: boolean) => void
  onOpenCarved?: (fileId: number, start: number) => void
  onFilterCarved?: (fileId: number, start: number, end: number) => void
}): JSX.Element {
  if (row.gap) {
    return (
      <tr className="hex-row hex-row--gap" style={{ top: index * HEX_ROW_HEIGHT }}>
        <td className="hex-row__gutter" />
        <th scope="row" className="hex-row__offset">
          {offsetText(row.offset, hexOffsets ? 'hex' : 'decimal')}
        </th>
        <td className="hex-row__gap" colSpan={18}>
          {`Missing ${(row.missing ?? 0).toLocaleString('en-US')} bytes. These packets are not in the capture.`}
        </td>
      </tr>
    )
  }

  const cells: JSX.Element[] = []
  for (let position = 0; position < 16; position += 1) {
    const byte = row.bytes[position]
    if (byte === undefined) {
      cells.push(<td key={position} className="hex-row__cell" />)
      continue
    }
    const offset = row.offset + position
    const selected =
      selection !== null && offset >= selection.start && offset < selection.end
    const classes = ['hex-row__cell']
    if (position === 8) classes.push('hex-row__cell--group')
    if (selected) classes.push('hex-row__cell--selected')
    cells.push(
      <td
        key={position}
        className={classes.join(' ')}
        data-offset={offset}
        aria-selected={selected}
        tabIndex={offset === (selection?.start ?? row.offset) ? 0 : -1}
        onMouseDown={(event) => {
          event.preventDefault()
          onSelect(offset, event.shiftKey)
        }}
        onMouseEnter={(event) => {
          if (event.buttons === 1) onSelect(offset, true)
        }}
      >
        {byte.toString(16).toUpperCase().padStart(2, '0')}
      </td>,
    )
  }

  const text: JSX.Element[] = []
  for (let position = 0; position < 16; position += 1) {
    const byte = row.bytes[position]
    const offset = row.offset + position
    const selected = selection !== null && offset >= selection.start && offset < selection.end
    text.push(
      <td
        key={position}
        className={selected ? 'hex-row__text hex-row__text--selected' : 'hex-row__text'}
        data-offset={offset}
        onMouseDown={(event) => {
          event.preventDefault()
          onSelect(offset, event.shiftKey)
        }}
      >
        {byte === undefined ? '' : byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '·'}
      </td>,
    )
  }

  const classes = ['hex-row']
  if (row.carvedStart) classes.push('hex-row--carved-start')
  if (row.carvedEnd) classes.push('hex-row--carved-end')

  return (
    <>
      {row.carvedStart && row.carvedLabel ? (
        <tr className="hex-row hex-row--carved-chip">
          <td colSpan={19} className="hex-row__carved-label">
            <span className="hex-row__carved-name">{row.carvedLabel}</span>
            {onOpenCarved && row.carvedFileId !== undefined ? (
              <button
                type="button"
                className="button button--tertiary hex-row__carved-open"
                onClick={() => onOpenCarved(row.carvedFileId as number, row.offset)}
              >
                Open the file
              </button>
            ) : null}
            {onFilterCarved && row.carvedFileId !== undefined ? (
              <button
                type="button"
                className="button button--tertiary hex-row__carved-open"
                onClick={() =>
                  onFilterCarved(
                    row.carvedFileId as number,
                    row.carvedRange?.start ?? row.offset,
                    row.carvedRange?.end ?? row.offset + row.bytes.length,
                  )
                }
              >
                Show only this range
              </button>
            ) : null}
          </td>
        </tr>
      ) : null}
      <tr className={classes.join(' ')} style={{ top: index * HEX_ROW_HEIGHT }}>
        <td className="hex-row__gutter">{row.packetNo === undefined ? null : `#${row.packetNo}`}</td>
        <th scope="row" className="hex-row__offset">
          {offsetText(row.offset, hexOffsets ? 'hex' : 'decimal')}
        </th>
        {cells}
        {text}
      </tr>
    </>
  )
}
