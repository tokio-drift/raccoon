import type { JSX } from 'react'

export interface HexRowProps {
  /** The offset of the row in bytes. */
  offset: number
  /** The sixteen bytes of the row. */
  bytes: number[]
  /** The packet number of the first segment in the row. */
  packetNo?: number
  /** The row covers a gap in the capture. */
  gap?: boolean
  /** The number of missing bytes, for a gap row. */
  missing?: number
  /** The range of the missing bytes, for example "0x05B4–0x0B67". */
  missingRange?: string
  /** The row starts a carved range. */
  carvedStart?: boolean
  /** The row ends a carved range. */
  carvedEnd?: boolean
  /** The carved range label, for example "invoice.zip · 5.2 KB". */
  carvedLabel?: string
  /** The offset is shown in hexadecimal (the default) or in decimal. */
  offsetFormat?: 'hex' | 'decimal'
}

/** The printable ASCII of a byte, or a middle dot. */
export function asciiOf(byte: number): string {
  return byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '·'
}

/** The hexadecimal representation of a byte. */
export function hexOf(byte: number): string {
  return byte.toString(16).toUpperCase().padStart(2, '0')
}

/** The offset of a row: "00004120" in hexadecimal, "16,640" in decimal. */
export function offsetText(offset: number, format: 'hex' | 'decimal' = 'hex'): string {
  if (format === 'decimal') return offset.toLocaleString('en-US')
  return offset.toString(16).toUpperCase().padStart(8, '0')
}

/**
 * A row of the hex pane (UI_Design.md §7.6, §7.7, §11). The offset cell is
 * the row header and the packet gutter shows the packet number; a gap is a
 * hatched row and is never zero-filled.
 */
export function HexRow({
  offset,
  bytes,
  packetNo,
  gap = false,
  missing = 0,
  missingRange,
  carvedStart = false,
  carvedEnd = false,
  carvedLabel,
  offsetFormat = 'hex',
}: HexRowProps): JSX.Element {
  if (gap) {
    return (
      <tr className="hex-row hex-row--gap">
        <td className="hex-row__gutter" />
        <th scope="row" className="hex-row__offset">
          {offsetText(offset, offsetFormat)}
        </th>
        <td className="hex-row__gap" colSpan={18}>
          {`Missing ${missing.toLocaleString('en-US')} bytes${
            missingRange ? ` (${missingRange})` : ''
          }. These packets are not in the capture.`}
        </td>
      </tr>
    )
  }

  const cells: JSX.Element[] = []
  for (let index = 0; index < 16; index += 1) {
    const byte = bytes[index]
    const classes = ['hex-row__cell']
    if (index === 8) classes.push('hex-row__cell--group')
    cells.push(
      <td key={index} className={classes.join(' ')}>
        {byte === undefined ? '' : hexOf(byte)}
      </td>,
    )
  }

  const text: JSX.Element[] = []
  for (let index = 0; index < 16; index += 1) {
    const byte = bytes[index]
    text.push(
      <td key={index} className="hex-row__text">
        {byte === undefined ? '' : asciiOf(byte)}
      </td>,
    )
  }

  const classes = ['hex-row']
  if (carvedStart) classes.push('hex-row--carved-start')
  if (carvedEnd) classes.push('hex-row--carved-end')

  return (
    <tr className={classes.join(' ')}>
      <td className="hex-row__gutter">
        {packetNo === undefined ? null : `#${packetNo}`}
      </td>
      <th scope="row" className="hex-row__offset">
        {offsetText(offset, offsetFormat)}
      </th>
      {cells}
      {text}
      {carvedStart && carvedLabel ? (
        <td className="hex-row__carved-label" colSpan={18}>
          {carvedLabel}
        </td>
      ) : null}
    </tr>
  )
}
