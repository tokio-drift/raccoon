import { useEffect, useRef, useState, type JSX } from 'react'

import { Icon } from '../assets/icons'
import { CopyButton } from '../components/primitives/CopyButton'
import { Tooltip } from '../components/primitives/Tooltip'
import type { Direction, StreamSummary } from '../api/types'
import {
  BOTH_MODE_TOOLTIP,
  DIRECTION_LEGEND,
  DIRECTION_LABELS,
  bothModeAllowed,
} from '../lib/streams'
import type { StreamDirection } from '../hooks/useStreams'

export interface StreamsToolbarProps {
  /** The stream that is shown. */
  stream: StreamSummary
  /** The direction of the inspector. */
  direction: StreamDirection
  /** The reader changes the direction. */
  onDirectionChange: (direction: StreamDirection) => void
  /** The linked scrolling is on. */
  linked: boolean
  /** The reader toggles the linked scrolling. */
  onToggleLinked: () => void
  /** The text wraps at the pane width. */
  wrap: boolean
  /** The reader toggles the wrapping. */
  onToggleWrap: () => void
  /** The offsets are shown in hexadecimal. */
  hexOffsets: boolean
  /** The reader toggles the offset format. */
  onToggleOffsetFormat: () => void
  /** The text as it is shown; it is copied and shown as an alternative. */
  text: string
  /** The bytes of the window; they are copied as hexadecimal. */
  bytes: Uint8Array
  /** The reader opens the text alternative. */
  onOpenTextAlternative: () => void
  /** The view is reset: the direction and the byte offset (§3.6). */
  onResetView: () => void
}

/**
 * The toolbar of the stream inspector (UI_Design.md §7.4–§7.6): the
 * direction control, the legend, the view toggles and the copy menu.
 */
export function StreamsToolbar({
  stream,
  direction,
  onDirectionChange,
  linked,
  onToggleLinked,
  wrap,
  onToggleWrap,
  hexOffsets,
  onToggleOffsetFormat,
  text,
  bytes,
  onOpenTextAlternative,
  onResetView,
}: StreamsToolbarProps): JSX.Element {
  const [menuOpen, setMenuOpen] = useState(false)
  const root = useRef<HTMLDivElement | null>(null)
  const bothAllowed = bothModeAllowed(stream)

  useEffect(() => {
    if (!menuOpen) return
    const onDocumentClick = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setMenuOpen(false)
    }
    document.addEventListener('mousedown', onDocumentClick)
    return () => document.removeEventListener('mousedown', onDocumentClick)
  }, [menuOpen])

  const directions: StreamDirection[] = ['c2s', 's2c', 'both']

  return (
    <div className="streams-toolbar">
      <div
        className="streams-direction"
        role="group"
        aria-label="Direction"
      >
        {directions.map((item) => {
          const label = item === 'both' ? 'Both' : DIRECTION_LABELS[item as Direction]
          const disabled = item === 'both' && !bothAllowed
          const button = (
            <button
              type="button"
              className={
                direction === item ? 'streams-direction__button streams-direction__button--on' : 'streams-direction__button'
              }
              aria-pressed={direction === item}
              disabled={disabled}
              onClick={() => onDirectionChange(item)}
            >
              {label}
            </button>
          )
          return disabled ? (
            <Tooltip key={item} text={BOTH_MODE_TOOLTIP}>
              {button}
            </Tooltip>
          ) : (
            <span key={item}>{button}</span>
          )
        })}
      </div>

      <ul className="streams-legend" aria-label="Direction legend">
        <li className="streams-legend__item streams-legend__item--c2s">
          <span className="streams-legend__swatch" aria-hidden="true" />
          {DIRECTION_LEGEND.c2s}
        </li>
        <li className="streams-legend__item streams-legend__item--s2c">
          <span className="streams-legend__swatch" aria-hidden="true" />
          {DIRECTION_LEGEND.s2c}
        </li>
      </ul>

      <div className="streams-toolbar__toggles">
        <button
          type="button"
          className={linked ? 'button button--secondary streams-toggle streams-toggle--on' : 'button button--secondary streams-toggle'}
          aria-pressed={linked}
          onClick={onToggleLinked}
        >
          Linked scrolling
        </button>
        <button
          type="button"
          className={wrap ? 'button button--secondary streams-toggle streams-toggle--on' : 'button button--secondary streams-toggle'}
          aria-pressed={wrap}
          onClick={onToggleWrap}
        >
          Wrap lines
        </button>
        <button
          type="button"
          className="button button--secondary streams-toggle"
          onClick={onToggleOffsetFormat}
        >
          {hexOffsets ? 'Decimal offsets' : 'Hex offsets'}
        </button>
        <button
          type="button"
          className="button button--secondary streams-toggle"
          onClick={onOpenTextAlternative}
        >
          Text alternative
        </button>
        <button
          type="button"
          className="button button--secondary streams-toggle"
          onClick={onResetView}
        >
          Reset view
        </button>

        <div className="streams-copymenu" ref={root}>
          <button
            type="button"
            className="button button--secondary streams-copymenu__trigger"
            aria-haspopup="menu"
            aria-expanded={menuOpen}
            onClick={() => setMenuOpen((state) => !state)}
          >
            <Icon name="copy" size={16} />
            <span>Copy</span>
          </button>
          {menuOpen ? (
            <ul className="streams-copymenu__menu" role="menu">
              <li role="none">
                <CopyButton value={text} label="Text (as shown)" showLabel />
              </li>
              <li role="none">
                <CopyButton
                  value={hexBytes(bytes)}
                  label="Hex bytes"
                  showLabel
                />
              </li>
              <li role="none">
                <CopyButton
                  value={hexContinuous(bytes)}
                  label="Hex continuous"
                  showLabel
                />
              </li>
            </ul>
          ) : null}
        </div>
      </div>

      <p className="streams-toolbar__warning">
        Raw bytes are shown as captured and may include passwords sent in cleartext.
      </p>
    </div>
  )
}

/** The hex bytes of a window: "48 65 6C 6C 6F". */
function hexBytes(bytes: Uint8Array): string {
  const parts: string[] = []
  for (const byte of bytes) parts.push(byte.toString(16).toUpperCase().padStart(2, '0'))
  return parts.join(' ')
}

/** The continuous hex of a window: "48656C6C6F". */
function hexContinuous(bytes: Uint8Array): string {
  let out = ''
  for (const byte of bytes) out += byte.toString(16).toUpperCase().padStart(2, '0')
  return out
}
