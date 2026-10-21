import { useState, type JSX } from 'react'

import { CopyButton } from '../primitives/CopyButton'

export interface TextBlockProps {
  /** The value; it is rendered as inert text, never as markup. */
  value: string
  /** The label of the copy button. */
  copyLabel?: string
  /** The maximum height before the block scrolls. */
  maxHeight?: number
}

/**
 * A text block (UI_Design.md §11, §12.9). It shows long and hostile values as
 * inert text and offers a copy button; the copied value is always the exact
 * one.
 */
export function TextBlock({
  value,
  copyLabel = 'Copy',
  maxHeight = 160,
}: TextBlockProps): JSX.Element {
  const [expanded, setExpanded] = useState(false)
  const long = value.length > 160

  return (
    <div className="text-block-wrap">
      <div
        className="text-block"
        style={expanded ? undefined : { maxHeight }}
        data-expanded={expanded ? 'true' : undefined}
      >
        {value}
      </div>
      <div className="text-block__actions">
        {long ? (
          <button
            type="button"
            className="button button--tertiary"
            aria-expanded={expanded}
            onClick={() => setExpanded((state) => !state)}
          >
            {expanded ? 'Show less' : 'Show all'}
          </button>
        ) : null}
        <CopyButton value={value} label={copyLabel} />
      </div>
    </div>
  )
}
