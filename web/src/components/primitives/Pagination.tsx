import type { JSX } from 'react'

import { Button } from './Button'

export interface LoadMorePillProps {
  /** The number of new items that arrived. */
  count: number
  /** The word for the items, for example "events". */
  noun?: string
  onShow: () => void
}

/**
 * The "{n} new events · Show" pill (UI_Design.md §5.14). It never re-sorts the
 * list on its own; the user decides when the new items are shown.
 */
export function LoadMorePill({ count, noun = 'events', onShow }: LoadMorePillProps): JSX.Element {
  if (count <= 0) return <></>
  return (
    <div className="load-more" role="status">
      <span className="load-more__label">{`${count} new ${noun}`}</span>
      <Button variant="tertiary" onClick={onShow}>
        Show
      </Button>
    </div>
  )
}

export interface PagingBarProps {
  /** The offset of the window that is shown. */
  offset: number
  /** The length of the window in bytes. */
  length: number
  /** The total length of the stream direction. */
  total: number
  onPrevious: () => void
  onNext: () => void
  onJump?: (offset: number) => void
  previousLabel?: string
  nextLabel?: string
}

/**
 * The 4 KB paging bar of the byte inspector (UI_Design.md §7.9). It never
 * pages past the end of the stream.
 */
export function PagingBar({
  offset,
  length,
  total,
  onPrevious,
  onNext,
  onJump,
  previousLabel = 'Previous 4 KB',
  nextLabel = 'Next 4 KB',
}: PagingBarProps): JSX.Element {
  const atStart = offset <= 0
  const atEnd = offset + length >= total

  return (
    <div className="paging-bar">
      <Button variant="secondary" disabled={atStart} onClick={onPrevious}>
        {previousLabel}
      </Button>
      <span className="paging-bar__position">{`bytes ${offset.toLocaleString('en-US')}–${(offset + length).toLocaleString('en-US')}`}</span>
      {onJump ? (
        <button type="button" className="button button--tertiary" onClick={() => onJump(offset)}>
          Jump to…
        </button>
      ) : null}
      <Button variant="secondary" disabled={atEnd} onClick={onNext}>
        {nextLabel}
      </Button>
    </div>
  )
}
