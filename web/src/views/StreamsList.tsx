import { useMemo, useRef, type JSX, type RefObject } from 'react'

import { Icon } from '../assets/icons'
import { StreamRow } from '../components/content/StreamRow'
import { SearchField } from '../components/primitives/Field'
import { Select } from '../components/primitives/Select'
import { useVirtualRows } from '../hooks/useVirtualRows'
import type { StreamSummary } from '../api/types'
import {
  STREAM_SORT_OPTIONS,
  buildStreamRows,
  searchStreams,
  sortStreams,
  streamEndpoints,
  type StreamSortKey,
} from '../lib/streams'

export interface StreamsListProps {
  /** Every stream of the case. */
  streams: StreamSummary[]
  /** The id of the selected stream. */
  selectedId: number | null
  /** The reader picks a stream. */
  onSelect: (id: number) => void
  /** The text of the search field. */
  query: string
  /** The reader searches. */
  onQueryChange: (value: string) => void
  /** The sort key. */
  sort: StreamSortKey
  /** The reader changes the sort. */
  onSortChange: (sort: StreamSortKey) => void
  /** The parents whose children are hidden. */
  collapsed: Set<number>
  /** The reader folds a parent. */
  onToggleCollapsed: (id: number) => void
  /** The list is loading. */
  loading?: boolean
  /** The search field of the list, so the keyboard map can focus it. */
  searchRef?: RefObject<HTMLInputElement>
}

/**
 * The stream picker (UI_Design.md §7.1): the search field, the sort and the
 * rows, with the FTP data streams nested under their control stream.
 */
export function StreamsList({
  streams,
  selectedId,
  onSelect,
  query,
  onQueryChange,
  sort,
  onSortChange,
  collapsed,
  onToggleCollapsed,
  loading = false,
  searchRef,
}: StreamsListProps): JSX.Element {
  const rows = useMemo(() => {
    const searched = searchStreams(streams, query)
    const sorted = sortStreams(searched, sort)
    return buildStreamRows(sorted, collapsed)
  }, [streams, query, sort, collapsed])

  const rowsRef = useRef<HTMLDivElement>(null)
  // A case with many streams renders only the rows near the viewport
  // (§14.6).
  const visible = useVirtualRows({
    count: rows.length,
    containerRef: rowsRef,
    limit: 300,
    rowHeight: 64,
  })

  return (
    <div className="streams-list">
      <div className="streams-list__head">
        <SearchField
          label="Search the streams"
          value={query}
          onChange={onQueryChange}
          placeholder="Search the streams"
          inputRef={searchRef}
        />
        <Select
          label="Sort"
          options={STREAM_SORT_OPTIONS.map((option) => ({
            value: option.value,
            label: option.label,
          }))}
          value={sort}
          onChange={(value) => onSortChange(value as StreamSortKey)}
          showCount
        />
      </div>

      <div
        className="streams-list__rows"
        role="listbox"
        aria-label="Streams of the case"
        ref={rowsRef}
      >
        {loading && rows.length === 0 ? (
          <p className="streams-list__empty">Loading the streams…</p>
        ) : null}
        {!loading && rows.length === 0 ? (
          <p className="streams-list__empty">No stream matches the search.</p>
        ) : null}
        {visible.virtualised ? (
          <div className="streams-list__spacer" role="presentation" style={{ height: visible.topPad }} />
        ) : null}
        {rows.slice(visible.start, visible.end).map((row) => (
          <div key={row.stream.id} className="streams-list__item">
            {row.hasChildren ? (
              <button
                type="button"
                className="streams-list__chevron"
                aria-label={row.collapsed ? `Show the child streams of Stream ${row.stream.id}` : `Hide the child streams of Stream ${row.stream.id}`}
                aria-expanded={!row.collapsed}
                onClick={() => onToggleCollapsed(row.stream.id)}
              >
                <Icon name={row.collapsed ? 'chevron-right' : 'chevron-down'} size={16} />
              </button>
            ) : null}
            <StreamRow
              streamId={row.stream.id}
              protocol={row.stream.proto.toUpperCase()}
              endpoints={streamEndpoints(row.stream)}
              bytesC2S={row.stream.bytesC2S}
              bytesS2C={row.stream.bytesS2C}
              packets={row.stream.packets}
              selected={row.stream.id === selectedId}
              child={row.child}
              childLabel={row.childLabel}
              hasGap={row.stream.hasGaps}
              midstream={row.stream.midstream}
              onSelect={() => onSelect(row.stream.id)}
            />
          </div>
        ))}
        {visible.virtualised ? (
          <div
            className="streams-list__spacer"
            role="presentation"
            style={{ height: visible.bottomPad }}
          />
        ) : null}
      </div>
    </div>
  )
}
