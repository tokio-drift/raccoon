import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react'

import type { RaccoonApi } from '../api/api'
import { Icon } from '../assets/icons'
import { Button } from '../components/primitives/Button'
import { ContextChip } from '../components/primitives/ContextChip'
import { Drawer } from '../components/primitives/Overlay'
import { PaneResizer } from '../components/primitives/PaneResizer'
import { Skeleton } from '../components/primitives/Skeleton'
import { EmptyState, ErrorState } from '../components/primitives/States'
import { TextBlock } from '../components/content/TextBlock'
import { useIsWide } from '../hooks/useMediaQuery'
import { useResizablePane } from '../hooks/useResizablePane'
import { useStreams, type StreamDirection } from '../hooks/useStreams'
import { formatCount } from '../lib/format'
import { buildDiagnostics } from '../lib/diagnostics'
import type { URLParams } from '../lib/router'
import {
  DIRECTION_LABELS,
  escapeBytes,
  largeStreamNote,
  offsetOfPacket,
  type StreamSortKey,
} from '../lib/streams'
import { StreamsFooter } from './StreamsFooter'
import { StreamsHeaderCard } from './StreamsHeaderCard'
import { StreamsList } from './StreamsList'
import { StreamsPanes, type ByteSelection } from './StreamsPanes'
import { StreamsToolbar } from './StreamsToolbar'

/** The smallest width of the stream list, in pixels (§14.2). */
const LIST_MIN_WIDTH = 260

/** The largest width of the stream list, in pixels (§14.2). */
const LIST_MAX_WIDTH = 480

/** Where the reader came from (UI_Design.md §7.11). */
export interface StreamsOrigin {
  /** The kind of the origin. */
  kind: 'file' | 'event'
  /** The id of the file or the event. */
  id: number
  /** The label of the chip, for example "invoice.zip". */
  label: string
}

export interface StreamsViewProps {
  caseId: string
  api: RaccoonApi
  params: URLParams
  onParamsChange: (params: URLParams) => void
  /** The file or the event the reader came from. */
  origin?: StreamsOrigin | null
  /** The reader follows the origin. */
  onFollowOrigin?: () => void
  /** The reader dismisses the origin. */
  onDismissOrigin?: () => void
  /** The reader opens a file of the case. */
  onOpenFile?: (fileId: number) => void
  /** The analysis is still running. */
  partial?: boolean
  /** The analysis stopped early; the results are partial (§8.5). */
  partialResults?: boolean
  /** The start of the capture, in milliseconds. */
  captureStart?: number
  /** The time basis of the wall clock. */
  basis: 'utc' | 'local'
}

/**
 * The stream inspector (UI_Design.md §4.5, §7). The list of the streams sits
 * beside the panes from 1280 px and becomes a drawer below it.
 */
export function StreamsView({
  caseId,
  api,
  params,
  onParamsChange,
  origin,
  onFollowOrigin,
  onDismissOrigin,
  onOpenFile,
  partial = false,
  partialResults = false,
  captureStart,
  basis,
}: StreamsViewProps): JSX.Element {
  const streams = useStreams({ caseId, api, params, onParamsChange })
  const wide = useIsWide()
  // The stream list can be resized; the width is remembered (§14.2).
  const listPane = useResizablePane('streams-list', {
    min: LIST_MIN_WIDTH,
    max: LIST_MAX_WIDTH,
    fallback: 300,
  })
  const listWidth = listPane.width
  const [sort, setSort] = useState<StreamSortKey>('start')
  const [collapsed, setCollapsed] = useState<Set<number>>(() => new Set())
  const [linked, setLinked] = useState(true)
  const [wrap, setWrap] = useState(true)
  const [hexOffsets, setHexOffsets] = useState(true)
  const [selection, setSelection] = useState<ByteSelection | null>(null)
  const [drawerOpen, setDrawerOpen] = useState(false)
  const [alternativeOpen, setAlternativeOpen] = useState(false)
  const [jumpOpen, setJumpOpen] = useState(false)
  const [announcement, setAnnouncement] = useState('')

  const query = params.q ?? ''

  const setQuery = useCallback(
    (value: string) => {
      const next: URLParams = { ...params }
      if (value) next.q = value
      else delete next.q
      onParamsChange(next)
    },
    [onParamsChange, params],
  )

  const toggleCollapsed = useCallback((id: number) => {
    setCollapsed((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const selected = streams.selected
  const parent = useMemo(
    () => streams.streams.find((stream) => stream.id === selected?.parentId) ?? null,
    [streams.streams, selected],
  )
  const relatedFiles = useMemo(
    () =>
      streams.files
        .filter((file) => file.streamId === selected?.id)
        .map((file) => ({ id: file.id, name: file.displayName })),
    [streams.files, selected],
  )

  // The elapsed times are counted from the start of the capture. When the
  // shell does not know it, the first stream of the case is the best guess.
  const captureStartMs = useMemo(() => {
    if (typeof captureStart === 'number') return captureStart
    const starts = streams.streams
      .map((stream) => Date.parse(stream.startTs))
      .filter((value) => Number.isFinite(value))
    return starts.length > 0 ? Math.min(...starts) : 0
  }, [captureStart, streams.streams])

  const byteWindow = streams.window
  const bytes = useMemo(
    () => byteWindow?.model.bytes ?? new Uint8Array(0),
    [byteWindow],
  )
  const text = useMemo(
    () => escapeBytes(bytes, byteWindow?.model.offset ?? 0),
    [bytes, byteWindow],
  )

  // The direction of the panes follows the direction of the inspector.
  const directionLabel =
    streams.direction === 'both' ? 'both directions' : DIRECTION_LABELS[streams.direction]

  // The deep link names a stream that is not in the case: the view says so
  // instead of showing an empty inspector (§7.12).
  const unknownStream =
    !streams.loading &&
    streams.streams.length > 0 &&
    streams.selectedId !== null &&
    selected === null

  // The search field of the stream list, which the keyboard map focuses.
  const searchRef = useRef<HTMLInputElement>(null)

  // The keyboard map of the inspector (§7.10).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent): void => {
      const target = event.target as HTMLElement | null
      if (target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA')) return
      if (event.metaKey || event.ctrlKey || event.altKey) return
      if (event.key === '/') {
        event.preventDefault()
        searchRef.current?.focus()
        return
      }
      if (event.key === '[') {
        event.preventDefault()
        streams.previous()
        return
      }
      if (event.key === ']') {
        event.preventDefault()
        streams.next()
        return
      }
      if (event.key === 'w') {
        event.preventDefault()
        setWrap((state) => !state)
        return
      }
      if (event.key === 'l') {
        event.preventDefault()
        setLinked((state) => !state)
        return
      }
      if (event.key === 'd') {
        event.preventDefault()
        const order: StreamDirection[] = ['c2s', 's2c', 'both']
        const index = order.indexOf(streams.direction)
        const next = order[(index + 1) % order.length]
        if (next === 'both' && selected) {
          const allowed = selected.bytesC2S <= 65536 && selected.bytesS2C <= 65536
          if (!allowed) return
        }
        streams.setDirection(next)
        return
      }
      if (event.key === 'g') {
        const onNextKey = (next: KeyboardEvent): void => {
          if (next.key === 'o') {
            event.preventDefault()
            setJumpOpen(true)
          }
          window.removeEventListener('keydown', onNextKey, true)
        }
        window.addEventListener('keydown', onNextKey, true)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [streams, selected])

  // The window that is loaded is announced (§7.10).
  useEffect(() => {
    if (!byteWindow) return
    if (byteWindow.length === 0) {
      setAnnouncement('No bytes in this direction.')
      return
    }
    setAnnouncement(
      `Loaded bytes ${formatCount(byteWindow.offset)} to ${formatCount(
        byteWindow.offset + byteWindow.length - 1,
      )}.`,
    )
  }, [byteWindow])

  const list = (
    <StreamsList
      streams={streams.streams}
      selectedId={streams.selectedId}
      onSelect={(id) => {
        streams.selectStream(id)
        setDrawerOpen(false)
      }}
      query={query}
      onQueryChange={setQuery}
      sort={sort}
      onSortChange={setSort}
      collapsed={collapsed}
      onToggleCollapsed={toggleCollapsed}
      loading={streams.loading}
      searchRef={searchRef}
    />
  )

  const header = selected ? (
    <StreamsHeaderCard
      stream={selected}
      captureStart={captureStartMs}
      basis={basis}
      parent={parent}
      relatedFiles={relatedFiles}
      onOpenStream={(id) => streams.selectStream(id)}
      onOpenFile={(id) => onOpenFile?.(id)}
      onJump={() => setJumpOpen(true)}
    />
  ) : null

  const panes = selected ? (
    <>
      {header}
      <StreamsToolbar
        stream={selected}
        direction={streams.direction}
        onDirectionChange={(direction) => streams.setDirection(direction)}
        linked={linked}
        onToggleLinked={() => setLinked((state) => !state)}
        wrap={wrap}
        onToggleWrap={() => setWrap((state) => !state)}
        hexOffsets={hexOffsets}
        onToggleOffsetFormat={() => setHexOffsets((state) => !state)}
        text={text}
        bytes={bytes}
        onOpenTextAlternative={() => setAlternativeOpen(true)}
        onResetView={() => {
          streams.setDirection('c2s')
          streams.setOffset(0)
        }}
      />
      {streams.bytesError ? (
        <ErrorState
          title="Couldn't load these bytes."
          explanation="The bytes of this window did not arrive. The rest of the case is unaffected."
          code={streams.bytesError.code}
          detail={streams.bytesError.message}
          diagnostic={buildDiagnostics({
            caseId,
            errorCode: streams.bytesError.code,
            errorMessage: streams.bytesError.message,
          })}
          actions={[
            { label: 'Try again', onClick: streams.reloadBytes },
          ]}
        />
      ) : (
        <StreamsPanes
          window={byteWindow}
          otherWindow={streams.otherWindow}
          linked={linked}
          wrap={wrap}
          hexOffsets={hexOffsets}
          selection={selection}
          onSelect={setSelection}
          onOpenCarved={(fileId) => onOpenFile?.(fileId)}
          onFilterCarved={(_fileId, start) => streams.setOffset(start)}
          directionLabel={directionLabel}
        />
      )}
      <StreamsFooter
        offset={streams.offset}
        length={byteWindow?.length ?? 0}
        total={streams.total}
        onPrevious={streams.previous}
        onNext={streams.next}
        onJump={(offset) => streams.setOffset(offset)}
        onJumpPacket={(packetNo) => {
          const segments = byteWindow?.model.segments ?? []
          const offset = offsetOfPacket(segments, packetNo)
          if (offset !== null) streams.setOffset(offset)
        }}
        onLoadLarger={streams.loadLarger}
        windowSize={streams.windowSize}
        note={largeStreamNote(streams.total)}
        jumpOpen={jumpOpen}
        onJumpOpenChange={setJumpOpen}
      />
    </>
  ) : null

  return (
    <section className="streams-view" aria-labelledby="streams-view-title">
      <div className="streams-view__head">
        {origin ? (
          <ContextChip
            label={
              origin.kind === 'file'
                ? `Back to file ${origin.label}`
                : `Back to event #${origin.id} · ${origin.label}`
            }
            onFollow={onFollowOrigin}
            onDismiss={onDismissOrigin}
          />
        ) : null}
        <h1 className="streams-view__title" id="streams-view-title">
          Streams
        </h1>
        {partialResults ? <span className="tag tag--warning">Partial</span> : null}
        {!wide ? (
          <Button variant="secondary" onClick={() => setDrawerOpen(true)}>
            <Icon name="streams" size={16} />
            <span>Streams</span>
          </Button>
        ) : null}
      </div>

      <p className="live-region" role="status" aria-live="polite">
        {announcement}
      </p>

      {partial ? (
        <p className="streams-view__partial">Streams are still being rebuilt. This list may grow.</p>
      ) : null}

      <div
        className="streams-view__body"
        style={wide ? { gridTemplateColumns: `${listWidth}px 8px minmax(0, 1fr)` } : undefined}
      >
        {wide ? <div className="streams-view__list">{list}</div> : null}
        {wide ? (
          <PaneResizer
            value={listWidth}
            min={LIST_MIN_WIDTH}
            max={LIST_MAX_WIDTH}
            onChange={listPane.setWidth}
            label="Resize the stream list"
          />
        ) : null}

        <div className="streams-view__main">
          {streams.error ? (
            <ErrorState
              title="Couldn't load the streams."
              explanation="The list of the streams did not arrive. The rest of the case is unaffected."
              code={streams.error.code}
              detail={streams.error.message}
              diagnostic={buildDiagnostics({
                caseId,
                errorCode: streams.error.code,
                errorMessage: streams.error.message,
              })}
              actions={[{ label: 'Try again', onClick: streams.reloadBytes }]}
            />
          ) : unknownStream ? (
            <EmptyState
              kind="no-data"
              title={`Stream ${streams.selectedId} doesn't exist in this case.`}
              body="The link may point at a stream of another case, or at one that was never rebuilt."
              actions={[
                {
                  label: 'Open the first stream',
                  onClick: () => {
                    const first = streams.streams[0]
                    if (first) streams.selectStream(first.id)
                  },
                },
              ]}
            />
          ) : !selected ? (
            <EmptyState
              kind="no-data"
              title="Choose a stream"
              body="A stream is one conversation between two computers. Pick one on the left to read it."
            />
          ) : streams.loading ? (
            <div className="streams-view__loading">
              <Skeleton kind="header" />
              <Skeleton kind="hex" count={12} />
            </div>
          ) : (
            panes
          )}
        </div>
      </div>

      {!wide && drawerOpen ? (
        <Drawer title="Streams" onClose={() => setDrawerOpen(false)} className="drawer--streams">
          {list}
        </Drawer>
      ) : null}

      {alternativeOpen ? (
        <div className="streams-alternative" role="dialog" aria-modal="true" aria-label="Text alternative">
          <div className="dialog streams-alternative__dialog">
            <h2 className="overlay__title">Text alternative</h2>
            <TextBlock value={text} copyLabel="Copy the text" maxHeight={320} />
            <Button variant="secondary" onClick={() => setAlternativeOpen(false)}>
              Close
            </Button>
          </div>
        </div>
      ) : null}
    </section>
  )
}
