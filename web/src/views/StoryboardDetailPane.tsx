import { useState, type JSX, type RefObject } from 'react'

import type { CarvedFile, CaseEvent } from '../api/types'
import type { DetailBlock, DetailValue } from '../lib/details'


/**
 * The detail pane of the storyboard (UI_Design.md §5.8–§5.9, §5.12–§5.13).
 * The list stays visible; the pane is inline on the right.
 */

export interface StoryboardDetailPaneProps {
  event: CaseEvent | null
  /** The titles of the findings that this event belongs to. */
  findingTitles: string[]
  /** The findings of the case, by their event id. */
  findings: CaseEvent[]
  /** The titles of the events this finding supports. */
  supportedTitles: Map<number, string>
  /** The events the user can jump to from the links. */
  eventsById: Map<number, CaseEvent>
  /** The file the event belongs to, when the case has one. */
  relatedFile?: CarvedFile | null
  /** The children of the selected event. */
  children?: CaseEvent[]
  /** The start of the capture; the elapsed time counts from here (§5.2). */
  captureStart?: number
  onSelectEvent: (id: number) => void
  onOpenStream?: (streamId: number, packetNo: number) => void
  onOpenFile?: (fileId: number) => void
  onClose?: () => void
  /** The reference of the pane, so the keyboard can move the focus into it. */
  paneRef?: RefObject<HTMLElement>
}

export function StoryboardDetailPane({
  event,
  findingTitles,
  findings,
  supportedTitles,
  eventsById,
  relatedFile,
  children,
  captureStart = 0,
  onSelectEvent,
  onOpenStream,
  onOpenFile,
  onClose,
  paneRef,
}: StoryboardDetailPaneProps): JSX.Element {
  const [fullTitleOpen, setFullTitle] = useState(false)
  const pane = paneRef

  if (!event) {
    return (
      <aside className="storyboard-detail" aria-label="Event details" ref={pane}>
        <p className="storyboard-detail__empty">Select an event to see its details.</p>
      </aside>
    )
  }

  const typeLabel = event.type.replace(/_/g, ' ').replace(/^\w/, (c) => c.toUpperCase())
  const isUnknownType = !KNOWN_DETAIL_TYPES.has(event.type)
  // A long title is cut to four lines; the reader can ask for all of it.
  const longTitle = (event.title ?? '').length > 120
  const detailView = buildDetailView(event)
  const tags = uncertaintyTags(event)
  // The technique of a finding is a chip of its own (§9.4).
  const technique = findingTechniqueParts(event)
  const inFindings = (event.findingIds ?? [])
    .map((id) => findings.find((f) => f.id === id))
    .filter((f): f is CaseEvent => Boolean(f))
  // The events that support a finding (§9.4).
  const supportingIds = isFindingEvent(event) ? findingEventIds(event) : []

  return (
    <aside className="storyboard-detail" aria-label="Event details" tabIndex={-1} ref={paneRef}>
      <header className="storyboard-detail__header">
        <div className="storyboard-detail__header-row">
          <SeverityBadge severity={eventSeverity(event)} />
          <span className="tag tag--plain">{typeLabel}</span>
          {event.proto ? <span className="tag tag--plain">{event.proto.toUpperCase()}</span> : null}
          {technique ? (
            <span className="tag tag--technique" title={technique.name ?? technique.id}>
              {technique.name ? `${technique.id} ${technique.name}` : technique.id}
            </span>
          ) : null}
          {onClose ? (
            <button
              type="button"
              className="icon-button storyboard-detail__close"
              aria-label="Close detail pane"
              onClick={onClose}
            >
              <Icon name="close" size={16} />
            </button>
          ) : null}
        </div>
        <h2 className="storyboard-detail__title">{event.title || 'Untitled event'}</h2>
        {longTitle ? (
          <button
            type="button"
            className="button button--tertiary storyboard-detail__full-title"
            onClick={() => setFullTitle((value) => !value)}
          >
            {fullTitleOpen ? 'Show less' : 'Show full title'}
          </button>
        ) : null}
        <p
          className="storyboard-detail__time"
          title={formatClock(parseTimestamp(event.ts), { micro: true })}
        >
          {`${formatElapsed(parseTimestamp(event.ts) - captureStart)} · ${formatClock(parseTimestamp(event.ts))}`}
        </p>
        {event.src || event.dst ? (
          <p className="storyboard-detail__endpoints" aria-label={endpointsLabel(event.src ?? '', event.dst ?? '')}>
            {(event.src ?? '') + ' → ' + (event.dst ?? '')}
          </p>
        ) : null}
        <div className="storyboard-detail__tags">
          {tags.map((tag) => (
            <span key={tag.label} className="tag tag--uncertain" title={tag.help}>
                <Icon name={tag.icon} size={14} />
                <span>{tag.label}</span>
              </span>
          ))}
          {findingTitles.map((title) => (
            <span key={title} className="tag tag--plain">
              <Icon name="bookmark" size={14} />
              <span>{title}</span>
            </span>
          ))}
        </div>
      </header>

      <div className="storyboard-detail__body">
        {event.explain ? (
          <DetailSection title="In plain words" collapsible={false}>
            <p className="storyboard-detail__text">{event.explain}</p>
          </DetailSection>
        ) : null}

        <DetailSection title="Details">
          {detailView.blocks.length === 0 ? (
            <p className="storyboard-detail__muted">No details were recorded for this event.</p>
          ) : null}
          {detailView.blocks.map((block, index) => (
            <DetailBlockView key={index} block={block} />
          ))}
        </DetailSection>

        <DetailSection title="Evidence">
          {event.packetNo > 0 || event.streamId > 0 || event.fileId > 0 || supportingIds.length > 0 ? (
            <div className="storyboard-detail__evidence">
              {event.packetNo > 0 ? (
                <EvidenceChip
                  kind="packets"
                  label={packetRangeLabel(event.packetNo, event.packetEnd) ?? `pkt ${event.packetNo}`}
                  title={event.streamId > 0 ? 'Opens the stream at this packet.' : 'This event has no stream.'}
                  onClick={
                    event.streamId > 0 && onOpenStream
                      ? () => onOpenStream(event.streamId, event.packetNo)
                      : undefined
                  }
                />
              ) : null}
              {event.streamId > 0 ? (
                <EvidenceChip
                  kind="stream"
                  label={`Stream ${event.streamId}`}
                  onClick={onOpenStream ? () => onOpenStream(event.streamId, 0) : undefined}
                />
              ) : null}
              {event.fileId > 0 ? (
                <EvidenceChip
                  kind="file"
                  label={`File ${event.fileId}`}
                  onClick={onOpenFile ? () => onOpenFile(event.fileId) : undefined}
                />
              ) : null}
              {/* A finding lists the events that support it (§9.4). */}
              {supportingIds.map((id) => {
                const supporting = eventsById.get(id)
                const title = supportedTitles.get(id) ?? supporting?.title ?? `Event ${id}`
                return (
                  <button
                    key={id}
                    type="button"
                    className="storyboard-detail__link"
                    onClick={() => onSelectEvent(id)}
                  >
                    <Icon name="flag" size={14} />
                    <span>{`Event ${id}: ${title}`}</span>
                  </button>
                )
              })}
            </div>
          ) : (
            <p className="storyboard-detail__muted">No packet evidence was recorded for this event.</p>
          )}
        </DetailSection>

        {relatedFile ? (
          <DetailSection title="Related file">
            <div className="storyboard-detail__file">
              <div className="storyboard-detail__file-head">
                <span className="storyboard-detail__file-name">
                  {relatedFile.displayName || relatedFile.path || `File ${relatedFile.id}`}
                </span>
                {relatedFile.format ? (
                  <span className="tag tag--plain">{relatedFile.format}</span>
                ) : null}
                {relatedFile.verdict ? (
                  <VerdictBadge
                    status={relatedFile.verdict.status}
                    score={relatedFile.verdict.score}
                    total={relatedFile.verdict.total}
                    source={relatedFile.verdict.source}
                  />
                ) : (
                  <span className="tag tag--uncertain">Not checked</span>
                )}
              </div>
              <p className="storyboard-detail__muted">
                {`${formatBytes(relatedFile.size)} · ${relatedFile.confidence} confidence`}
              </p>
              <Button variant="secondary" onClick={() => onOpenFile?.(relatedFile.id)}>
                Open file
              </Button>
            </div>
          </DetailSection>
        ) : null}

        {inFindings.length > 0 ? (
          <DetailSection title="Related findings">
            <ul className="storyboard-detail__list">
              {inFindings.map((finding) => (
                <li key={finding.id}>
                  <button type="button" className="storyboard-detail__link" onClick={() => onSelectEvent(finding.id)}>
                    <Icon name="bookmark" size={14} />
                    <span>{finding.title || 'Finding'}</span>
                    <SeverityBadge severity={eventSeverity(finding)} />
                  </button>
                </li>
              ))}
            </ul>
          </DetailSection>
        ) : null}

        {event.findingIds && event.findingIds.length > 0 && inFindings.length === 0 ? (
          <DetailSection title="Related findings">
            <ul className="storyboard-detail__list">
              {event.findingIds.map((id) => {
                const title = supportedTitles.get(id) ?? `Finding ${id}`
                return (
                  <li key={id}>
                    <button type="button" className="storyboard-detail__link" onClick={() => onSelectEvent(id)}>
                      <Icon name="bookmark" size={14} />
                      <span>{title}</span>
                    </button>
                  </li>
                )
              })}
            </ul>
          </DetailSection>
        ) : null}

        {event.parentId && event.parentId > 0 ? (
          <DetailSection title="Part of">
            <button type="button" className="storyboard-detail__link" onClick={() => onSelectEvent(event.parentId)}>
              <span>{`Event ${event.parentId}`}</span>
            </button>
          </DetailSection>
        ) : null}

        {children && children.length > 0 ? (
          <DetailSection title="Contains">
            <ul className="storyboard-detail__list">
              {children.map((child) => (
                <li key={child.id}>
                  <button
                    type="button"
                    className="storyboard-detail__link"
                    onClick={() => onSelectEvent(child.id)}
                  >
                    <SeverityBadge severity={eventSeverity(child)} />
                    <span>{child.title || eventTypeLabel(child.type)}</span>
                  </button>
                </li>
              ))}
            </ul>
          </DetailSection>
        ) : null}

        {detailView.other.length > 0 ? (
          <DetailSection title="Other details" defaultCollapsed={detailView.other.length > 8} sectionKey={`other-${event.id}`}>
            <table className="storyboard-detail__table">
              <tbody>
                {detailView.other.map((entry) => (
                  <tr key={entry.label}>
                    <th scope="row">{entry.label}</th>
                    <td>
                      <DetailValueView
                        value={entry.value}
                        masked={entry.masked}
                        maskLabel={entry.masked ? entry.label.toLowerCase() : undefined}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </DetailSection>
        ) : null}

        {isUnknownType && detailView.other.length === 0 ? (
          <DetailSection title="Other details">
            <p className="storyboard-detail__muted">
              The type &quot;{event.type}&quot; is not known to this build.
            </p>
            <table className="storyboard-detail__table">
              <tbody>
                <tr>
                  <th scope="row">type</th>
                  <td>{event.type}</td>
                </tr>
              </tbody>
            </table>
          </DetailSection>
        ) : null}
      </div>
    </aside>
  )
}

function DetailBlockView({ block }: { block: DetailBlock }): JSX.Element {
  return (
    <div className="storyboard-detail__block">
      {block.title ? <p className="storyboard-detail__block-title">{block.title}</p> : null}
      {block.lead ? (
        <div className="storyboard-detail__lead">
          <DetailValueView value={block.lead} />
        </div>
      ) : null}
      <table className="storyboard-detail__table">
        <tbody>
          {block.entries.map((entry) => (
            <tr key={entry.label}>
              <th scope="row">{entry.label}</th>
              <td>
                <DetailValueView
                  value={entry.value}
                  masked={entry.masked}
                  maskLabel={entry.masked ? entry.label.toLowerCase() : undefined}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {block.note ? <p className="storyboard-detail__note">{block.note}</p> : null}
    </div>
  )
}

function DetailValueView({
  value,
  masked,
  maskLabel,
}: {
  value: DetailValue
  masked?: boolean
  /** The name of the hidden value, for the reveal button (§12.7). */
  maskLabel?: string
}): JSX.Element {
  const [revealed, setRevealed] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [rawShown, setRawShown] = useState(false)
  if (masked) {
    return (
      <span className="storyboard-detail__masked">
        {revealed ? value.kind === 'text' ? value.text : stringifyValue(value) : '••••••••'}
        <button
          type="button"
          className="button button--tertiary"
          onClick={() => setRevealed((state) => !state)}
        >
          {revealed ? `Hide ${maskLabel ?? 'value'}` : `Show ${maskLabel ?? 'value'}`}
        </button>
      </span>
    )
  }
  if (value.kind === 'text') {
    return <span className="storyboard-detail__value">{value.text}</span>
  }
  if (value.kind === 'code') {
    // A long value is shown in a scrolling block; the reader can open all of
    // it and copy it (§5.8).
    return (
      <div className="storyboard-detail__code-block">
        <pre className={expanded ? 'storyboard-detail__code storyboard-detail__code--full' : 'storyboard-detail__code'}>
          {value.text}
        </pre>
        <div className="storyboard-detail__code-actions">
          <button
            type="button"
            className="button button--tertiary"
            onClick={() => setExpanded((state) => !state)}
          >
            {expanded ? 'Show less' : 'Show all'}
          </button>
          <CopyButton value={value.text} label="Copy value" showLabel />
        </div>
      </div>
    )
  }
  if (value.kind === 'list') {
    const shown = expanded ? value.items : value.items.slice(0, MAX_LIST_ITEMS)
    return (
      <div className="storyboard-detail__list-block">
        <ul className="storyboard-detail__value-list">
          {shown.map((item, index) => (
            <li key={index}>{item}</li>
          ))}
        </ul>
        {value.overflow > 0 ? (
          <button
            type="button"
            className="button button--tertiary"
            onClick={() => setExpanded((state) => !state)}
          >
            {expanded ? 'Show fewer' : `Show all ${value.items.length}`}
          </button>
        ) : null}
      </div>
    )
  }
  if (value.kind === 'object') {
    return (
      <div className="storyboard-detail__object">
        {value.entries.map((entry) => (
          <div key={entry.label} className="storyboard-detail__object-row">
            <span className="storyboard-detail__object-key">{entry.label}</span>
            <DetailValueView value={entry.value} />
          </div>
        ))}
      </div>
    )
  }
  return (
    <span className="storyboard-detail__unreadable">
      {rawShown ? (
        <code className="storyboard-detail__raw">{value.raw}</code>
      ) : (
        <>
          Couldn&apos;t read this value.
          <button
            type="button"
            className="button button--tertiary"
            onClick={() => setRawShown(true)}
          >
            Show raw
          </button>
        </>
      )}
    </span>
  )
}

function stringifyValue(value: DetailValue): string {
  if (value.kind === 'text') return value.text
  if (value.kind === 'code') return value.text
  if (value.kind === 'list') return value.items.join('\n')
  if (value.kind === 'unreadable') return value.raw
  return ''
}

const KNOWN_DETAIL_TYPES = new Set([
  'STREAM_OPENED',
  'TCP_ANOMALY',
  'FTP_LOGIN_ATTEMPT',
  'FTP_LOGIN_SUCCESS',
  'FTP_LOGIN_FAILED',
  'FTP_COMMAND',
  'FTP_FILE_TRANSFER',
  'HTTP_TRANSACTION',
  'DNS_QUERY',
  'FILE_CARVED',
  'THREAT_VERDICT',
  'FINDING',
  'GROUP',
  'OPAQUE_REGION',
])

import { Icon } from '../assets/icons'
import { SeverityBadge, VerdictBadge } from '../components/content/Badges'
import { Button } from '../components/primitives/Button'
import { CopyButton } from '../components/primitives/CopyButton'
import { DetailSection } from '../components/content/DetailSection'
import { EvidenceChip } from '../components/content/EvidenceChip'
import { buildDetailView, MAX_LIST_ITEMS } from '../lib/details'
import {
  eventSeverity,
  findingEventIds,
  findingTechniqueParts,
  isFindingEvent,
  endpointsLabel,
  packetRangeLabel,
  uncertaintyTags,
  typeLabel as eventTypeLabel,
} from '../lib/events'
import { formatBytes, formatClock, formatElapsed, parseTimestamp } from '../lib/format'
