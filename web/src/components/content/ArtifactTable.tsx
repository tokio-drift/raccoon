import type { JSX, ReactNode } from 'react'

import { ConfidenceTag, VerdictBadge, type Confidence, type VerdictStatus } from './Badges'
import { CopyButton } from '../primitives/CopyButton'
import { Icon, type IconName } from '../../assets/icons'
import { formatByteCount } from '../../lib/format'

export type SortDirection = 'ascending' | 'descending' | 'none'

export interface ArtifactColumn {
  key: string
  label: string
  /** The column can be sorted. */
  sortable?: boolean
  /** The current sort state of the column. */
  sort?: SortDirection
  onSort?: () => void
  /** The column is hidden below 1280 px. */
  optional?: boolean
  align?: 'left' | 'right' | 'center'
}

export interface ArtifactTableProps {
  columns: ArtifactColumn[]
  /** The rows of the table. */
  children: ReactNode
  /** The caption of the table, for screen readers. */
  caption: string
}

/** A tag under the name of a file (§6.2, §6.3). */
export interface ArtifactNameTag {
  label: string
  /** The explanation shown as the tooltip. */
  tooltip?: string
  /** The tag warns about the file. */
  warning?: boolean
}

export interface ArtifactRowProps {
  /** The file id of the row. */
  fileId: number
  /** The display name; it is rendered as inert text. */
  name: string
  /** The shortened name of the table cell; the full name stays in the tooltip. */
  shortName?: string
  /** The sub-line under the name, for example the extension ".png". */
  nameSubline?: string
  /** The tags under the name: path-like, unusual characters, a mismatch. */
  nameTags?: ArtifactNameTag[]
  /** The icon of the format. */
  icon?: IconName
  /** The format and the extension, for example "PNG image · .png". */
  format?: string
  /** The endpoints, for example "192.0.2.14:51822 → 192.0.2.50:21". */
  endpoints?: string
  /** The direction chip of the endpoints. */
  direction?: { label: string; icon: IconName }
  /** The size in bytes. */
  size?: number
  /** The verdict of the file. */
  verdict?: { status: VerdictStatus; score?: number; total?: number; source?: string; checkedAt?: string }
  /** The extraction status, for example "Complete". */
  extraction?: string
  /** The icon of the extraction status (§6.3). */
  extractionIcon?: IconName
  /** The extraction status warns about the file. */
  extractionWarning?: boolean
  /** The confidence of the carve. */
  confidence?: Confidence
  /** The SHA-256 of the file. */
  sha256?: string
  /** The row is the selected one. */
  selected?: boolean
  /** The row is a low-confidence file that is shown anyway. */
  lowConfidence?: boolean
  /** The row was updated by a live verdict. */
  updated?: boolean
  onSelect?: () => void
  /** The actions of the row, in the last cell. */
  actions?: ReactNode
  /** The number of the row, for the aria row index. */
  rowIndex?: number
  /** The number of rows in the table, for the aria row count. */
  rowCount?: number
}

/**
 * The artifact table (UI_Design.md §6.1, §11). It is a real table with a
 * sticky header and sortable headers that carry `aria-sort`.
 */
export function ArtifactTable({ columns, children, caption }: ArtifactTableProps): JSX.Element {
  return (
    <table className="table artifact-table">
      <caption className="live-region">{caption}</caption>
      <thead>
        <tr>
          {columns.map((column) => (
            <th
              key={column.key}
              scope="col"
              className={column.optional ? 'table__cell table__cell--optional' : 'table__cell'}
              aria-sort={column.sortable ? (column.sort ?? 'none') : undefined}
              style={column.align ? { textAlign: column.align } : undefined}
            >
              {column.sortable ? (
                <button
                  type="button"
                  className="table__sort"
                  onClick={column.onSort}
                  aria-label={`Sort by ${column.label}`}
                >
                  {column.label}
                </button>
              ) : (
                column.label
              )}
            </th>
          ))}
        </tr>
      </thead>
      <tbody>{children}</tbody>
    </table>
  )
}

/**
 * A row of the artifact table (UI_Design.md §6.1). A low-confidence file has a
 * dashed bottom border and muted text; the row never re-sorts itself.
 */
export function ArtifactRow({
  fileId,
  name,
  shortName,
  nameSubline,
  nameTags,
  icon,
  format,
  endpoints,
  direction,
  size,
  verdict,
  extraction,
  extractionIcon,
  extractionWarning = false,
  confidence,
  sha256,
  selected = false,
  lowConfidence = false,
  updated = false,
  onSelect,
  actions,
  rowIndex,
  rowCount,
}: ArtifactRowProps): JSX.Element {
  const classes = ['table__row']
  if (selected) classes.push('table__row--selected')
  if (lowConfidence) classes.push('table__row--low-confidence')
  if (updated) classes.push('table__row--updated')

  return (
    <tr
      className={classes.join(' ')}
      aria-selected={selected}
      aria-rowindex={rowIndex}
      aria-rowcount={rowCount}
      data-file-id={fileId}
      tabIndex={0}
      onClick={onSelect}
      onKeyDown={(event) => {
        if (event.key !== 'Enter' && event.key !== ' ') return
        if (event.target instanceof HTMLElement && event.target.closest('button, a, input')) return
        event.preventDefault()
        onSelect?.()
      }}
    >
      <td className="table__cell">
        <span className="artifact-cell__name">
          {icon ? <Icon name={icon} size={18} /> : null}
          <span className="artifact-cell__title" title={name} dir="auto">
            {shortName ?? name}
          </span>
          {nameSubline ? <span className="artifact-cell__subline">{nameSubline}</span> : null}
          {nameTags && nameTags.length > 0 ? (
            <span className="artifact-cell__tags">
              {nameTags.map((tag) => (
                <span
                  key={tag.label}
                  className={tag.warning ? 'tag tag--warning' : 'tag tag--plain'}
                  title={tag.tooltip}
                >
                  {tag.label}
                </span>
              ))}
            </span>
          ) : null}
        </span>
        <CopyButton value={name} label="Copy file name" />
      </td>
      <td className="table__cell">{format ?? '—'}</td>
      <td className="table__cell table__cell--optional">
        {endpoints ? (
          <span className="artifact-cell__endpoints">
            {direction ? (
              <span
                className={
                  direction.icon === 'direction-left'
                    ? 'direction-chip direction-chip--s2c'
                    : 'direction-chip direction-chip--c2s'
                }
                title={direction.label}
              >
                <Icon name={direction.icon} size={14} />
                <span>{direction.label}</span>
              </span>
            ) : null}
            <span className="artifact-cell__hash">{endpoints}</span>
          </span>
        ) : (
          '—'
        )}
      </td>
      <td className="table__cell" style={{ textAlign: 'right' }}>
        {size === undefined ? '—' : formatByteCount(size)}
      </td>
      <td className="table__cell">
        {verdict ? (
          <VerdictBadge
            status={verdict.status}
            score={verdict.score}
            total={verdict.total}
            source={verdict.source}
            checkedAt={verdict.checkedAt}
            updating={updated}
          />
        ) : (
          <VerdictBadge status="not_checked" />
        )}
      </td>
      <td className={extractionWarning ? 'table__cell table__cell--warning' : 'table__cell'}>
        {extraction ? (
          <span className="artifact-cell__extraction">
            {extractionIcon ? <Icon name={extractionIcon} size={14} /> : null}
            <span>{extraction}</span>
          </span>
        ) : (
          '—'
        )}
      </td>
      <td className="table__cell table__cell--optional">
        {confidence ? <ConfidenceTag confidence={confidence} /> : '—'}
      </td>
      <td className="table__cell table__cell--optional">
        {sha256 ? <span className="artifact-cell__hash">{sha256}</span> : '—'}
      </td>
      <td className="table__cell" style={{ textAlign: 'center' }}>
        {actions}
      </td>
    </tr>
  )
}
