import { useEffect, useRef, useState, type JSX, type RefObject } from 'react'

import type { CarvedFile, Direction, VerdictStatus } from '../api/types'
import { Icon } from '../assets/icons'
import { FilterChip } from '../components/primitives/FilterChip'
import { SearchField } from '../components/primitives/Field'
import { MultiSelect, Select, type SelectOption } from '../components/primitives/Select'
import { EXTRACTION_LABEL, type FileFilters } from '../lib/files'

/**
 * The filter bar of the artifact gallery (UI_Design.md §6.9). The verdict,
 * the format, the direction, the extraction status, the low-confidence switch
 * and the free text all combine with AND; within a multi-select they are OR.
 */

/** The time the search field waits before it filters the list. */
export const SEARCH_DEBOUNCE_MS = 250

const VERDICT_OPTIONS: SelectOption[] = [
  { value: 'malicious', label: 'Malicious' },
  { value: 'suspicious', label: 'Suspicious' },
  { value: 'unknown', label: 'Unknown' },
  { value: 'not_checked', label: 'Not checked' },
  { value: 'no_detections', label: 'No detections' },
]

const DIRECTION_OPTIONS: SelectOption[] = [
  { value: 'any', label: 'Both directions' },
  { value: 'c2s', label: 'Sent to server' },
  { value: 's2c', label: 'Sent to client' },
]

const EXTRACTION_OPTIONS: SelectOption[] = [
  { value: 'complete', label: EXTRACTION_LABEL.complete },
  { value: 'truncated', label: EXTRACTION_LABEL.truncated },
  { value: 'corrupt', label: EXTRACTION_LABEL.corrupt },
]

export interface FilesFilterBarProps {
  filters: FileFilters
  onChange: (filters: FileFilters) => void
  /** The number of files of the case. */
  total: number
  /** The number of files that pass the filters. */
  matching: number
  /** The formats present in the case. */
  formats: string[]
  onClearAll: () => void
  /** The view is reset: the filters, the search and the selection (§3.6). */
  onResetView: () => void
  /** The reference of the search field; "/" focuses it. */
  searchRef?: RefObject<HTMLInputElement>
}

export function FilesFilterBar({
  filters,
  onChange,
  total,
  matching,
  formats,
  onClearAll,
  onResetView,
  searchRef,
}: FilesFilterBarProps): JSX.Element {
  // The search field waits 250 ms before it filters, so a long word does not
  // filter the list once per keystroke.
  const [query, setQuery] = useState(filters.query)
  const dirtyQuery = useRef(false)
  useEffect(() => {
    if (!dirtyQuery.current) setQuery(filters.query)
  }, [filters.query])
  useEffect(() => {
    if (query === filters.query) return
    const timer = window.setTimeout(() => {
      dirtyQuery.current = false
      onChange({ ...filters, query })
    }, SEARCH_DEBOUNCE_MS)
    return () => window.clearTimeout(timer)
  }, [query, filters, onChange])

  const formatOptions: SelectOption[] = formats.map((format) => ({ value: format, label: format }))

  const active =
    filters.verdicts.length > 0 ||
    filters.formats.length > 0 ||
    filters.dir !== null ||
    filters.extractions.length > 0 ||
    filters.query.trim().length > 0 ||
    filters.showLowConfidence

  const withVerdicts = (values: string[]) =>
    onChange({ ...filters, verdicts: values as VerdictStatus[] })

  return (
    <div className="files-filters">
      <div className="files-filters__row">
        <div className="files-filters__search">
          <SearchField
            label="Search files"
            placeholder="Search files"
            value={query}
            onChange={(value) => {
              dirtyQuery.current = true
              setQuery(value)
            }}
            inputRef={searchRef}
          />
        </div>

        <MultiSelect
          label="Verdict"
          options={VERDICT_OPTIONS}
          values={filters.verdicts}
          onChange={withVerdicts}
        />

        <MultiSelect
          label="Format"
          options={formatOptions}
          values={filters.formats}
          onChange={(values) => onChange({ ...filters, formats: values })}
        />

        <Select
          label="Direction"
          options={DIRECTION_OPTIONS}
          value={filters.dir ?? 'any'}
          onChange={(value) =>
            onChange({ ...filters, dir: value === 'any' ? null : (value as Direction) })
          }
        />

        <MultiSelect
          label="Extraction"
          options={EXTRACTION_OPTIONS}
          values={filters.extractions}
          onChange={(values) =>
            onChange({ ...filters, extractions: values as CarvedFile['status'][] })
          }
        />

        <label className="switch">
          <input
            type="checkbox"
            className="switch__input"
            checked={filters.showLowConfidence}
            onChange={(event) =>
              onChange({ ...filters, showLowConfidence: event.target.checked })
            }
          />
          <span className="switch__label">Show low-confidence files</span>
        </label>

        <p className="files-filters__count" aria-live="polite">
          {`${matching} of ${total} files`}
        </p>

        {active ? (
          <button type="button" className="button button--tertiary" onClick={onClearAll}>
            Clear all
          </button>
        ) : null}

        <button type="button" className="button button--tertiary" onClick={onResetView}>
          Reset view
        </button>
      </div>

      {active ? (
        <div className="files-filters__chips">
          {filters.verdicts.map((verdict) => (
            <FilterChip
              key={`verdict-${verdict}`}
              label={VERDICT_OPTIONS.find((option) => option.value === verdict)?.label ?? verdict}
              onRemove={() =>
                withVerdicts(filters.verdicts.filter((item) => item !== verdict))
              }
            />
          ))}
          {filters.formats.map((format) => (
            <FilterChip
              key={`format-${format}`}
              label={format}
              onRemove={() => onChange({ ...filters, formats: filters.formats.filter((i) => i !== format) })}
            />
          ))}
          {filters.dir !== null ? (
            <FilterChip
              label={filters.dir === 'c2s' ? 'Sent to server' : 'Sent to client'}
              onRemove={() => onChange({ ...filters, dir: null })}
            >
              <Icon
                name={filters.dir === 'c2s' ? 'direction-right' : 'direction-left'}
                size={14}
              />
            </FilterChip>
          ) : null}
          {filters.extractions.map((status) => (
            <FilterChip
              key={`extraction-${status}`}
              label={EXTRACTION_LABEL[status]}
              onRemove={() =>
                onChange({ ...filters, extractions: filters.extractions.filter((i) => i !== status) })
              }
            />
          ))}
          {filters.showLowConfidence ? (
            <FilterChip
              label="Low-confidence files"
              onRemove={() => onChange({ ...filters, showLowConfidence: false })}
            />
          ) : null}
          {filters.query.trim().length > 0 ? (
            <FilterChip
              label={`“${filters.query}”`}
              onRemove={() => onChange({ ...filters, query: '' })}
            />
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
