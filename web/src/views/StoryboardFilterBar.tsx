import { useEffect, useRef, useState, type JSX, type RefObject } from 'react'

import type { Severity } from '../api/types'
import { Icon } from '../assets/icons'
import { SEVERITY_LABEL } from '../components/content/Badges'
import { FilterChip } from '../components/primitives/FilterChip'
import { SearchField } from '../components/primitives/Field'
import { MultiSelect, type SelectOption } from '../components/primitives/Select'
import { formatElapsedRange } from '../lib/format'
import type { StoryboardFilters } from '../lib/storyboard'

/**
 * The filter bar of the storyboard (UI_Design.md §5.15). The controls sit in
 * one row, the active filters appear as removable chips under the bar, and the
 * result count is a live region.
 */

/** The time the search field waits before it filters the list. */
export const SEARCH_DEBOUNCE_MS = 250

const SEVERITY_OPTIONS: SelectOption[] = [
  { value: 'critical', label: SEVERITY_LABEL.critical, icon: 'critical' },
  { value: 'warning', label: SEVERITY_LABEL.warning, icon: 'warning' },
  { value: 'info', label: SEVERITY_LABEL.info, icon: 'info' },
]

const PROTOCOL_OPTIONS: SelectOption[] = [
  { value: 'ftp', label: 'FTP' },
  { value: 'ftp-data', label: 'FTP data' },
  { value: 'http', label: 'HTTP' },
  { value: 'dns', label: 'DNS' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'unknown', label: 'Other' },
]

export interface StoryboardFilterBarProps {
  filters: StoryboardFilters
  onChange: (filters: StoryboardFilters) => void
  /** The number of events of the case. */
  total: number
  /** The number of events that pass the filters. */
  matching: number
  /** The event types present in the case. */
  types: string[]
  /** The protocols present in the case. */
  protos: string[]
  /** The phases present in the case; the control is hidden without them. */
  phases: string[]
  onClearAll: () => void
  onPreviousCritical: () => void
  onNextCritical: () => void
  /** True when a critical event exists to jump to. */
  canJumpCritical: boolean
  onPreviousWarning: () => void
  onNextWarning: () => void
  /** True when a warning event exists to jump to. */
  canJumpWarning: boolean
  /** The reference of the search field; "/" focuses it. */
  searchRef?: RefObject<HTMLInputElement>
}

export function StoryboardFilterBar({
  filters,
  onChange,
  total,
  matching,
  types,
  protos,
  phases,
  onClearAll,
  onPreviousCritical,
  onNextCritical,
  canJumpCritical,
  onPreviousWarning,
  onNextWarning,
  canJumpWarning,
  searchRef,
}: StoryboardFilterBarProps): JSX.Element {
  const [moreOpen, setMoreOpen] = useState(false)
  const more = useRef<HTMLDivElement | null>(null)

  // The search field waits 250 ms before it filters, so a long word does not
  // filter the list once per keystroke (§5.15).
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

  useEffect(() => {
    if (!moreOpen) return
    const onDocumentClick = (event: MouseEvent) => {
      if (more.current && !more.current.contains(event.target as Node)) setMoreOpen(false)
    }
    document.addEventListener('mousedown', onDocumentClick)
    return () => document.removeEventListener('mousedown', onDocumentClick)
  }, [moreOpen])

  const severityOptions = SEVERITY_OPTIONS.map((option) => ({
    ...option,
    icon: option.icon as 'critical' | 'warning' | 'info',
  }))
  const typeOptions: SelectOption[] = types.map((type) => ({ value: type, label: type }))
  const protocolOptions: SelectOption[] = PROTOCOL_OPTIONS.filter(
    (option) => protos.length === 0 || protos.includes(option.value),
  ).map((option) => ({ value: option.value, label: option.label }))
  const phaseOptions: SelectOption[] = phases.map((phase) => ({ value: phase, label: phase }))

  const active = (
    filters.severities.length > 0 ||
    filters.types.length > 0 ||
    filters.protos.length > 0 ||
    filters.phases.length > 0 ||
    filters.query.trim().length > 0 ||
    filters.from !== null ||
    filters.to !== null ||
    filters.findingsOnly
  )

  const withSeverities = (values: string[]) =>
    onChange({ ...filters, severities: values as Severity[] })

  return (
    <div className="storyboard-filters">
      <div className="storyboard-filters__row">
        <div className="storyboard-filters__search">
          <SearchField
            label="Search events"
            placeholder="Search events"
            value={query}
            onChange={(value) => {
              dirtyQuery.current = true
              setQuery(value)
            }}
            inputRef={searchRef}
          />
        </div>

        <MultiSelect
          label="Severity"
          options={severityOptions}
          values={filters.severities}
          onChange={withSeverities}
        />

        <MultiSelect
          label="Event type"
          options={typeOptions}
          values={filters.types}
          onChange={(values) => onChange({ ...filters, types: values })}
          searchable
        />

        <div className="storyboard-filters__wide">
          <MultiSelect
            label="Protocol"
            options={protocolOptions}
            values={filters.protos}
            onChange={(values) => onChange({ ...filters, protos: values })}
          />
        </div>

        {phases.length > 0 ? (
          <div className="storyboard-filters__wide">
            <MultiSelect
              label="Phase"
              options={phaseOptions}
              values={filters.phases}
              onChange={(values) => onChange({ ...filters, phases: values })}
            />
          </div>
        ) : null}

        <div className="storyboard-filters__more" ref={more}>
          <button
            type="button"
            className="button button--secondary storyboard-filters__more-button"
            aria-expanded={moreOpen}
            onClick={() => setMoreOpen((open) => !open)}
          >
            More filters
          </button>
          {moreOpen ? (
            <div className="storyboard-filters__more-menu">
              <MultiSelect
                label="Protocol"
                options={protocolOptions}
                values={filters.protos}
                onChange={(values) => onChange({ ...filters, protos: values })}
              />
              {phases.length > 0 ? (
                <MultiSelect
                  label="Phase"
                  options={phaseOptions}
                  values={filters.phases}
                  onChange={(values) => onChange({ ...filters, phases: values })}
                />
              ) : null}
            </div>
          ) : null}
        </div>

        <div className="storyboard-filters__jump">
          <button
            type="button"
            className="icon-button"
            aria-label="Previous critical event"
            disabled={!canJumpCritical}
            onClick={onPreviousCritical}
          >
            <Icon name="chevron-up" size={16} />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label="Next critical event"
            disabled={!canJumpCritical}
            onClick={onNextCritical}
          >
            <Icon name="chevron-down" size={16} />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label="Previous warning event"
            disabled={!canJumpWarning}
            onClick={onPreviousWarning}
          >
            <Icon name="chevron-up" size={16} />
          </button>
          <button
            type="button"
            className="icon-button"
            aria-label="Next warning event"
            disabled={!canJumpWarning}
            onClick={onNextWarning}
          >
            <Icon name="chevron-down" size={16} />
          </button>
        </div>

        <p className="storyboard-filters__count" aria-live="polite">
          {`${matching} of ${total} events`}
        </p>

        {active ? (
          <button type="button" className="button button--tertiary" onClick={onClearAll}>
            Clear all
          </button>
        ) : null}
      </div>

      {active ? (
        <div className="storyboard-filters__chips">
          {filters.severities.map((severity) => (
            <FilterChip
              key={`sev-${severity}`}
              label={SEVERITY_LABEL[severity]}
              onRemove={() =>
                withSeverities(filters.severities.filter((item) => item !== severity))
              }
            />
          ))}
          {filters.types.map((type) => (
            <FilterChip
              key={`type-${type}`}
              label={type}
              onRemove={() => onChange({ ...filters, types: filters.types.filter((i) => i !== type) })}
            />
          ))}
          {filters.protos.map((proto) => (
            <FilterChip
              key={`proto-${proto}`}
              label={proto}
              onRemove={() => onChange({ ...filters, protos: filters.protos.filter((i) => i !== proto) })}
            />
          ))}
          {filters.phases.map((phase) => (
            <FilterChip
              key={`phase-${phase}`}
              label={phase}
              onRemove={() => onChange({ ...filters, phases: filters.phases.filter((i) => i !== phase) })}
            />
          ))}
          {filters.findingsOnly ? (
            <FilterChip
              label="Findings"
              onRemove={() => onChange({ ...filters, findingsOnly: false })}
            />
          ) : null}
          {filters.query.trim().length > 0 ? (
            <FilterChip
              label={`“${filters.query}”`}
              onRemove={() => onChange({ ...filters, query: '' })}
            />
          ) : null}
          {filters.from !== null || filters.to !== null ? (
            <FilterChip
              label={
                filters.from !== null && filters.to !== null
                  ? formatElapsedRange(filters.from, filters.to)
                  : filters.from !== null
                    ? `From ${formatElapsedRange(filters.from, filters.from)}`
                    : `Until ${formatElapsedRange(filters.to ?? 0, filters.to ?? 0)}`
              }
              onRemove={() => onChange({ ...filters, from: null, to: null })}
            />
          ) : null}
        </div>
      ) : null}
    </div>
  )
}
