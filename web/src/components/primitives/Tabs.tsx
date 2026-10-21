import type { JSX, KeyboardEvent } from 'react'

import { formatCount } from '../../lib/format'

export interface TabItem<T extends string> {
  id: T
  label: string
  /** The count shown next to the label, for example the number of files. */
  count?: number
  disabled?: boolean
}

export interface TabsProps<T extends string> {
  items: TabItem<T>[]
  /** The id of the selected tab. */
  active: T
  onSelect: (id: T) => void
  /** The accessible name of the tab list. */
  label: string
  /** The id of the panel the tabs control. */
  panelId?: string
}

/**
 * A tab list (UI_Design.md §4.2, §11). The arrow keys move between the tabs,
 * Home and End jump to the first and the last one, and the selected tab is
 * the only one in the tab order.
 */
export function Tabs<T extends string>({
  items,
  active,
  onSelect,
  label,
  panelId = 'case-panel',
}: TabsProps<T>): JSX.Element {
  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    const index = items.findIndex((item) => item.id === active)
    if (index < 0) return
    let next = index
    if (event.key === 'ArrowRight') next = (index + 1) % items.length
    else if (event.key === 'ArrowLeft') next = (index - 1 + items.length) % items.length
    else if (event.key === 'Home') next = 0
    else if (event.key === 'End') next = items.length - 1
    else return
    event.preventDefault()
    onSelect(items[next].id)
  }

  return (
    <div className="tabs" role="tablist" aria-label={label} onKeyDown={onKeyDown}>
      {items.map((item) => {
        const selected = item.id === active
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={`tab-${item.id}`}
            className="tab"
            aria-selected={selected}
            aria-controls={panelId}
            tabIndex={selected ? 0 : -1}
            disabled={item.disabled}
            onClick={() => onSelect(item.id)}
          >
            {item.label}
            {item.count !== undefined ? (
              <span className="tab__count" aria-label={`${formatCount(item.count)} ${item.label.toLowerCase()}`}>
                {formatCount(item.count)}
              </span>
            ) : null}
          </button>
        )
      })}
    </div>
  )
}
