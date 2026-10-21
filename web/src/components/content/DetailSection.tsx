import { useEffect, useState, type JSX, type ReactNode } from 'react'

import { Icon } from '../../assets/icons'

export interface DetailSectionProps {
  /** The heading of the section. */
  title: string
  /** The sections can be collapsed; the state is remembered per section. */
  collapsible?: boolean
  /** The key that remembers the collapsed state, for example "verdict". */
  sectionKey?: string
  /** The state of a section that is collapsed by default. */
  defaultCollapsed?: boolean
  children?: ReactNode
}

/**
 * A detail section (UI_Design.md §11). The heading is a level-three heading
 * and the collapse state is remembered per section type.
 */
export function DetailSection({
  title,
  collapsible = true,
  sectionKey,
  defaultCollapsed = false,
  children,
}: DetailSectionProps): JSX.Element {
  const storageKey = sectionKey ? `raccoon.detail.${sectionKey}` : null
  const [collapsed, setCollapsed] = useState(() => {
    if (!storageKey) return defaultCollapsed
    try {
      const stored = window.localStorage.getItem(storageKey)
      if (stored === null) return defaultCollapsed
      return stored === '1'
    } catch {
      return defaultCollapsed
    }
  })

  useEffect(() => {
    if (!storageKey) return
    try {
      window.localStorage.setItem(storageKey, collapsed ? '1' : '0')
    } catch {
      // A browser without storage keeps the state in memory only.
    }
  }, [collapsed, storageKey])

  return (
    <section className="detail-section">
      <h3 className="detail-section__heading">
        {collapsible ? (
          <button
            type="button"
            className="detail-section__toggle"
            aria-expanded={!collapsed}
            onClick={() => setCollapsed((state) => !state)}
          >
            <Icon name={collapsed ? 'chevron-right' : 'chevron-down'} size={16} />
            <span>{title}</span>
          </button>
        ) : (
          title
        )}
      </h3>
      {collapsed ? null : <div className="detail-section__body">{children}</div>}
    </section>
  )
}
