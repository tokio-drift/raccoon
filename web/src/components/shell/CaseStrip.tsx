import type { JSX } from 'react'

import type { CaseTab } from '../../lib/router'
import { Tabs, type TabItem } from '../primitives/Tabs'

const TABS: TabItem<CaseTab>[] = [
  { id: 'storyboard', label: 'Storyboard' },
  { id: 'files', label: 'Files' },
  { id: 'streams', label: 'Streams' },
]

export interface CaseStripProps {
  activeTab: CaseTab | null
  onSelectTab: (tab: CaseTab) => void
  filesCount: number
  streamsCount: number
  /** The quiet statistics line, rendered on the right. */
  children?: JSX.Element | null
}

/** The case strip: the tab list of the three case views (UI_Design.md §3.3, §4.2). */
export function CaseStrip({
  activeTab,
  onSelectTab,
  filesCount,
  streamsCount,
  children,
}: CaseStripProps): JSX.Element {
  const items = TABS.map((tab) => ({
    ...tab,
    count: tab.id === 'files' ? filesCount : tab.id === 'streams' ? streamsCount : undefined,
  }))

  return (
    <nav className="case-strip" aria-label="Case views">
      <Tabs
        items={items}
        active={activeTab ?? 'storyboard'}
        onSelect={onSelectTab}
        label="Case views"
      />
      {children}
    </nav>
  )
}
