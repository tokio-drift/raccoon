import type { JSX } from 'react'

import { Icon, type IconName } from '../../assets/icons'

export type StatusKind = 'queued' | 'running' | 'checking' | 'ready' | 'failed' | 'partial' | 'disconnected'

export interface StatusPillProps {
  kind: StatusKind
  /** The text shown in the pill; each state has an exact wording. */
  label: string
}

const PILL_CLASS: Record<StatusKind, string> = {
  queued: 'pill',
  running: 'pill pill--running',
  checking: 'pill pill--running',
  ready: 'pill pill--ready',
  failed: 'pill pill--failed',
  partial: 'pill pill--partial',
  disconnected: 'pill pill--disconnected',
}

/** The status pill of the header (UI_Design.md §4.2). */
export function StatusPill({ kind, label }: StatusPillProps): JSX.Element {
  let icon: IconName | null = null
  if (kind === 'ready') icon = 'flag'
  if (kind === 'failed' || kind === 'partial') icon = 'critical'
  if (kind === 'disconnected') icon = 'link-broken'

  return (
    <span className={PILL_CLASS[kind]} role="status">
      {kind === 'running' || kind === 'checking' ? (
        <span className="spinner" aria-hidden="true" />
      ) : icon ? (
        <Icon name={icon} size={16} />
      ) : (
        <span className="pill__dot" aria-hidden="true" />
      )}
      {label}
    </span>
  )
}
