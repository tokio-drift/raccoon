import type { JSX } from 'react'

import { Icon, type IconName } from '../../assets/icons'

export type EvidenceKind = 'packets' | 'stream' | 'file' | 'partial'

export interface EvidenceChipProps {
  kind: EvidenceKind
  /** The label of the chip, for example "pkts 14–19". */
  label: string
  /** The tooltip of the chip. */
  title?: string
  onClick?: () => void
}

const EVIDENCE_ICON: Record<EvidenceKind, IconName> = {
  packets: 'flag',
  stream: 'streams',
  file: 'file',
  partial: 'gap',
}

/**
 * An evidence chip (UI_Design.md §11). It points at the packets, the stream or
 * the file that supports a finding; a partial chip is drawn with a dashed
 * outline.
 */
export function EvidenceChip({
  kind,
  label,
  title,
  onClick,
}: EvidenceChipProps): JSX.Element {
  const classes = kind === 'partial' ? 'evidence-chip evidence-chip--partial' : 'evidence-chip'

  if (!onClick) {
    return (
      <span className={classes} title={title}>
        <Icon name={EVIDENCE_ICON[kind]} size={14} />
        <span>{label}</span>
      </span>
    )
  }

  return (
    <button type="button" className={classes} title={title} onClick={onClick}>
      <Icon name={EVIDENCE_ICON[kind]} size={14} />
      <span>{label}</span>
      <Icon name="chevron-right" size={14} />
    </button>
  )
}
