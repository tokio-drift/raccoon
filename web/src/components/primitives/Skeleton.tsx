import type { JSX } from 'react'

export type SkeletonKind = 'card' | 'row' | 'hex' | 'header'

export interface SkeletonProps {
  kind?: SkeletonKind
  /** The number of repeated skeleton lines. */
  count?: number
}

/**
 * A skeleton placeholder (UI_Design.md §11). The shimmer is a CSS animation;
 * under reduced motion the skeleton is a static tint.
 */
export function Skeleton({ kind = 'row', count = 1 }: SkeletonProps): JSX.Element {
  return (
    <span className="skeleton-wrap" aria-hidden="true">
      {Array.from({ length: count }, (_, index) => (
        <span key={index} className={`skeleton skeleton--${kind}`} />
      ))}
    </span>
  )
}
