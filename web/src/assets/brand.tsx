import type { JSX } from 'react'

/**
 * Brand marks (UI_Design.md §1.5, §10.9). Everything is drawn from simple
 * primitives, so there is no image file and no remote asset.
 */

export interface MaskMarkProps {
  size?: number
  className?: string
  title?: string
}

/** The abstract bandit-mask mark used in the header, the favicon and empty states. */
export function MaskMark({ size = 24, className, title }: MaskMarkProps): JSX.Element {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 48 48"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      <path
        d="M6 16c0-5 8-9 18-9s18 4 18 9v8c0 8-8 16-18 16S6 32 6 24Z"
        fill="none"
        stroke="currentColor"
        strokeWidth="3"
        strokeLinejoin="round"
      />
      <path
        d="M13 20c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S14 23 13 20Zm13.5 0c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S27.5 23 26.5 20Z"
        fill="currentColor"
        stroke="none"
      />
      <path
        d="M18 33c3.5 2 8.5 2 12 0"
        fill="none"
        stroke="currentColor"
        strokeWidth="2.5"
        strokeLinecap="round"
      />
    </svg>
  )
}

export interface PawMarkProps {
  size?: number
  className?: string
  title?: string
}

/** The paw print used in empty, unknown and failure states: one pad, four toes. */
export function PawMark({ size = 48, className, title }: PawMarkProps): JSX.Element {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 64 64"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      <ellipse cx="32" cy="44" rx="15" ry="12" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <ellipse cx="13" cy="26" rx="6" ry="7.5" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <ellipse cx="25" cy="17" rx="6" ry="8" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <ellipse cx="40" cy="17" rx="6" ry="8" fill="none" stroke="currentColor" strokeWidth="2.5" />
      <ellipse cx="52" cy="26" rx="6" ry="7.5" fill="none" stroke="currentColor" strokeWidth="2.5" />
    </svg>
  )
}

/** The favicon: the mask mark as an inline SVG data URL (§10.9). */
export const MASK_FAVICON =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath d='M6 16c0-5 8-9 18-9s18 4 18 9v8c0 8-8 16-18 16S6 32 6 24Z' fill='none' stroke='%231E293B' stroke-width='3' stroke-linejoin='round'/%3E%3Cpath d='M13 20c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S14 23 13 20Zm13.5 0c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S27.5 23 26.5 20Z' fill='%231E293B'/%3E%3C/svg%3E"

/** The working favicon: the mask with a ring around it. */
export const MASK_FAVICON_WORKING =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Ccircle cx='24' cy='24' r='22' fill='none' stroke='%231E293B' stroke-width='2'/%3E%3Cpath d='M6 16c0-5 8-9 18-9s18 4 18 9v8c0 8-8 16-18 16S6 32 6 24Z' fill='none' stroke='%231E293B' stroke-width='3' stroke-linejoin='round'/%3E%3Cpath d='M13 20c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S14 23 13 20Zm13.5 0c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S27.5 23 26.5 20Z' fill='%231E293B'/%3E%3C/svg%3E"

/** The failed favicon: the mask with a small octagon badge. */
export const MASK_FAVICON_FAILED =
  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 48 48'%3E%3Cpath d='M6 16c0-5 8-9 18-9s18 4 18 9v8c0 8-8 16-18 16S6 32 6 24Z' fill='none' stroke='%231E293B' stroke-width='3' stroke-linejoin='round'/%3E%3Cpath d='M13 20c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S14 23 13 20Zm13.5 0c2.5-2 6-2 8.5 0-1 3-2.5 5-4.25 5S27.5 23 26.5 20Z' fill='%231E293B'/%3E%3Cpath d='M36 30h8l5 5v8l-5 5h-8l-5-5v-8Z' fill='%23B91C1C'/%3E%3C/svg%3E"
