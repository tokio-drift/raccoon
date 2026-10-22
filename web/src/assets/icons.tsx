import type { JSX, ReactNode } from 'react'

/**
 * In-house icon set (UI_Design.md §10.7).
 *
 * Outline icons drawn on a 24 px grid with a 1.5 px stroke, round caps and
 * round joins, recoloured by `currentColor`. They are inline SVG, so there is
 * no icon package, no font and no remote asset.
 */
export type IconName =
  | 'info'
  | 'warning'
  | 'critical'
  | 'storyboard'
  | 'files'
  | 'streams'
  | 'graph'
  | 'ftp'
  | 'ftp-data'
  | 'http'
  | 'dns'
  | 'tcp'
  | 'udp'
  | 'unknown-proto'
  | 'unknown-event'
  | 'file'
  | 'archive'
  | 'image'
  | 'executable'
  | 'verdict-malicious'
  | 'verdict-suspicious'
  | 'verdict-no-detections'
  | 'verdict-unknown'
  | 'verdict-not-checked'
  | 'direction-right'
  | 'direction-left'
  | 'download'
  | 'copy'
  | 'check'
  | 'search'
  | 'filter'
  | 'close'
  | 'chevron-left'
  | 'chevron-right'
  | 'chevron-up'
  | 'chevron-down'
  | 'upload'
  | 'export'
  | 'settings'
  | 'help'
  | 'eye'
  | 'eye-slash'
  | 'bookmark'
  | 'group'
  | 'gap'
  | 'lock'
  | 'flag'
  | 'link-broken'

const STROKE = {
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
} as const

const PATHS: Record<IconName, ReactNode> = {
  info: (
    <>
      <circle cx="12" cy="12" r="9" {...STROKE} />
      <path d="M12 11v5" {...STROKE} />
      <circle cx="12" cy="7.5" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  warning: (
    <>
      <path d="M12 3.5 21.5 19.5H2.5Z" {...STROKE} />
      <path d="M12 9.5v4.5" {...STROKE} />
      <circle cx="12" cy="16.8" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  critical: (
    <>
      <path
        d="M8.5 2.5h7l6 6v7l-6 6h-7l-6-6v-7Z"
        {...STROKE}
      />
      <path d="M12 7v6" {...STROKE} />
      <circle cx="12" cy="16.8" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  storyboard: (
    <>
      <path d="M4 5v14" {...STROKE} />
      <path d="M4 6h16M4 12h16M4 18h16" {...STROKE} />
    </>
  ),
  files: (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
    </>
  ),
  streams: (
    <>
      <path d="M3 9h14m0 0-3-3m3 3-3 3" {...STROKE} />
      <path d="M21 15H7m0 0 3-3m-3 3 3 3" {...STROKE} />
    </>
  ),
  graph: (
    <>
      <circle cx="5" cy="18" r="2.5" {...STROKE} />
      <circle cx="12" cy="6" r="2.5" {...STROKE} />
      <circle cx="19" cy="16" r="2.5" {...STROKE} />
      <path d="m6.8 16.3 3.7-7.9m2.6 2.3 3.6 4.2" {...STROKE} />
    </>
  ),
  ftp: (
    <>
      <path d="M3 6h6l2 2h10v11H3Z" {...STROKE} />
      <path d="M12 20v-7m0 0-2 2m2-2 2 2" {...STROKE} />
    </>
  ),
  'ftp-data': (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <path d="M10 13h8m0 0-2-2m2 2-2 2" {...STROKE} />
    </>
  ),
  http: (
    <>
      <rect x="3" y="5" width="18" height="14" rx="2" {...STROKE} />
      <path d="M3 9h18" {...STROKE} />
    </>
  ),
  dns: (
    <>
      <path d="M8 3v18" {...STROKE} />
      <path d="M8 7h11l-3 3 3 3H8" {...STROKE} />
      <path d="M8 16h7l-2.5 2.5L15 21H8" {...STROKE} />
    </>
  ),
  tcp: (
    <>
      <path d="M3 8h10m0 0-3-3m3 3-3 3" {...STROKE} />
      <path d="M21 16H11m0 0 3-3m-3 3 3 3" {...STROKE} />
    </>
  ),
  udp: (
    <>
      <path d="M4 12h14" strokeDasharray="3 3" {...STROKE} />
      <path d="m14 8 4 4-4 4" {...STROKE} />
    </>
  ),
  'unknown-proto': (
    <>
      <rect x="4" y="4" width="16" height="16" rx="2" {...STROKE} />
      <path d="M9.5 9.5a2.5 2.5 0 1 1 3.2 2.4V13" {...STROKE} />
      <circle cx="12" cy="16.5" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  // The generic card of an event type this build does not know (§5.12).
  'unknown-event': (
    <>
      <rect x="4" y="4" width="16" height="16" rx="2" strokeDasharray="3 3" {...STROKE} />
      <path d="M9.5 9.5a2.5 2.5 0 1 1 3.2 2.4V13" {...STROKE} />
      <circle cx="12" cy="16.5" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  file: (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <path d="M9 13h6M9 16h6" {...STROKE} />
    </>
  ),
  archive: (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <path d="M11 8h2v9h-2Z" {...STROKE} />
    </>
  ),
  image: (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <rect x="9" y="12" width="6" height="5" {...STROKE} />
    </>
  ),
  executable: (
    <>
      <path d="M6 3h8l4 4v14H6Z" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <circle cx="12" cy="14" r="2.5" {...STROKE} />
      <path d="M12 9.5v1.5M12 17v1.5" {...STROKE} />
    </>
  ),
  'verdict-malicious': (
    <>
      <path d="M12 3 5 6v6c0 4.2 2.9 7.7 7 9 4.1-1.3 7-4.8 7-9V6Z" {...STROKE} />
      <path d="m9.5 9.5 5 5m0-5-5 5" {...STROKE} />
    </>
  ),
  'verdict-suspicious': (
    <>
      <path d="M12 3 5 6v6c0 4.2 2.9 7.7 7 9 4.1-1.3 7-4.8 7-9V6Z" {...STROKE} />
      <path d="M12 8.5v4" {...STROKE} />
      <circle cx="12" cy="15.5" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  'verdict-no-detections': (
    <>
      <path d="M12 3 5 6v6c0 4.2 2.9 7.7 7 9 4.1-1.3 7-4.8 7-9V6Z" {...STROKE} />
      <path d="M9 12h6" {...STROKE} />
    </>
  ),
  'verdict-unknown': (
    <>
      <circle cx="12" cy="12" r="9" strokeDasharray="3 3" {...STROKE} />
      <path d="M9.8 9.8a2.2 2.2 0 1 1 2.8 2.1v1.3" {...STROKE} />
      <circle cx="12" cy="16.4" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  'verdict-not-checked': (
    <>
      <circle cx="12" cy="12" r="9" strokeDasharray="3 3" {...STROKE} />
      <circle cx="12" cy="12" r="1.4" fill="currentColor" stroke="none" />
    </>
  ),
  'direction-right': (
    <>
      <path d="M4 12h14m0 0-4-4m4 4-4 4" {...STROKE} />
    </>
  ),
  'direction-left': (
    <>
      <path d="M20 12H6m0 0 4-4m-4 4 4 4" {...STROKE} />
    </>
  ),
  download: (
    <>
      <path d="M12 4v10m0 0-3.5-3.5M12 14l3.5-3.5" {...STROKE} />
      <path d="M4 16v4h16v-4" {...STROKE} />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" {...STROKE} />
      <path d="M15 6.5V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h.5" {...STROKE} />
    </>
  ),
  check: (
    <>
      <path d="m5 12.5 4.5 4.5L19 7" {...STROKE} />
    </>
  ),
  search: (
    <>
      <circle cx="10.5" cy="10.5" r="6" {...STROKE} />
      <path d="m15 15 4.5 4.5" {...STROKE} />
    </>
  ),
  filter: (
    <>
      <path d="M3.5 5h17l-6.5 8v6l-4 2v-8Z" {...STROKE} />
    </>
  ),
  close: (
    <>
      <path d="m6 6 12 12M18 6 6 18" {...STROKE} />
    </>
  ),
  'chevron-left': (
    <>
      <path d="m14.5 6-6 6 6 6" {...STROKE} />
    </>
  ),
  'chevron-right': (
    <>
      <path d="m9.5 6 6 6-6 6" {...STROKE} />
    </>
  ),
  'chevron-up': (
    <>
      <path d="m6 14.5 6-6 6 6" {...STROKE} />
    </>
  ),
  'chevron-down': (
    <>
      <path d="m6 9.5 6 6 6-6" {...STROKE} />
    </>
  ),
  upload: (
    <>
      <path d="M12 20V10m0 0L8.5 13.5M12 10l3.5 3.5" {...STROKE} />
      <path d="M4 8V4h16v4" {...STROKE} />
    </>
  ),
  export: (
    <>
      <path d="M6 3h8l4 4v9h-4" {...STROKE} />
      <path d="M14 3v4h4" {...STROKE} />
      <path d="M12 12v8m0 0-3.5-3.5M12 20l3.5-3.5" {...STROKE} />
    </>
  ),
  settings: (
    <>
      <path d="M4 7h10M18 7h2M4 12h3M11 12h9M4 17h8M16 17h4" {...STROKE} />
      <circle cx="16" cy="7" r="2" {...STROKE} />
      <circle cx="9" cy="12" r="2" {...STROKE} />
      <circle cx="14" cy="17" r="2" {...STROKE} />
    </>
  ),
  help: (
    <>
      <circle cx="12" cy="12" r="9" {...STROKE} />
      <path d="M9.8 9.8a2.2 2.2 0 1 1 2.8 2.1v1.3" {...STROKE} />
      <circle cx="12" cy="16.4" r="0.75" fill="currentColor" stroke="none" />
    </>
  ),
  eye: (
    <>
      <path d="M2.5 12S6 5.5 12 5.5 21.5 12 21.5 12 18 18.5 12 18.5 2.5 12 2.5 12Z" {...STROKE} />
      <circle cx="12" cy="12" r="3" {...STROKE} />
    </>
  ),
  'eye-slash': (
    <>
      <path d="M2.5 12S6 5.5 12 5.5c1.4 0 2.7.4 3.8 1" {...STROKE} />
      <path d="M21.5 12s-1 1.9-2.9 3.7c-1.7 1.7-4 2.8-6.6 2.8-1.3 0-2.5-.3-3.6-.8" {...STROKE} />
      <circle cx="12" cy="12" r="3" {...STROKE} />
      <path d="m4 4 16 16" {...STROKE} />
    </>
  ),
  bookmark: (
    <>
      <path d="M7 3h10v18l-5-4-5 4Z" {...STROKE} />
    </>
  ),
  group: (
    <>
      <rect x="3" y="5" width="13" height="11" rx="2" {...STROKE} />
      <path d="M8 19h10a3 3 0 0 0 3-3V8" {...STROKE} />
    </>
  ),
  gap: (
    <>
      <path d="M3 12h18" strokeDasharray="4 3" {...STROKE} />
    </>
  ),
  lock: (
    <>
      <rect x="5" y="10" width="14" height="10" rx="2" {...STROKE} />
      <path d="M8.5 10V7.5a3.5 3.5 0 0 1 7 0V10" {...STROKE} />
    </>
  ),
  flag: (
    <>
      <path d="M6 3v18" {...STROKE} />
      <path d="M6 4h11l-2.5 4L17 12H6" {...STROKE} />
    </>
  ),
  'link-broken': (
    <>
      <path d="M10.5 13.5a3.5 3.5 0 0 0 5 0l2-2a3.54 3.54 0 0 0-5-5l-1 1" {...STROKE} />
      <path d="M13.5 10.5a3.5 3.5 0 0 0-5 0l-2 2a3.54 3.54 0 0 0 5 5l1-1" {...STROKE} />
      <path d="M4 4 20 20" {...STROKE} />
    </>
  ),
}

export interface IconProps {
  name: IconName
  size?: number
  className?: string
  /** Accessible name. Without it the icon is hidden from assistive technology. */
  title?: string
}

/** Renders one in-house outline icon. */
export function Icon({ name, size = 20, className, title }: IconProps): JSX.Element {
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      role={title ? 'img' : undefined}
      aria-hidden={title ? undefined : true}
      aria-label={title}
      focusable="false"
    >
      {title ? <title>{title}</title> : null}
      {PATHS[name]}
    </svg>
  )
}
