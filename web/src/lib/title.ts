import { useEffect } from 'react'

import { MASK_FAVICON, MASK_FAVICON_FAILED, MASK_FAVICON_WORKING } from '../assets/brand'
import type { CaseTab } from './router'

export type FaviconState = 'normal' | 'working' | 'failed'

const FAVICONS: Record<FaviconState, string> = {
  normal: MASK_FAVICON,
  working: MASK_FAVICON_WORKING,
  failed: MASK_FAVICON_FAILED,
}

/** The browser tab title (UI_Design.md §12.11). */
export function buildTitle(options: {
  fileName?: string
  status?: 'running' | 'failed' | 'ready'
  percent?: number
  view?: CaseTab | null
  unknown?: boolean
}): string {
  if (options.unknown) return 'RACCOON — Not found'
  if (!options.fileName) return 'RACCOON — Follow the trail'
  const viewName =
    options.view === 'files'
      ? 'Files'
      : options.view === 'streams'
        ? 'Streams'
        : options.view === 'storyboard'
          ? 'Storyboard'
          : null
  if (options.status === 'running') {
    const percent = options.percent ?? 0
    return `(${Math.round(percent)}%) RACCOON — ${options.fileName} — Analysing`
  }
  if (options.status === 'failed') return `RACCOON — ${options.fileName} — Analysis failed`
  return viewName
    ? `RACCOON — ${options.fileName} — ${viewName}`
    : `RACCOON — ${options.fileName}`
}

/** Keeps the browser tab title in sync with the open case. */
export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title
  }, [title])
}

/** Swaps the favicon between the normal, working and failed variants (§10.9). */
export function useFavicon(state: FaviconState): void {
  useEffect(() => {
    let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
    if (!link) {
      link = document.createElement('link')
      link.rel = 'icon'
      document.head.appendChild(link)
    }
    link.href = FAVICONS[state]
  }, [state])
}
