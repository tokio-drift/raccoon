/**
 * The diagnostic text of the error surfaces (UI_Design.md §8.5, §8.6).
 *
 * It holds the case id, the capture name, the size, the hashes, the tool
 * version, the stage, the progress, the times, the error and the browser. It
 * never holds the session token, packet content, credentials or file
 * contents.
 */

import { UI_VERSION } from './version'

export interface DiagnosticFields {
  caseId?: string | null
  fileName?: string | null
  size?: number | null
  sha256?: string | null
  toolVersion?: string | null
  stage?: string | null
  progress?: number | null
  startedAt?: string | null
  finishedAt?: string | null
  errorCode?: string | null
  errorMessage?: string | null
  /** The time of the report. */
  at?: number
}

/** The name of the browser, without the whole user agent string. */
export function browserName(): string {
  if (typeof navigator === 'undefined') return 'unknown'
  const agent = navigator.userAgent ?? ''
  if (/edg\//i.test(agent)) return 'Edge'
  if (/firefox\//i.test(agent)) return 'Firefox'
  if (/chrome\//i.test(agent)) return 'Chrome'
  if (/safari\//i.test(agent)) return 'Safari'
  return 'unknown'
}

/** Builds the diagnostic text of an error surface. */
export function buildDiagnostics(fields: DiagnosticFields = {}): string {
  const lines: string[] = ['RACCOON diagnostics']
  const add = (name: string, value: string | number | null | undefined) => {
    if (value === null || value === undefined || value === '') return
    lines.push(`${name}: ${value}`)
  }
  add('Case', fields.caseId)
  add('Capture', fields.fileName)
  add('Size', fields.size)
  add('SHA-256', fields.sha256)
  add('Tool version', fields.toolVersion)
  add('Stage', fields.stage)
  add('Progress', fields.progress)
  add('Started', fields.startedAt)
  add('Finished', fields.finishedAt)
  add('Error code', fields.errorCode)
  add('Error', fields.errorMessage)
  add('Browser', browserName())
  add('UI version', UI_VERSION)
  add('Reported', new Date(fields.at ?? Date.now()).toISOString())
  return lines.join('\n')
}

/**
 * Copies text to the clipboard. The clipboard is not always available (an
 * older browser, a denied permission), so the caller can offer the text
 * instead.
 */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (typeof navigator === 'undefined' || !navigator.clipboard) return false
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}
