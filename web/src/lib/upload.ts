/**
 * The capture file rules of the upload flow (UI_Design.md §8.1–§8.2).
 *
 * The size limit belongs to the server (`limits.UploadMaxBytes`); the API
 * exposes no route that advertises it, so the value of the server is the
 * default here and the server stays the authority.
 */

import { formatBytes } from './format'

/** The extensions the server accepts. */
export const CAPTURE_EXTENSIONS = ['.pcap', '.pcapng'] as const

/** The upload limit of the server in bytes (500 MiB, `limits.UploadMaxBytes`). */
export const UPLOAD_LIMIT_BYTES = 500 * 1024 * 1024

export type CaptureProblem = 'invalid' | 'too-large'

export interface CaptureCheck {
  ok: boolean
  /** Why the file was refused. */
  problem?: CaptureProblem
}

/** True when the name carries an accepted extension. */
export function isCaptureName(name: string): boolean {
  const lower = name.toLowerCase()
  return CAPTURE_EXTENSIONS.some((extension) => lower.endsWith(extension))
}

/**
 * The first file of a drop that carries an accepted extension. The other files
 * of the drop are ignored (UI_Design.md §8.2).
 */
export function firstCaptureFile(files: File[]): File | null {
  return files.find((file) => isCaptureName(file.name)) ?? null
}

/**
 * Checks a file before it is uploaded: first the type, then the size. The
 * order matters, because a wrong file that is also too large is reported as
 * the wrong type.
 */
export function checkCapture(file: File, limitBytes: number = UPLOAD_LIMIT_BYTES): CaptureCheck {
  if (!isCaptureName(file.name)) return { ok: false, problem: 'invalid' }
  if (file.size > limitBytes) return { ok: false, problem: 'too-large' }
  return { ok: true }
}

/**
 * The accepted-formats line of the empty dashboard: with the limit when the
 * server reports one, without it otherwise.
 */
export function captureLimitLabel(limitBytes?: number | null): string {
  if (!limitBytes) return 'Accepts .pcap and .pcapng files.'
  return `Accepts .pcap and .pcapng files up to ${formatBytes(limitBytes)}.`
}
