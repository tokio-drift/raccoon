import { useCallback, useRef, useState } from 'react'

import type { RaccoonApi } from '../api/api'
import { checkCapture, firstCaptureFile, UPLOAD_LIMIT_BYTES } from '../lib/upload'

/** The states of the upload flow (UI_Design.md §8.2). */
export type UploadStatus = 'idle' | 'invalid' | 'too-large' | 'uploading' | 'processing' | 'failed'

export interface UploadState {
  status: UploadStatus
  /** The file the user chose, kept so a failed upload can be retried. */
  file: File | null
  /** The bytes that were sent. */
  uploaded: number
  /** The size of the file. */
  total: number
  /** Why the upload failed. */
  reason: string | null
  /** A one-time note under the dropzone. */
  note: string | null
  /** The number of files that were ignored in a multi-file drop. */
  ignored: number
}

const INITIAL: UploadState = {
  status: 'idle',
  file: null,
  uploaded: 0,
  total: 0,
  reason: null,
  note: null,
  ignored: 0,
}

export interface UseUploadOptions {
  /** The size limit of the server; the server value is the default. */
  limitBytes?: number | null
  /** Called with the id of the new case when the upload succeeded. */
  onUploaded?: (caseId: string) => void
}

export interface UploadApi {
  state: UploadState
  /** Starts an upload; only the first file of a drop is used. */
  start: (files: File[]) => void
  /** Aborts a running upload. */
  cancel: () => void
  /** Uploads the same file again after a failure. */
  retry: () => void
  /** Forgets the current file and returns to the idle state. */
  chooseAnother: () => void
}

/**
 * The upload flow of the empty dashboard: the type and size check, the
 * progress, the cancel, the retry and the one-file-at-a-time rule.
 */
export function useUpload(api: RaccoonApi, options: UseUploadOptions = {}): UploadApi {
  const { limitBytes = UPLOAD_LIMIT_BYTES, onUploaded } = options
  const [state, setState] = useState<UploadState>(INITIAL)
  const abort = useRef<AbortController | null>(null)
  const current = useRef<{ file: File; ignored: number } | null>(null)

  const run = useCallback(
    async (file: File, ignored: number) => {
      const controller = new AbortController()
      abort.current = controller
      current.current = { file, ignored }
      setState({
        status: 'uploading',
        file,
        uploaded: 0,
        total: file.size,
        reason: null,
        note: null,
        ignored,
      })
      try {
        const response = await api.uploadCapture(file, {
          onProgress: (progress) => {
            setState((previous) => ({
              ...previous,
              uploaded: progress.loaded,
              total: progress.total || previous.total,
            }))
            if (progress.total > 0 && progress.loaded >= progress.total) {
              setState((s) => ({ ...s, status: 'processing' }))
            }
          },
          signal: controller.signal,
        })
        onUploaded?.(response.caseId)
        // Reset to idle so returning to the dashboard shows a fresh dropzone.
        setState(INITIAL)
      } catch (error) {
        if (isCancelled(error)) {
          setState((previous) => ({
            ...previous,
            status: 'idle',
            uploaded: 0,
            note: 'Upload cancelled. Nothing was kept.',
          }))
          return
        }
        setState((previous) => ({
          ...previous,
          status: 'failed',
          reason: messageOf(error),
        }))
      } finally {
        abort.current = null
      }
    },
    [api, onUploaded],
  )

  const start = useCallback(
    (files: File[]) => {
      // Only the first valid file of a drop is used; the others are ignored.
      const file = firstCaptureFile(files)
      if (!file) {
        setState({
          status: 'invalid',
          file: null,
          uploaded: 0,
          total: 0,
          reason: null,
          note: null,
          ignored: 0,
        })
        return
      }
      const ignored = Math.max(0, files.length - 1)
      const check = checkCapture(file, limitBytes ?? UPLOAD_LIMIT_BYTES)
      if (!check.ok) {
        setState({
          status: check.problem === 'too-large' ? 'too-large' : 'invalid',
          file,
          uploaded: 0,
          total: file.size,
          reason: null,
          note: null,
          ignored,
        })
        return
      }
      void run(file, ignored)
    },
    [limitBytes, run],
  )

  const cancel = useCallback(() => {
    abort.current?.abort()
  }, [])

  const retry = useCallback(() => {
    const previous = current.current
    if (!previous) return
    void run(previous.file, previous.ignored)
  }, [run])

  const chooseAnother = useCallback(() => {
    abort.current?.abort()
    current.current = null
    setState(INITIAL)
  }, [])

  return { state, start, cancel, retry, chooseAnother }
}

/** True when the upload was aborted by the user. */
function isCancelled(error: unknown): boolean {
  return (error as { code?: string } | null)?.code === 'cancelled'
}

/** The message of a failed upload. */
function messageOf(error: unknown): string {
  const message = (error as { message?: string } | null)?.message
  return message && message.length > 0 ? message : 'The upload failed.'
}
