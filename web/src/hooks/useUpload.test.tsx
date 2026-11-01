import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import { ApiError } from '../api/client'
import type { RaccoonApi } from '../api/api'
import type { UploadProgress } from '../api/types'
import { useUpload } from './useUpload'

function capture(name: string, size = 1024): File {
  return new File([new Uint8Array(size)], name, { type: 'application/octet-stream' })
}

interface FakeUpload {
  api: RaccoonApi
  progress: (value: UploadProgress) => void
  resolve: (caseId: string) => void
  reject: (error: unknown) => void
  aborted: () => boolean
}

function fakeApi(): FakeUpload {
  let onProgress: ((value: UploadProgress) => void) | undefined
  let resolveUpload: ((response: { caseId: string }) => void) | undefined
  let rejectUpload: ((error: unknown) => void) | undefined
  let signal: AbortSignal | undefined
  const api = {
    uploadCapture: (
      _file: File,
      options?: { onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal },
    ) => {
      onProgress = options?.onProgress
      signal = options?.signal
      return new Promise<{ caseId: string }>((resolve, reject) => {
        resolveUpload = resolve
        rejectUpload = reject
      })
    },
  } as unknown as RaccoonApi
  return {
    api,
    progress: (value) => onProgress?.(value),
    resolve: (caseId) => resolveUpload?.({ caseId }),
    reject: (error) => rejectUpload?.(error),
    aborted: () => signal?.aborted ?? false,
  }
}

describe('useUpload', () => {
  it('refuses a file that is not a capture', () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('notes.txt')])
    })

    expect(result.current.state.status).toBe('invalid')
    expect(result.current.state.file).toBeNull()
  })

  it('refuses a file that is larger than the limit', () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api, { limitBytes: 100 }))

    act(() => {
      result.current.start([capture('big.pcap', 200)])
    })

    expect(result.current.state.status).toBe('too-large')
    expect(result.current.state.total).toBe(200)
  })

  it('uses the first valid file of a drop and ignores the others', () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('notes.txt'), capture('first.pcap'), capture('second.pcap')])
    })

    expect(result.current.state.status).toBe('uploading')
    expect(result.current.state.file?.name).toBe('first.pcap')
    expect(result.current.state.ignored).toBe(2)
  })

  it('reports the progress of the upload', () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap', 1000)])
    })
    act(() => {
      fake.progress({ loaded: 250, total: 1000 })
    })

    expect(result.current.state.uploaded).toBe(250)
    expect(result.current.state.total).toBe(1000)
  })

  it('transitions to processing status when transfer completes', () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap', 1000)])
    })
    act(() => {
      fake.progress({ loaded: 1000, total: 1000 })
    })

    expect(result.current.state.status).toBe('processing')
    expect(result.current.state.uploaded).toBe(1000)
  })

  it('calls back with the new case when the upload finishes', async () => {
    const fake = fakeApi()
    const onUploaded = vi.fn()
    const { result } = renderHook(() => useUpload(fake.api, { onUploaded }))

    act(() => {
      result.current.start([capture('capture.pcap')])
    })
    act(() => {
      fake.resolve('case-42')
    })

    await waitFor(() => expect(onUploaded).toHaveBeenCalledWith('case-42'))
  })

  it('aborts the upload when the user cancels it', async () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap')])
    })
    act(() => {
      result.current.cancel()
    })
    expect(fake.aborted()).toBe(true)

    act(() => {
      fake.reject(new ApiError(0, 'cancelled', 'The upload was cancelled.'))
    })

    await waitFor(() => expect(result.current.state.status).toBe('idle'))
    expect(result.current.state.note).toBe('Upload cancelled. Nothing was kept.')
  })

  it('keeps the file after a failure so it can be tried again', async () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap')])
    })
    act(() => {
      fake.reject(new ApiError(500, 'internal', 'RACCOON stopped unexpectedly.'))
    })

    await waitFor(() => expect(result.current.state.status).toBe('failed'))
    expect(result.current.state.reason).toBe('RACCOON stopped unexpectedly.')
    expect(result.current.state.file?.name).toBe('capture.pcap')
  })

  it('uploads the same file again on a retry', async () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap')])
    })
    act(() => {
      fake.reject(new ApiError(500, 'internal', 'RACCOON stopped unexpectedly.'))
    })
    await waitFor(() => expect(result.current.state.status).toBe('failed'))

    act(() => {
      result.current.retry()
    })
    expect(result.current.state.status).toBe('uploading')
    expect(result.current.state.file?.name).toBe('capture.pcap')
  })

  it('forgets the file when another one is chosen', async () => {
    const fake = fakeApi()
    const { result } = renderHook(() => useUpload(fake.api))

    act(() => {
      result.current.start([capture('capture.pcap')])
    })
    act(() => {
      result.current.chooseAnother()
    })

    expect(result.current.state.status).toBe('idle')
    expect(result.current.state.file).toBeNull()
  })
})
