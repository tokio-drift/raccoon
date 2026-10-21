import { useCallback, useEffect, useState } from 'react'

import { ApiError } from '../api/client'
import type { RaccoonApi } from '../api/api'
import type { CaseSummary } from '../api/types'

export interface UseCaseSummary {
  caseSummary: CaseSummary | null
  error: ApiError | null
  loading: boolean
  reload: () => void
}

/**
 * Loads the metadata of the open case. A missing case (404) and a broken
 * session (401) are reported separately so the shell can show the right
 * full-page state.
 */
export function useCaseSummary(caseId: string | null, client: RaccoonApi): UseCaseSummary {
  const [caseSummary, setCaseSummary] = useState<CaseSummary | null>(null)
  const [error, setError] = useState<ApiError | null>(null)
  const [loading, setLoading] = useState(false)
  const [nonce, setNonce] = useState(0)

  const reload = useCallback(() => setNonce((value) => value + 1), [])

  useEffect(() => {
    if (!caseId) {
      setCaseSummary(null)
      setError(null)
      return
    }
    let cancelled = false
    setLoading(true)
    client
      .getCase(caseId)
      .then((summary) => {
        if (cancelled) return
        setCaseSummary(summary)
        setError(null)
      })
      .catch((cause: unknown) => {
        if (cancelled) return
        setCaseSummary(null)
        setError(cause instanceof ApiError ? cause : new ApiError(0, 'internal', String(cause)))
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [caseId, client, nonce])

  return { caseSummary, error, loading, reload }
}
