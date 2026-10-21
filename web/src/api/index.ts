import type { RaccoonApi } from './api'
import { ApiClient } from './client'

export type { RaccoonApi } from './api'
export { ApiClient, ApiError } from './client'

/**
 * Builds the API client of the app. With `VITE_MOCK=1` the mock adapter
 * serves the fixtures of `web/mock`; without it the real local server is
 * used. The mock is imported lazily, so the fixtures never end up in the
 * production bundle.
 */
export async function createApi(): Promise<RaccoonApi> {
  if (import.meta.env.VITE_MOCK === '1') {
    const { MockApi, createHttpMockLoader } = await import('./mock')
    return new MockApi(createHttpMockLoader())
  }
  return new ApiClient()
}
