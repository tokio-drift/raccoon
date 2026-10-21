import { useEffect, useState } from 'react'

/**
 * A clock that ticks every `intervalMs` milliseconds. The views use it for
 * the elapsed time and for the age of the last update.
 */
export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(() => Date.now())
  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), intervalMs)
    return () => window.clearInterval(timer)
  }, [intervalMs])
  return now
}
