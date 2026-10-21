import { useEffect, useRef, useState } from 'react'

/**
 * The time each finished stage took (UI_Design.md §8.3). The server reports
 * the stage, not its duration, so the client measures the time between two
 * stage changes.
 */
export function useStageDurations(index: number): number[] {
  const [durations, setDurations] = useState<number[]>([])
  const previous = useRef<{ index: number; since: number }>({ index: -1, since: Date.now() })

  useEffect(() => {
    const now = Date.now()
    const closed = previous.current.index
    if (closed === index) return
    const took = now - previous.current.since
    previous.current = { index, since: now }
    if (closed < 0) return
    setDurations((all) => {
      const next = all.slice()
      next[closed] = (next[closed] ?? 0) + took
      return next
    })
  }, [index])

  return durations
}
