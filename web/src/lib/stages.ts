/**
 * The eight analysis stages of the design (UI_Design.md §12.10) and the
 * mapping from the coarse stages the server reports.
 *
 * The server reports `init`, `read`, `process` and `done`; the design shows a
 * stepper of eight steps. The mapping keeps the steps the server has certainly
 * passed marked as done, and uses the live counters to move inside the
 * `process` phase.
 */

export type DesignStage =
  | 'capture'
  | 'decode'
  | 'reassemble'
  | 'analyse'
  | 'carve'
  | 'intelligence'
  | 'timeline'
  | 'done'

export interface StageInfo {
  id: DesignStage
  name: string
  reassurance: string
}

export const STAGES: StageInfo[] = [
  {
    id: 'capture',
    name: 'Reading the capture',
    reassurance: 'Opening the file and checking its format.',
  },
  {
    id: 'decode',
    name: 'Decoding packets',
    reassurance: 'Reading each packet, one at a time.',
  },
  {
    id: 'reassemble',
    name: 'Rebuilding conversations',
    reassurance: 'Putting packets back in order to rebuild each stream.',
  },
  {
    id: 'analyse',
    name: 'Analysing protocols',
    reassurance: 'Looking for logins, commands, web requests and DNS lookups.',
  },
  {
    id: 'carve',
    name: 'Extracting files',
    reassurance: "Finding files that crossed the wire. Nothing is opened or run.",
  },
  {
    id: 'intelligence',
    name: 'Checking file hashes',
    reassurance: "Only each file's hash is sent for checking. The files stay on this computer.",
  },
  {
    id: 'timeline',
    name: 'Building the storyboard',
    reassurance: 'Putting events in order and linking each one to its evidence.',
  },
  {
    id: 'done',
    name: 'Done',
    reassurance: 'Your case is ready.',
  },
]

export interface StageCounters {
  streams: number
  files: number
  timelineReady: boolean
}

/** The index of the design step the given server stage corresponds to. */
export function resolveStageIndex(serverStage: string, counters: StageCounters): number {
  if (counters.timelineReady) return STAGES.findIndex((stage) => stage.id === 'timeline')
  switch (serverStage) {
    case 'init':
      return 0
    case 'read':
      return 1
    case 'process':
      if (counters.streams === 0) return 2
      if (counters.files === 0) return 3
      return 4
    case 'done':
      return STAGES.length - 1
    default:
      return 0
  }
}

/** The stage the given server stage maps to. */
export function resolveStage(serverStage: string, counters: StageCounters): StageInfo {
  const index = resolveStageIndex(serverStage, counters)
  return STAGES[Math.min(Math.max(index, 0), STAGES.length - 1)]
}
