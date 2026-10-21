import { describe, expect, it } from 'vitest'

import { STAGES, resolveStage, resolveStageIndex } from './stages'

const EMPTY = { streams: 0, files: 0, timelineReady: false }

describe('stage mapping', () => {
  it('lists the eight design stages in order', () => {
    expect(STAGES.map((stage) => stage.id)).toEqual([
      'capture',
      'decode',
      'reassemble',
      'analyse',
      'carve',
      'intelligence',
      'timeline',
      'done',
    ])
  })

  it('maps the coarse server stages onto the stepper', () => {
    expect(resolveStageIndex('init', EMPTY)).toBe(0)
    expect(resolveStageIndex('read', EMPTY)).toBe(1)
    expect(resolveStageIndex('done', EMPTY)).toBe(7)
  })

  it('moves inside the process phase with the live counters', () => {
    expect(resolveStageIndex('process', EMPTY)).toBe(2)
    expect(resolveStageIndex('process', { streams: 3, files: 0, timelineReady: false })).toBe(3)
    expect(resolveStageIndex('process', { streams: 3, files: 2, timelineReady: false })).toBe(4)
  })

  it('shows the timeline step once the timeline is ready', () => {
    expect(resolveStageIndex('process', { streams: 3, files: 2, timelineReady: true })).toBe(6)
  })

  it('names the stage', () => {
    expect(resolveStage('read', EMPTY).name).toBe('Decoding packets')
    expect(resolveStage('done', EMPTY).name).toBe('Done')
  })
})
