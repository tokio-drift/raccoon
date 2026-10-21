import type { JSX } from 'react'

import { Icon } from '../../assets/icons'
import { STAGES, type DesignStage } from '../../lib/stages'

export interface StageStepperProps {
  /** The stage that is currently running. */
  current: DesignStage
  /** The stages that are already finished, with the time they took. */
  durations?: Partial<Record<DesignStage, string>>
  /** The stages that are still to come. */
}

/**
 * The stage stepper of the processing view (UI_Design.md §8.3, §11). A stage
 * that is done has a filled mark, the running stage a spinner arc and the
 * upcoming stages a hollow circle; the order never changes.
 */
export function StageStepper({ current, durations = {} }: StageStepperProps): JSX.Element {
  const currentIndex = STAGES.findIndex((stage) => stage.id === current)

  return (
    <ol className="stage-stepper">
      {STAGES.map((stage, index) => {
        const done = index < currentIndex
        const running = index === currentIndex
        const classes = ['stage-stepper__item']
        if (done) classes.push('stage-stepper__item--done')
        if (running) classes.push('stage-stepper__item--current')

        return (
          <li key={stage.id} className={classes.join(' ')} aria-current={running ? 'step' : undefined}>
            <span className="stage-stepper__icon" aria-hidden="true">
              {done ? (
                <Icon name="check" size={16} />
              ) : running ? (
                <span className="spinner" />
              ) : (
                <span className="stage-stepper__hollow" />
              )}
            </span>
            <span className="stage-stepper__name">{stage.name}</span>
            {done && durations[stage.id] ? (
              <span className="stage-stepper__time">{durations[stage.id]}</span>
            ) : null}
            <span className="live-region">
              {done ? 'done' : running ? 'running' : 'not started'}
            </span>
          </li>
        )
      })}
    </ol>
  )
}
