import type { JSX, RefObject } from 'react'

export interface ViewPlaceholderProps {
  title: string
  description: string
  /**
   * The heading of the view. The shell moves the focus here when the analysis
   * finishes and the Processing view becomes the Storyboard (UI_Design.md §8.9).
   */
  headingRef?: RefObject<HTMLHeadingElement>
}

/**
 * Placeholder for a case view that is implemented in a later task of Phase 11
 * (Storyboard in 11.6, Files in 11.7, Streams in 11.8). It keeps the shell
 * structure — one H1 per view — so the layout and the accessibility tree are
 * already correct.
 */
export function ViewPlaceholder({
  title,
  description,
  headingRef,
}: ViewPlaceholderProps): JSX.Element {
  return (
    <section className="content-scroll" id="case-panel" role="tabpanel" aria-labelledby="tab-storyboard">
      <div className="empty-state">
        <h1 className="empty-state__title" ref={headingRef} tabIndex={-1}>
          {title}
        </h1>
        <p className="empty-state__body">{description}</p>
      </div>
    </section>
  )
}
