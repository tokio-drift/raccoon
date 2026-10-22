import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

/**
 * The contrast of the tokens (UI_Design.md §10.1, §16). The design names the
 * targets: 4.5:1 for normal text, 3:1 for the borders and the icons of the
 * interface. The values are read from the token layer, so a change of a
 * colour that breaks the contrast fails here.
 */

const tokensCss = readFileSync(join(process.cwd(), 'src/styles/tokens.css'), 'utf8')

function themeBlock(marker: string): Record<string, string> {
  const start = tokensCss.indexOf(marker)
  expect(start, `missing theme block ${marker}`).toBeGreaterThan(-1)
  const end = tokensCss.indexOf('\n}', start)
  const block = tokensCss.slice(start, end)
  const tokens: Record<string, string> = {}
  for (const match of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-fA-F]{6});/g)) {
    tokens[match[1]] = match[2]
  }
  return tokens
}

const themes: Array<[string, Record<string, string>]> = [
  ['light', themeBlock(':root {')],
  ['dark', themeBlock("[data-theme='dark'] {")],
]

function luminance(hex: string): number {
  const channels = [0, 2, 4].map((offset) => parseInt(hex.slice(offset + 1, offset + 3), 16) / 255)
  const [r, g, b] = channels.map((channel) =>
    channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4,
  )
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** The contrast ratio of two colours, from 1 to 21. */
function contrast(a: string, b: string): number {
  const first = luminance(a)
  const second = luminance(b)
  const lighter = Math.max(first, second)
  const darker = Math.min(first, second)
  return (lighter + 0.05) / (darker + 0.05)
}

const TEXT_PAIRS: Array<[string, string, number]> = [
  ['text-primary', 'bg-page', 4.5],
  ['text-primary', 'bg-surface', 4.5],
  ['text-primary', 'bg-sunken', 4.5],
  ['text-secondary', 'bg-page', 4.5],
  ['text-secondary', 'bg-surface', 4.5],
  ['text-secondary', 'bg-sunken', 4.5],
  ['text-muted', 'bg-page', 4.5],
  ['text-muted', 'bg-surface', 4.5],
  ['text-muted', 'bg-sunken', 4.5],
  ['accent-on', 'accent', 4.5],
  ['info', 'bg-page', 4.5],
  ['info', 'bg-surface', 4.5],
  ['warning', 'bg-page', 4.5],
  ['warning', 'bg-surface', 4.5],
  ['critical', 'bg-page', 4.5],
  ['critical', 'bg-surface', 4.5],
  ['evidence', 'bg-surface', 4.5],
  ['text-on-warning-tint', 'warning-tint', 4.5],
  ['text-on-critical-tint', 'critical-tint', 4.5],
  ['text-on-info-tint', 'info-tint', 4.5],
  ['text-on-accent-tint', 'accent-tint', 4.5],
  ['neutral-status', 'bg-surface', 4.5],
]

const UI_PAIRS: Array<[string, string, number]> = [
  ['border-strong', 'bg-page', 3],
  ['border-strong', 'bg-surface', 3],
  ['focus-ring', 'bg-page', 3],
  ['focus-ring', 'bg-surface', 3],
  ['accent', 'bg-surface', 3],
  ['warning', 'bg-surface', 3],
  ['critical', 'bg-surface', 3],
]

describe.each(themes)('the contrast of the %s theme', (_name, tokens) => {
  it.each(TEXT_PAIRS)('keeps %s on %s above %i:1', (foreground, background, target) => {
    expect(tokens[foreground], `missing token ${foreground}`).toBeDefined()
    expect(tokens[background], `missing token ${background}`).toBeDefined()
    const ratio = contrast(tokens[foreground], tokens[background])
    expect(ratio, `${foreground} on ${background} is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(
      target,
    )
  })

  it.each(UI_PAIRS)('keeps the interface of %s on %s above %i:1', (foreground, background, target) => {
    expect(tokens[foreground], `missing token ${foreground}`).toBeDefined()
    expect(tokens[background], `missing token ${background}`).toBeDefined()
    const ratio = contrast(tokens[foreground], tokens[background])
    expect(ratio, `${foreground} on ${background} is ${ratio.toFixed(2)}:1`).toBeGreaterThanOrEqual(
      target,
    )
  })
})
