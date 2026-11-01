import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

const projectRoot = process.cwd()
const tokensCss = readFileSync(join(projectRoot, 'src/styles/tokens.css'), 'utf8')
const indexHtml = readFileSync(join(projectRoot, 'index.html'), 'utf8')

/**
 * The token layer is the contract of UI_Design.md §10: exact colours for both
 * themes, the type scale, spacing, radii, elevation, z-index, motion and the
 * focus ring. These tests fail if a token drifts away from the design.
 */

const LIGHT_THEME = `:root {`
const DARK_THEME = `[data-theme='dark'] {`

function themeBlock(source: string, marker: string): string {
  const start = source.indexOf(marker)
  expect(start, `missing theme block ${marker}`).toBeGreaterThan(-1)
  const end = source.indexOf('\n}', start)
  return source.slice(start, end)
}

const light = themeBlock(tokensCss, LIGHT_THEME)
const dark = themeBlock(tokensCss, DARK_THEME)

const COLOUR_TOKENS: Array<[string, string, string]> = [
  ['--bg-page', '#f4f5f7', '#0b0f19'],
  ['--bg-surface', '#ffffff', '#111827'],
  ['--bg-sunken', '#e9ecf0', '#070a10'],
  ['--border-subtle', '#e2e8f0', '#1f2937'],
  ['--border-strong', '#64748b', '#64748b'],
  ['--text-primary', '#1e293b', '#f9fafb'],
  ['--text-secondary', '#475569', '#cbd5e1'],
  ['--text-muted', '#475569', '#94a3b8'],
  ['--accent', '#1e293b', '#38bdf8'],
  ['--accent-hover', '#0f172a', '#7dd3fc'],
  ['--accent-on', '#ffffff', '#0b0f19'],
  ['--accent-tint', '#e2e8f0', '#0c4a6e'],
  ['--focus-ring', '#0369a1', '#38bdf8'],
  ['--evidence', '#0369a1', '#38bdf8'],
  ['--info', '#1d4ed8', '#60a5fa'],
  ['--info-tint', '#dbeafe', '#1e3a8a'],
  ['--warning', '#b45309', '#fbbf24'],
  ['--warning-tint', '#fef3c7', '#451a03'],
  ['--critical', '#b91c1c', '#f87171'],
  ['--critical-tint', '#fee2e2', '#450a0a'],
  ['--neutral-status', '#15803d', '#4ade80'],
  ['--dir-c2s', '#fef3c7', '#292524'],
  ['--dir-s2c', '#e0f2fe', '#1e293b'],
]

describe('colour tokens', () => {
  it.each(COLOUR_TOKENS)('defines %s in both themes', (name, lightValue, darkValue) => {
    expect(light).toContain(`${name}: ${lightValue};`)
    expect(dark).toContain(`${name}: ${darkValue};`)
  })
})

describe('typography tokens', () => {
  it('uses the system sans stack only', () => {
    expect(tokensCss).toContain('--font-sans: "Avenir Next"')
    expect(tokensCss).not.toMatch(/@import\s+url/)
    expect(tokensCss).not.toContain('https://fonts')
  })

  it('defines the type scale from the design', () => {
    for (const token of [
      '--text-display',
      '--text-h1',
      '--text-h2',
      '--text-h3',
      '--text-body',
      '--text-body-strong',
      '--text-small',
      '--text-caption',
      '--text-label',
      '--text-mono',
      '--text-mono-small',
      '--text-wordmark',
    ]) {
      expect(tokensCss).toContain(`${token}:`)
    }
  })
})

describe('shape, spacing, motion and layout tokens', () => {
  it('defines the 4 px spacing scale', () => {
    for (const token of [
      '--space-4',
      '--space-8',
      '--space-12',
      '--space-16',
      '--space-24',
      '--space-32',
      '--space-48',
      '--space-64',
    ]) {
      expect(tokensCss).toContain(`${token}:`)
    }
  })

  it('defines radii, borders, elevation and z-index roles', () => {
    expect(tokensCss).toContain('--radius-badge: 4px;')
    expect(tokensCss).toContain('--radius-control: 6px;')
    expect(tokensCss).toContain('--radius-dialog: 8px;')
    expect(tokensCss).toContain('--border-hairline: 1px;')
    expect(tokensCss).toContain('--border-focus: 2px;')
    expect(tokensCss).toContain('--elevation-1:')
    expect(tokensCss).toContain('--elevation-2:')
    expect(tokensCss).toContain('--scrim:')
    expect(tokensCss).toContain('--z-header: 20;')
    expect(tokensCss).toContain('--z-banner: 25;')
    expect(tokensCss).toContain('--z-drawer: 30;')
    expect(tokensCss).toContain('--z-menu: 40;')
    expect(tokensCss).toContain('--z-toast: 50;')
    expect(tokensCss).toContain('--z-dialog: 60;')
  })

  it('defines the motion durations', () => {
    expect(tokensCss).toContain('--motion-panel: 180ms')
    expect(tokensCss).toContain('--motion-fade: 120ms')
    expect(tokensCss).toContain('--motion-card: 160ms')
    expect(tokensCss).toContain('--motion-pulse: 600ms')
    expect(tokensCss).toContain('--motion-progress: 250ms')
    expect(tokensCss).toContain('--motion-insert: 200ms')
    expect(tokensCss).toContain('--motion-toast: 160ms')
    expect(tokensCss).toContain('--motion-skeleton: 1.4s')
  })

  it('defines the shell metrics from the design', () => {
    expect(tokensCss).toContain('--header-height: 56px;')
    expect(tokensCss).toContain('--progress-hairline-height: 3px;')
    expect(tokensCss).toContain('--case-strip-height: 44px;')
    expect(tokensCss).toContain('--banner-height: 40px;')
    expect(tokensCss).toContain('--incident-strip-height: 44px;')
    expect(tokensCss).toContain('--status-bar-height: 28px;')
    expect(tokensCss).toContain('--control-height: 36px;')
    expect(tokensCss).toContain('--target-size: 32px;')
  })

  it('removes motion when the reader asks for reduced motion', () => {
    expect(tokensCss).toContain('@media (prefers-reduced-motion: reduce)')
  })
})

describe('the page applies the theme before the first paint', () => {
  it('loads the theme script before the application bundle', () => {
    const themeScript = indexHtml.indexOf('/theme.js')
    const bundle = indexHtml.indexOf('/src/main.tsx')
    expect(themeScript).toBeGreaterThan(-1)
    expect(bundle).toBeGreaterThan(-1)
    expect(themeScript).toBeLessThan(bundle)
  })

  it('reads the stored theme in the script that runs first', () => {
    const theme = readFileSync(join(projectRoot, 'public/theme.js'), 'utf8')
    expect(theme).toContain("getItem('raccoon.theme')")
    expect(theme).toContain("setAttribute('data-theme', theme)")
  })

  it('does not reference any remote asset', () => {
    // The only URL allowed here is the SVG namespace of the inline favicon.
    expect(indexHtml).not.toMatch(/https?:\/\/(?!www\.w3\.org)/)
  })
})
