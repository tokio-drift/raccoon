import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

/**
 * The visual, responsive and accessibility rules of UI_Design.md §16 that
 * live in the stylesheets and in the sources rather than in the behaviour of
 * a component. The tests read the files as they are shipped: a rule that is
 * removed or weakened fails here.
 */

const projectRoot = process.cwd()

function read(relative: string): string {
  return readFileSync(join(projectRoot, relative), 'utf8')
}

/** Every source file of the app, without the tests. */
function sourceFiles(directory = join(projectRoot, 'src')): string[] {
  const found: string[] = []
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry)
    if (statSync(path).isDirectory()) {
      found.push(...sourceFiles(path))
      continue
    }
    if (!/\.(ts|tsx)$/.test(entry)) continue
    if (/\.test\.(ts|tsx)$/.test(entry)) continue
    found.push(path)
  }
  return found
}

const CSS_FILES = [
  'src/styles/base.css',
  'src/styles/components.css',
  'src/styles/shell.css',
  'src/styles/tokens.css',
  'src/styles/views.css',
]

const css = CSS_FILES.map(read)
const allCss = css.join('\n')
const sources = sourceFiles()
const allSource = sources.map((path) => readFileSync(path, 'utf8')).join('\n')

/** The comments are removed so that a rule can be checked in the code only. */
function withoutComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const code = withoutComments(allSource)

/** The rules of a stylesheet, with their selector. */
function rules(source: string): Array<{ selector: string; body: string }> {
  const found: Array<{ selector: string; body: string }> = []
  const pattern = /([^{}]+)\{([^{}]*)\}/g
  const clean = withoutComments(source)
  let match = pattern.exec(clean)
  while (match !== null) {
    found.push({ selector: match[1].trim(), body: match[2] })
    match = pattern.exec(clean)
  }
  return found
}

const allRules = CSS_FILES.flatMap((file) =>
  rules(read(file)).map((rule) => ({ ...rule, file })),
)

describe('the palette of the design (UI_Design.md §16, visual)', () => {
  it('uses no purple', () => {
    // The six chart colours of §10.10 are the only exception: the design
    // itself names a plum as the sixth series of the charts.
    const chart = new Set(
      [...allCss.matchAll(/--chart-[0-9]+:\s*(#[0-9a-fA-F]{6})/g)].map((match) => match[1]),
    )
    const purples: string[] = []
    for (const match of allCss.matchAll(/#[0-9a-fA-F]{6}\b/g)) {
      const hex = match[0]
      if (chart.has(hex)) continue
      const r = parseInt(hex.slice(1, 3), 16) / 255
      const g = parseInt(hex.slice(3, 5), 16) / 255
      const b = parseInt(hex.slice(5, 7), 16) / 255
      const max = Math.max(r, g, b)
      const min = Math.min(r, g, b)
      const delta = max - min
      if (delta < 0.15) continue
      let hue = 0
      if (max === r) hue = ((g - b) / delta) % 6
      else if (max === g) hue = (b - r) / delta + 2
      else hue = (r - g) / delta + 4
      hue = ((hue * 60) % 360 + 360) % 360
      if (hue >= 265 && hue <= 330) purples.push(`${hex} (hue ${Math.round(hue)})`)
    }
    expect(purples).toEqual([])
  })

  it('uses gradients only as the texture and the chart patterns of §10.9', () => {
    const allowed = [
      'texture',
      'hatch',
      'progress',
      'rail',
      'hex-row',
      'segment',
      'legend',
      'bar',
      'stripe',
      'dropzone',
      'chapter-header',
    ]
    const decorative = allRules
      .filter((rule) => rule.body.includes('gradient('))
      .filter((rule) => !allowed.some((word) => rule.selector.includes(word)))
      .map((rule) => `${rule.file}: ${rule.selector}`)
    expect(decorative).toEqual([])
  })

  it('uses no glow, no blur and no text shadow', () => {
    expect(allCss).not.toMatch(/blur\(|text-shadow|drop-shadow/)
  })

  it('keeps the two elevation levels of the design', () => {
    // An inset rule paints a rail inside the element; it is not an elevation.
    const shadows = allRules
      .filter((rule) => rule.body.includes('box-shadow'))
      .flatMap((rule) => rule.body.match(/box-shadow:[^;]+;/g) ?? [])
      .map((value) => value.replace(/box-shadow:\s*/, '').trim())
      .filter((value) => !value.startsWith('inset'))
    for (const shadow of shadows) {
      expect(shadow, `shadow outside the elevation tokens: ${shadow}`).toMatch(
        /var\(--elevation-[12]\)|var\(--focus-ring\)|0 0 0 1px var\(--bg-surface\)|0 0 0 0 var\(--critical-tint\)|0 0 0 6px transparent|none/,
      )
    }
  })

  it('fills only the critical chip', () => {
    const critical = allRules.find((rule) => rule.selector === '.badge--critical')
    const warning = allRules.find((rule) => rule.selector === '.badge--warning')
    const info = allRules.find((rule) => rule.selector === '.badge--info')
    expect(critical?.body).toContain('background: var(--critical)')
    expect(warning?.body).toContain('background: var(--warning-tint)')
    expect(warning?.body).not.toContain('background: var(--warning)')
    expect(info?.body ?? '').not.toMatch(/background:\s*var\(--info\)/)
  })

  it('gives the three severities three different silhouettes', () => {
    const icons = read('src/assets/icons.tsx')
    expect(icons).toMatch(/info: \([\s\S]*?<circle cx="12" cy="12" r="9"/)
    expect(icons).toMatch(/warning: \([\s\S]*?M12 3\.5 21\.5 19\.5H2\.5Z/)
    expect(icons).toMatch(/critical: \([\s\S]*?M8\.5 2\.5h7l6 6v7l-6 6h-7l-6-6v-7Z/)
  })

  it('uses the system font stacks only', () => {
    expect(allCss).not.toContain('@font-face')
    expect(read('src/styles/tokens.css')).toContain('--font-sans:')
    expect(read('src/styles/tokens.css')).toContain('--font-mono:')
  })

  it('uses the mono stack only for bytes, hashes, addresses, offsets and credentials', () => {
    const mono = allRules
      .filter((rule) => rule.body.includes('font-family: var(--font-mono)'))
      .map((rule) => rule.selector)
    expect(mono.length).toBeGreaterThan(0)
    for (const selector of mono) {
      expect(selector).toMatch(
        /copy-button|key-value-row__value--masked|event-card__elapsed|artifact-cell__hash|hex-row|tag--technique/,
      )
    }
  })

  it('never calls a file safe or clean', () => {
    expect(code).not.toMatch(/\b(safe|clean)\b/i)
  })

  it('sends no analytics anywhere', () => {
    expect(code).not.toMatch(/analytics|gtag|googletagmanager|plausible|sentry|mixpanel|hotjar|segment\.io/i)
  })
})

describe('the assets of the design (UI_Design.md §16, visual)', () => {
  it('loads no remote asset', () => {
    expect(allCss).not.toMatch(/url\(\s*['"]?https?:/i)
    expect(allCss).not.toMatch(/@import\s+url/i)
    // The only URL allowed here is the SVG namespace of the inline favicon.
    expect(read('index.html')).not.toMatch(/https?:\/\/(?!www\.w3\.org)/)
  })

  it('keeps the page free of inline script, as the Content-Security-Policy demands', () => {
    const html = read('index.html')
    expect(html).not.toMatch(/<script(?![^>]*\bsrc=)[^>]*>[\s\S]*?<\/script>/)
    expect(html).toContain('<script src="/theme.js"></script>')
  })

  it('applies the stored theme before the first paint', () => {
    const theme = read('public/theme.js')
    expect(theme).toContain("getItem('raccoon.theme')")
    expect(theme).toContain("setAttribute('data-theme', theme)")
  })

  it('shows the mask mark as the favicon', () => {
    const html = read('index.html')
    expect(html).toMatch(/<link\s+rel="icon"\s+href="data:image\/svg\+xml,[^"]*"/)
  })

  it('asks the local server only', () => {
    const client = read('src/api/client.ts')
    expect(client).not.toMatch(/https?:\/\/(?!www\.w3\.org)/)
    expect(code).not.toMatch(/https?:\/\/(?!www\.w3\.org)/)
  })

  it('uses the paw motif only in the empty and the failure states', () => {
    const users = sources
      .filter((path) => readFileSync(path, 'utf8').includes('PawMark'))
      .map((path) => path.replace(`${projectRoot}/`, ''))
      .filter((path) => path !== 'src/assets/brand.tsx')
    expect(users).toEqual(['src/components/content/Dropzone.tsx'])
  })

  it('puts the ringed-tail stripe on the chapter header and on the dropzone', () => {
    const views = read('src/styles/components.css')
    expect(views).toMatch(/\.chapter-header::before \{[^}]*repeating-linear-gradient/)
    expect(views).toMatch(/\.dropzone::before \{[^}]*repeating-linear-gradient/)
  })
})

describe('the focus and the motion rules (UI_Design.md §16, accessibility)', () => {
  it('always shows the focus ring', () => {
    const base = read('src/styles/base.css')
    expect(base).toMatch(/:focus-visible \{[^}]*outline: var\(--border-focus\) solid var\(--focus-ring\)/)
    expect(base).toMatch(/:focus-visible \{[^}]*outline-offset: var\(--focus-offset\)/)
  })

  it('removes the outline only when the focus is not visible', () => {
    const base = read('src/styles/base.css')
    const withoutOutline = withoutComments(base)
      .split('}')
      .filter((block) => /outline:\s*none/.test(block))
      .map((block) => block.split('{')[0].trim())
    expect(withoutOutline).toEqual([':focus:not(:focus-visible)'])
  })

  it('removes the pulses and the transitions when the reader asks for it', () => {
    const base = read('src/styles/base.css')
    const reduced = base.slice(base.indexOf('@media (prefers-reduced-motion: reduce)'))
    expect(reduced).toContain('animation-duration: 0.001ms !important')
    expect(reduced).toContain('transition-duration: 0.001ms !important')
    expect(read('src/styles/tokens.css')).toContain('@media (prefers-reduced-motion: reduce)')
  })
})

describe('the breakpoints of the design (UI_Design.md §16, responsive)', () => {
  it('has a rule for every breakpoint of §14.2', () => {
    for (const width of ['1023px', '1279px', '1280px', '1440px', '1920px']) {
      expect(allCss, `no rule for ${width}`).toContain(width)
    }
  })

  it('keeps the storyboard list and detail side by side at 1024', () => {
    const storyboard = allRules.find((rule) => rule.selector === '.storyboard__body')
    expect(storyboard?.body).toContain('minmax(420px, 42%)')
    expect(storyboard?.body).toContain('minmax(440px, 1fr)')
  })

  it('turns the files detail into a drawer under 1280', () => {
    const views = read('src/styles/views.css')
    const narrow = views.slice(views.indexOf('@media (max-width: 1279px)'))
    expect(narrow).toContain('.drawer--files')
    expect(narrow).toContain('width: 420px')
  })

  it('turns the stream list into a drawer under 1280', () => {
    const views = read('src/styles/views.css')
    const narrow = views.slice(views.indexOf('@media (max-width: 1279px)'))
    expect(narrow).toContain('.streams-view__body')
    expect(narrow).toContain('.streams-view__main')
  })

  it('shortens the privacy line under 1024', () => {
    const shell = read('src/styles/shell.css')
    const narrow = shell.slice(shell.indexOf('@media (max-width: 1023px)'))
    expect(narrow).toContain('.status-bar__privacy-long')
    expect(narrow).toContain('.status-bar__privacy-short')
  })

  it('drops the event and file counts of the header under 1024', () => {
    const shell = read('src/styles/shell.css')
    const narrow = shell.slice(shell.indexOf('@media (max-width: 1023px)'))
    expect(narrow).toContain('.case-strip__stat--events')
    expect(narrow).toContain('.case-strip__stat--files')
  })

  it('caps and centres the content above 1920', () => {
    const shell = read('src/styles/shell.css')
    const wide = shell.slice(shell.indexOf('@media (min-width: 1920px)'))
    expect(wide).toContain('max-width: 1680px')
    expect(wide).toContain('margin-inline: auto')
  })

  it('moves the wide filters of the storyboard into the small screens', () => {
    const views = read('src/styles/views.css')
    expect(views).toMatch(/@media \(max-width: 1280px\) \{\s*\.storyboard-filters__wide \{\s*display: none;/)
  })
})

describe('the print stylesheet of the design (UI_Design.md C13)', () => {
  it('prints the view without the chrome and in the light theme', () => {
    expect(allCss).toContain('@media print')
    const source = allCss.slice(allCss.indexOf('@media print'))
    expect(source).toContain('--bg-page')
    expect(source).toContain('display: none')
    expect(source).toContain('.app-header')
    expect(source).toContain('.status-bar')
  })
})
