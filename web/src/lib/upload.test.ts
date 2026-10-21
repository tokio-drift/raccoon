import { describe, expect, it } from 'vitest'

import { buildDiagnostics, browserName } from './diagnostics'
import { captureLimitLabel, checkCapture, firstCaptureFile, isCaptureName } from './upload'

function file(name: string, size = 1024): File {
  return new File([new Uint8Array(size)], name)
}

describe('the capture rules', () => {
  it('accepts the extensions of the server', () => {
    expect(isCaptureName('capture.pcap')).toBe(true)
    expect(isCaptureName('capture.PCAPNG')).toBe(true)
    expect(isCaptureName('notes.txt')).toBe(false)
    expect(isCaptureName('capture.pcap.zip')).toBe(false)
  })

  it('reports the wrong type before the wrong size', () => {
    expect(checkCapture(file('notes.txt', 10_000), 100)).toEqual({
      ok: false,
      problem: 'invalid',
    })
    expect(checkCapture(file('capture.pcap', 200), 100)).toEqual({
      ok: false,
      problem: 'too-large',
    })
    expect(checkCapture(file('capture.pcap', 100), 100)).toEqual({ ok: true })
  })

  it('uses the first valid file of a drop', () => {
    expect(firstCaptureFile([file('a.txt'), file('b.pcap'), file('c.pcapng')])?.name).toBe('b.pcap')
    expect(firstCaptureFile([file('a.txt')])).toBeNull()
  })

  it('names the limit only when the server reports one', () => {
    expect(captureLimitLabel()).toBe('Accepts .pcap and .pcapng files.')
    expect(captureLimitLabel(500 * 1024 * 1024)).toBe(
      'Accepts .pcap and .pcapng files up to 500.0 MB.',
    )
  })
})

describe('the diagnostic text', () => {
  it('holds the case, the capture and the error', () => {
    const text = buildDiagnostics({
      caseId: 'case-1',
      fileName: 'capture.pcap',
      size: 1024,
      sha256: 'a'.repeat(64),
      toolVersion: 'devel',
      stage: 'process',
      progress: 62,
      errorCode: 'internal',
      errorMessage: 'boom',
      at: Date.parse('2026-01-01T12:00:00Z'),
    })
    expect(text).toContain('Case: case-1')
    expect(text).toContain('Capture: capture.pcap')
    expect(text).toContain('Size: 1024')
    expect(text).toContain(`SHA-256: ${'a'.repeat(64)}`)
    expect(text).toContain('Stage: process')
    expect(text).toContain('Progress: 62')
    expect(text).toContain('Error code: internal')
    expect(text).toContain('Error: boom')
    expect(text).toContain('Browser: ')
  })

  it('never holds the session token', () => {
    const text = buildDiagnostics({ caseId: 'case-1', fileName: 'capture.pcap' })
    expect(text).not.toContain('token')
    expect(text).not.toContain('X-Raccoon-Token')
  })

  it('names the browser without the whole user agent', () => {
    expect(typeof browserName()).toBe('string')
    expect(browserName().length).toBeLessThan(20)
  })
})
