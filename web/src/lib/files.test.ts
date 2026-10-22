import { describe, expect, it } from 'vitest'

import type { CarvedFile, StreamSummary, VerdictStatus } from '../api/types'
import {
  controlCharacterTokens,
  displayName,
  directionLabel,
  EXTRACTION_LABEL,
  fileEndpoints,
  fileSearchText,
  fileVerdict,
  filtersActive,
  filtersFromParams,
  filtersToParams,
  formatIconName,
  formatLabel,
  hasNonAscii,
  isPathLikeName,
  magicBytesText,
  nameExtension,
  nameMismatch,
  neutralDownloadName,
  sortFiles,
  tableName,
  unnamedFileLabel,
  verdictRank,
  VERDICT_ORDER,
} from './files'

function file(id: number, overrides: Partial<CarvedFile> = {}): CarvedFile {
  return {
    id,
    streamId: 2,
    dir: 'c2s',
    startOff: 0,
    endOff: 1024,
    format: 'PNG',
    ext: 'png',
    status: 'complete',
    confidence: 'high',
    size: 1024,
    md5: 'd41d8cd98f00b204e9800998ecf8427e',
    sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    displayName: `file-${id}.png`,
    path: `carved/file-${id}.png`,
    magicHex: '89504e47',
    ...overrides,
  }
}

const STREAM: StreamSummary = {
  id: 2,
  parentId: 0,
  proto: 'ftp',
  srcIp: '192.0.2.14',
  srcPort: 51822,
  dstIp: '192.0.2.50',
  dstPort: 21,
  startTs: '2026-01-01T12:00:00.000000000Z',
  endTs: '2026-01-01T12:00:05.000000000Z',
  bytesC2S: 4096,
  bytesS2C: 0,
  packets: 4,
  firstPacket: 1,
  lastPacket: 4,
  midstream: false,
  hasGaps: false,
  udp: false,
}

describe('the format of a file', () => {
  it('names the format and its extension', () => {
    expect(formatLabel('PNG', 'png')).toBe('PNG image · .png')
    expect(formatLabel('ZIP', 'zip')).toBe('ZIP archive · .zip')
    expect(formatLabel('ELF', '')).toBe('ELF executable')
  })

  it('keeps an unknown format as it is', () => {
    expect(formatLabel('SOMETHING_NEW', 'dat')).toBe('SOMETHING NEW · .dat')
  })

  it('picks a generic icon and never a preview', () => {
    expect(formatIconName('PNG')).toBe('image')
    expect(formatIconName('ZIP')).toBe('archive')
    expect(formatIconName('ELF')).toBe('executable')
    expect(formatIconName('UNKNOWN')).toBe('file')
  })
})

describe('the name of a file', () => {
  it('shows a path-like name literally', () => {
    expect(isPathLikeName('../../etc/passwd')).toBe(true)
    expect(isPathLikeName('dir\\file.txt')).toBe(true)
    expect(isPathLikeName('report.pdf')).toBe(false)
  })

  it('shows the control characters as visible tokens', () => {
    expect(controlCharacterTokens('a‮b')).toEqual(['‹U+202E›'])
    expect(controlCharacterTokens('ab')).toEqual(['‹0x1B›'])
    expect(controlCharacterTokens('plain.png')).toEqual([])
  })

  it('spots a name with characters outside ASCII', () => {
    expect(hasNonAscii('café.png')).toBe(true)
    expect(hasNonAscii('secret.png')).toBe(false)
  })

  it('reads the extension of a name', () => {
    expect(nameExtension('secret.PNG')).toBe('png')
    expect(nameExtension('archive.tar.gz')).toBe('gz')
    expect(nameExtension('noextension')).toBe('')
    expect(nameExtension('.hidden')).toBe('')
  })

  it('spots a name whose extension is not the content', () => {
    expect(nameMismatch('photo.jpg', 'zip')).toBe(true)
    expect(nameMismatch('photo.png', 'png')).toBe(false)
    expect(nameMismatch('photo', 'zip')).toBe(false)
  })

  it('names a file without a display name', () => {
    const unnamed = file(4, { displayName: '', format: 'PNG' })
    expect(unnamedFileLabel(unnamed)).toBe('Unnamed file · PNG · file 4')
    expect(displayName(unnamed)).toBe('Unnamed file · PNG · file 4')
  })

  it('keeps the last eight characters of the name in the table', () => {
    expect(tableName(file(1, { displayName: 'a-very-long-secret-name.png' }))).toBe('…name.png')
  })
})

describe('the extraction status', () => {
  it('names the three states', () => {
    expect(EXTRACTION_LABEL.complete).toBe('Complete')
    expect(EXTRACTION_LABEL.truncated).toBe('Incomplete')
    expect(EXTRACTION_LABEL.corrupt).toBe('Corrupt')
  })
})

describe('the verdict of a file', () => {
  it('orders the verdicts, most serious first', () => {
    expect(VERDICT_ORDER).toEqual([
      'malicious',
      'suspicious',
      'unknown',
      'not_checked',
      'no_detections',
    ])
    expect(verdictRank('malicious')).toBeLessThan(verdictRank('suspicious'))
    expect(verdictRank('no_detections')).toBeGreaterThan(verdictRank('not_checked'))
  })

  it('treats a file without a verdict as not checked', () => {
    expect(fileVerdict(file(1))).toBe('not_checked')
    expect(
      fileVerdict(
        file(1, {
          verdict: {
            source: 'virustotal',
            status: 'malicious',
            score: 3,
            total: 70,
            checkedAt: '2026-01-01T12:00:00.000000000Z',
          },
        }),
      ),
    ).toBe('malicious')
  })
})

describe('the saved name of a download', () => {
  it('is the first twelve hex characters of the hash', () => {
    expect(
      neutralDownloadName('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    ).toBe('e3b0c44298fc.bin')
  })

  it('never carries an executable-looking extension', () => {
    const name = neutralDownloadName('ABCDEF0123456789')
    expect(name.endsWith('.bin')).toBe(true)
    expect(name).not.toMatch(/\.(exe|bat|sh|js)$/i)
  })

  it('falls back to a neutral name without a hash', () => {
    expect(neutralDownloadName('')).toBe('download.bin')
  })
})

describe('the magic bytes of a file', () => {
  it('are spaced hex pairs', () => {
    expect(magicBytesText('89504e47')).toBe('89 50 4E 47')
    expect(magicBytesText('')).toBe('')
  })
})

describe('the endpoints of a file', () => {
  it('follow the direction the data travelled', () => {
    expect(fileEndpoints(file(1, { dir: 'c2s' }), STREAM)).toBe('192.0.2.14:51822 → 192.0.2.50:21')
    expect(fileEndpoints(file(1, { dir: 's2c' }), STREAM)).toBe('192.0.2.50:21 → 192.0.2.14:51822')
  })

  it('are unknown without a stream', () => {
    expect(fileEndpoints(file(1), null)).toBeNull()
  })

  it('name the direction of the chip', () => {
    expect(directionLabel('c2s')).toBe('Sent to server')
    expect(directionLabel('s2c')).toBe('Sent to client')
  })
})

describe('the search of the gallery', () => {
  it('looks at the name, the format, the hashes and the endpoints', () => {
    const text = fileSearchText(file(1, { displayName: 'secret.png' }), STREAM)
    expect(text).toContain('secret.png')
    expect(text).toContain('e3b0c442')
    expect(text).toContain('192.0.2.14:51822')
  })
})

describe('the order of the rows', () => {
  const files: CarvedFile[] = [
    file(1, { displayName: 'b.png', size: 10, verdict: { source: 'yara', status: 'no_detections', score: 0, total: 70, checkedAt: '' } }),
    file(2, { displayName: 'a.zip', size: 30, verdict: { source: 'yara', status: 'malicious', score: 2, total: 70, checkedAt: '' } }),
    file(3, { displayName: 'c.png', size: 20, verdict: { source: 'yara', status: 'suspicious', score: 1, total: 70, checkedAt: '' } }),
  ]

  it('puts the most serious verdict first by default', () => {
    expect(sortFiles(files, 'verdict').map((item) => item.id)).toEqual([2, 3, 1])
  })

  it('sorts by name, size and the order of the capture', () => {
    expect(sortFiles(files, 'name').map((item) => item.id)).toEqual([2, 1, 3])
    expect(sortFiles(files, 'size').map((item) => item.id)).toEqual([1, 3, 2])
    expect(sortFiles(files, 'order').map((item) => item.id)).toEqual([1, 2, 3])
  })

  it('can be reversed', () => {
    expect(sortFiles(files, 'size', true).map((item) => item.id)).toEqual([2, 3, 1])
  })
})

describe('the deep link of the gallery', () => {
  it('reads the parameters of §3.2', () => {
    const filters = filtersFromParams({
      verdict: 'malicious,suspicious',
      format: 'PNG,ZIP',
      dir: 'c2s',
      q: 'secret',
      low: '1',
    })
    expect(filters.verdicts).toEqual(['malicious', 'suspicious'])
    expect(filters.formats).toEqual(['PNG', 'ZIP'])
    expect(filters.dir).toBe('c2s')
    expect(filters.query).toBe('secret')
    expect(filters.showLowConfidence).toBe(true)
  })

  it('drops an unknown verdict', () => {
    expect(filtersFromParams({ verdict: 'malicious,invented' }).verdicts).toEqual(['malicious'])
  })

  it('writes the parameters of §3.2', () => {
    const params = filtersToParams({
      verdicts: ['malicious'],
      formats: ['PNG'],
      dir: 's2c',
      extractions: ['corrupt'],
      query: 'secret',
      showLowConfidence: true,
    })
    expect(params).toEqual({
      verdict: 'malicious',
      format: 'PNG',
      dir: 's2c',
      q: 'secret',
      low: '1',
    })
  })

  it('knows when a filter is active', () => {
    const filters = filtersFromParams({})
    expect(filtersActive(filters)).toBe(false)
    expect(filtersActive({ ...filters, query: 'x' })).toBe(true)
    expect(filtersActive({ ...filters, showLowConfidence: true })).toBe(true)
  })
})

describe('the verdict vocabulary', () => {
  it('is the same everywhere', () => {
    const status: VerdictStatus = 'not_checked'
    expect(VERDICT_ORDER).toContain(status)
  })
})
