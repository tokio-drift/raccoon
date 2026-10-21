import { describe, expect, it } from 'vitest'

import { buildTitle } from './title'

describe('page titles', () => {
  it('uses the tagline on the empty dashboard', () => {
    expect(buildTitle({})).toBe('RACCOON — Follow the trail')
  })

  it('uses the view name when a case is ready', () => {
    expect(buildTitle({ fileName: 'ftp_upload_png.pcap', status: 'ready', view: 'storyboard' })).toBe(
      'RACCOON — ftp_upload_png.pcap — Storyboard',
    )
    expect(buildTitle({ fileName: 'ftp_upload_png.pcap', status: 'ready', view: 'files' })).toBe(
      'RACCOON — ftp_upload_png.pcap — Files',
    )
  })

  it('shows the percent while the analysis runs', () => {
    expect(buildTitle({ fileName: 'ftp_upload_png.pcap', status: 'running', percent: 62 })).toBe(
      '(62%) RACCOON — ftp_upload_png.pcap — Analysing',
    )
  })

  it('names a failed analysis', () => {
    expect(buildTitle({ fileName: 'ftp_upload_png.pcap', status: 'failed' })).toBe(
      'RACCOON — ftp_upload_png.pcap — Analysis failed',
    )
  })

  it('names an unknown route', () => {
    expect(buildTitle({ unknown: true })).toBe('RACCOON — Not found')
  })
})
