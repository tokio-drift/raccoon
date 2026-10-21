import { render, screen, within } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import type { CaseSummary } from '../api/types'
import { EmptyDashboard } from './EmptyDashboard'
import { ProcessingView } from './ProcessingView'

const RUNNING_CASE: CaseSummary = {
  id: '20260101-120000-abcdef',
  fileName: 'ftp_upload_png.pcap',
  size: 48213,
  pcapSha256: '9f2c8a1d4e6b7c8d9e0f1a2b3c4d5e6f',
  status: 'running',
  stage: 'process',
  progress: 62,
  durationNs: 0,
  packets: 18230,
  streams: 3,
  files: 5,
  events: 0,
  toolVersion: 'devel',
  startedAt: '2026-01-01T12:00:00.000000000Z',
  finishedAt: '',
  error: '',
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('EmptyDashboard', () => {
  it('shows the elements of the design in order', () => {
    render(<EmptyDashboard />)
    expect(screen.getByRole('heading', { name: 'Follow the trail.' })).toBeInTheDocument()
    expect(screen.getByText(/RACCOON reads a network capture/)).toBeInTheDocument()
    expect(screen.getByText('Accepts .pcap and .pcapng files.')).toBeInTheDocument()
    expect(screen.getByText(/Your capture stays on this computer/)).toBeInTheDocument()
    expect(
      screen.getByText('Reliable and Consistent Cybersecurity Operations Over Network'),
    ).toBeInTheDocument()
  })

  it('names the limit when the server reports one', () => {
    render(<EmptyDashboard maxBytes={500 * 1024 * 1024} />)
    expect(
      screen.getByText('Accepts .pcap and .pcapng files up to 500.0 MB.'),
    ).toBeInTheDocument()
  })

  it('hides the sample case when the server has none', () => {
    render(<EmptyDashboard />)
    expect(screen.queryByRole('button', { name: /sample case/i })).not.toBeInTheDocument()
  })

  it('offers the sample case when the server has one', () => {
    render(<EmptyDashboard sampleAvailable onOpenSample={() => undefined} />)
    expect(
      screen.getByRole('button', { name: /Open the sample case \(ftp_upload_png\.pcap\)/ }),
    ).toBeInTheDocument()
  })

  it('asks for one capture at a time', () => {
    render(<EmptyDashboard />)
    expect(screen.getByText('One capture at a time.')).toBeInTheDocument()
    expect(screen.getByText('Drop a capture file here')).toBeInTheDocument()
  })

  it('explains a file that is not a capture', () => {
    render(<EmptyDashboard state="invalid" />)
    expect(
      screen.getByText("That doesn't look like a capture file. RACCOON reads .pcap and .pcapng files."),
    ).toBeInTheDocument()
  })

  it('names the size and the limit of a file that is too large', () => {
    render(<EmptyDashboard state="too-large" fileName="big.pcap" total={600 * 1024 * 1024} />)
    expect(
      screen.getByText(
        'This file is 600.0 MB. The limit is 500.0 MB. Try a smaller capture, or trim it first.',
      ),
    ).toBeInTheDocument()
  })

  it('shows the progress of the upload', () => {
    render(<EmptyDashboard state="uploading" fileName="capture.pcap" uploaded={512} total={1024} />)
    expect(screen.getByText('Uploading capture.pcap…')).toBeInTheDocument()
    expect(screen.getByText('512 B of 1.0 KB (50%)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel upload' })).toBeInTheDocument()
  })

  it('offers a retry and another file when the upload failed', () => {
    render(
      <EmptyDashboard state="failed" reason="RACCOON stopped unexpectedly." />,
    )
    expect(screen.getByText("The upload didn't finish.")).toBeInTheDocument()
    expect(screen.getByText('RACCOON stopped unexpectedly.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Choose another file' })).toBeInTheDocument()
  })

  it('names the file it used and the files it ignored', () => {
    render(<EmptyDashboard state="too-large" fileName="first.pcap" total={10} ignored={2} />)
    expect(
      screen.getByText(
        'RACCOON opens one capture at a time. Using first.pcap; the other 2 files were ignored.',
      ),
    ).toBeInTheDocument()
  })

  it('shows the note under the dropzone after a cancellation', () => {
    render(<EmptyDashboard note="Upload cancelled. Nothing was kept." />)
    expect(screen.getByText('Upload cancelled. Nothing was kept.')).toBeInTheDocument()
  })
})

describe('the dropzone and the motion preference', () => {
  it('bounces the icon once on a valid drag', () => {
    render(<EmptyDashboard state="dragging" />)
    const dropzone = document.querySelector('.dropzone')
    expect(dropzone?.className).toContain('dropzone--over')
    expect(dropzone?.className).toContain('dropzone--bounce')
  })

  it('does not bounce the icon under reduced motion', () => {
    vi.stubGlobal('matchMedia', (query: string) => ({
      matches: query.includes('prefers-reduced-motion'),
      media: query,
      addEventListener: () => undefined,
      removeEventListener: () => undefined,
    }))
    render(<EmptyDashboard state="dragging" />)
    const dropzone = document.querySelector('.dropzone')
    expect(dropzone?.className).toContain('dropzone--over')
    expect(dropzone?.className).not.toContain('dropzone--bounce')
  })
})

describe('ProcessingView', () => {
  it('shows the eight stages, the current stage and its reassurance', () => {
    render(
      <ProcessingView
        caseSummary={RUNNING_CASE}
        counters={{ streams: 3, files: 5, timelineReady: false }}
        percent={62}
      />,
    )
    const stepper = document.querySelector('.stage-stepper')
    expect(stepper?.children).toHaveLength(8)
    expect(screen.getByRole('heading', { name: 'Extracting files' })).toBeInTheDocument()
    expect(
      screen.getByText('Finding files that crossed the wire. Nothing is opened or run.'),
    ).toBeInTheDocument()
  })

  it('shows the four counters with the live values', () => {
    render(
      <ProcessingView
        caseSummary={RUNNING_CASE}
        counters={{ streams: 3, files: 5, timelineReady: false }}
        percent={62}
        packets={18230}
        bytes={48213}
      />,
    )
    const counters = document.querySelector('.counters')
    expect(counters).not.toBeNull()
    expect(within(counters as HTMLElement).getByText('18,230')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('47.1 KB')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('3')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('5')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('Packets')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('Data read')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('Streams')).toBeInTheDocument()
    expect(within(counters as HTMLElement).getByText('Files found')).toBeInTheDocument()
  })

  it('shows the percent and the elapsed time', () => {
    render(
      <ProcessingView
        caseSummary={RUNNING_CASE}
        counters={{ streams: 3, files: 5, timelineReady: false }}
        percent={62}
      />,
    )
    expect(screen.getByText('62%')).toBeInTheDocument()
    expect(screen.getByText(/^Elapsed /)).toBeInTheDocument()
  })

  it('marks the progress as stale when the connection is quiet', () => {
    render(
      <ProcessingView
        caseSummary={RUNNING_CASE}
        counters={{ streams: 3, files: 5, timelineReady: false }}
        percent={62}
        stale
        lastUpdateAt={Date.now() - 8000}
      />,
    )
    expect(document.querySelector('.progress-bar--stalled')).not.toBeNull()
    expect(document.querySelector('.counters--stale')).not.toBeNull()
    expect(document.querySelector('.processing__percent--stale')).not.toBeNull()
    expect(screen.getByText(/last update \d+ s ago/)).toBeInTheDocument()
  })
})
