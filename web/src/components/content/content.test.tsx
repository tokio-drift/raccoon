import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ArtifactRow, ArtifactTable } from './ArtifactTable'
import { ConfidenceTag, SeverityBadge, VerdictBadge } from './Badges'
import { CredentialField, REMASK_AFTER_MS } from './CredentialField'
import { DetailSection } from './DetailSection'
import { Dropzone } from './Dropzone'
import { EvidenceChip } from './EvidenceChip'
import { EventCard, ChapterHeader, GroupCard } from './EventCard'
import { HexRow, asciiOf, hexOf } from './HexRow'
import { KeyValueRow } from './KeyValueRow'
import { DirectionLegend, SeverityLegend } from './Legend'
import { StageStepper } from './StageStepper'
import { StreamRow } from './StreamRow'
import { TextBlock } from './TextBlock'
import { TimeStrip } from './TimeStrip'

afterEach(() => {
  vi.useRealTimers()
})

describe('SeverityBadge', () => {
  it('carries the severity in the label, not only in the colour', () => {
    render(<SeverityBadge severity="critical" />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
  })

  it('offers the exact helper text of the severity', async () => {
    const user = userEvent.setup()
    render(<SeverityBadge severity="warning" />)
    await user.hover(screen.getByText('Warning'))
    expect(
      await screen.findByText('Suspicious activity, or something worth a closer look.'),
    ).toBeInTheDocument()
  })
})

describe('VerdictBadge', () => {
  it('never calls a file safe', () => {
    render(<VerdictBadge status="no_detections" />)
    expect(screen.getByText('No detections')).toBeInTheDocument()
    expect(document.body.textContent).not.toMatch(/safe/i)
  })

  it('shows the score of the sources and the hash-only note', async () => {
    const user = userEvent.setup()
    render(<VerdictBadge status="malicious" score={2} total={5} source="VirusTotal" />)

    expect(screen.getByText('2 / 5')).toBeInTheDocument()
    await user.hover(screen.getByText('Malicious'))
    expect(
      await screen.findByText(/Only the file's hash is sent for checking/),
    ).toBeInTheDocument()
  })

  it('marks a file that was not checked', () => {
    render(<VerdictBadge status="not_checked" />)
    expect(screen.getByText('Not checked')).toBeInTheDocument()
  })
})

describe('ConfidenceTag', () => {
  it('marks a low-confidence file', () => {
    render(<ConfidenceTag confidence="low" />)
    expect(screen.getByText('Low')).toBeInTheDocument()
  })
})

describe('TextBlock', () => {
  it('renders a hostile value as inert text', () => {
    render(<TextBlock value="<script>alert(1)</script>" />)
    const block = screen.getByText('<script>alert(1)</script>')
    expect(block).toBeInTheDocument()
    expect(block.querySelector('script')).toBeNull()
    expect(document.querySelector('script')).toBeNull()
  })

  it('copies the exact value, not the truncated one', async () => {
    const writeText = vi.fn(async () => undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    const value = 'x'.repeat(200)
    render(<TextBlock value={value} />)

    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: 'Copy' }))
    })
    expect(writeText).toHaveBeenCalledWith(value)
  })
})

describe('KeyValueRow', () => {
  it('marks a value that was not recorded', () => {
    render(<KeyValueRow label="Result" unknown />)
    expect(screen.getByText('Not recorded')).toBeInTheDocument()
  })

  it('keeps a masked value masked', () => {
    const { container } = render(<KeyValueRow label="Password" masked />)
    expect(container.textContent).toContain('••••••••')
  })
})

describe('CredentialField', () => {
  it('masks the password and reveals it on demand', async () => {
    const user = userEvent.setup()
    render(<CredentialField value="hunter2" />)

    expect(screen.getByText('••••••••')).toBeInTheDocument()
    expect(document.body.textContent).not.toContain('hunter2')

    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(screen.getByText('hunter2')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Hide password' })).toBeInTheDocument()
  })

  it('masks the password again after 30 seconds', () => {
    vi.useFakeTimers()
    render(<CredentialField value="hunter2" />)

    act(() => {
      fireEvent.click(screen.getByRole('button', { name: 'Show password' }))
    })
    expect(screen.getByText('hunter2')).toBeInTheDocument()

    act(() => {
      vi.advanceTimersByTime(REMASK_AFTER_MS)
    })
    expect(screen.getByText('••••••••')).toBeInTheDocument()
  })

  it('masks the password again when the selection changes', async () => {
    const user = userEvent.setup()
    const { rerender } = render(<CredentialField value="hunter2" selectionKey={1} />)

    await user.click(screen.getByRole('button', { name: 'Show password' }))
    expect(screen.getByText('hunter2')).toBeInTheDocument()

    rerender(<CredentialField value="hunter2" selectionKey={2} />)
    await waitFor(() => expect(screen.getByText('••••••••')).toBeInTheDocument())
  })

  it('says when no password was seen', () => {
    render(<CredentialField />)
    expect(screen.getByText('No password was seen.')).toBeInTheDocument()
  })

  it('says when a password was sent but not recorded', () => {
    render(<CredentialField presenceOnly />)
    expect(screen.getByText('A password was sent (not recorded)')).toBeInTheDocument()
  })
})

describe('EvidenceChip', () => {
  it('points at the packets', () => {
    render(<EvidenceChip kind="packets" label="pkts 14–19" />)
    expect(screen.getByText('pkts 14–19')).toBeInTheDocument()
  })

  it('is a button when it leads somewhere', async () => {
    const onClick = vi.fn()
    const user = userEvent.setup()
    render(<EvidenceChip kind="stream" label="Stream 2" onClick={onClick} />)

    await user.click(screen.getByRole('button', { name: /Stream 2/ }))
    expect(onClick).toHaveBeenCalled()
  })
})

describe('DetailSection', () => {
  it('collapses and expands and remembers the state', async () => {
    const user = userEvent.setup()
    window.localStorage.clear()
    render(
      <DetailSection title="Verdict" sectionKey="verdict">
        <p>Malicious</p>
      </DetailSection>,
    )

    expect(screen.getByText('Malicious')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Verdict' }))
    expect(screen.queryByText('Malicious')).not.toBeInTheDocument()
    expect(window.localStorage.getItem('raccoon.detail.verdict')).toBe('1')
  })
})

describe('EventCard', () => {
  it('shows the severity, the time and the endpoints', () => {
    render(
      <EventCard
        severity="critical"
        elapsed="+00:12.431"
        wallClock="14:03:07.431"
        typeLabel="FTP login failed"
        protocol="FTP"
        title="Login failed for user 'admin'"
        endpoints="192.0.2.14:51822 → 192.0.2.50:21"
        packetRange="pkts 14–19"
      />,
    )

    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('+00:12.431')).toBeInTheDocument()
    expect(screen.getByText('192.0.2.14:51822 → 192.0.2.50:21')).toBeInTheDocument()
    expect(screen.getByText('pkts 14–19')).toBeInTheDocument()
  })

  it('renders a hostile title as inert text', () => {
    render(
      <EventCard
        severity="info"
        elapsed="+00:00.000"
        wallClock="14:03:07.000"
        typeLabel="Banner"
        title="<script>alert(1)</script>"
      />,
    )
    expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })

  it('expands with the space bar', async () => {
    const onToggle = vi.fn()
    const user = userEvent.setup()
    render(
      <EventCard
        severity="info"
        elapsed="+00:00.000"
        wallClock="14:03:07.000"
        typeLabel="DNS query"
        title="Query for example.test"
        onToggle={onToggle}
      />,
    )

    screen.getByRole('listitem').focus()
    await user.keyboard(' ')
    expect(onToggle).toHaveBeenCalled()
  })

  it('shows the summary only when the card is expanded', () => {
    const { rerender } = render(
      <EventCard
        severity="info"
        elapsed="+00:00.000"
        wallClock="14:03:07.000"
        typeLabel="DNS query"
        title="Query for example.test"
        summary="The name was looked up."
      />,
    )
    expect(screen.queryByText('The name was looked up.')).not.toBeInTheDocument()

    rerender(
      <EventCard
        severity="info"
        elapsed="+00:00.000"
        wallClock="14:03:07.000"
        typeLabel="DNS query"
        title="Query for example.test"
        summary="The name was looked up."
        expanded
      />,
    )
    expect(screen.getByText('The name was looked up.')).toBeInTheDocument()
  })
})

describe('GroupCard', () => {
  it('shows the number of the grouped events', () => {
    render(<GroupCard severity="warning" title="Repeated FTP attempts" count={12} />)
    expect(screen.getByText('×12')).toBeInTheDocument()
  })
})

describe('ChapterHeader', () => {
  it('labels the phase and counts the events', () => {
    render(<ChapterHeader label="Access" count={8} span="00:12.0 – 00:41.3" />)
    expect(screen.getByText('Access')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })
})

describe('ArtifactTable', () => {
  const columns = [
    { key: 'name', label: 'Name' },
    { key: 'size', label: 'Size', align: 'right' as const },
    { key: 'verdict', label: 'Verdict', sortable: true, sort: 'ascending' as const },
  ]

  it('is a table with a caption and sortable headers', () => {
    render(
      <ArtifactTable columns={columns} caption="Extracted files">
        <ArtifactRow fileId={4} name="invoice.zip" size={5294} />
      </ArtifactTable>,
    )

    const table = screen.getByRole('table', { name: 'Extracted files' })
    expect(table).toBeInTheDocument()
    expect(screen.getByRole('columnheader', { name: 'Verdict' })).toHaveAttribute(
      'aria-sort',
      'ascending',
    )
    expect(screen.getByText('5,294')).toBeInTheDocument()
  })

  it('shows a path-like name as text with its tag', () => {
    render(
      <ArtifactTable columns={columns} caption="Extracted files">
        <ArtifactRow fileId={5} name="../../etc/passwd" format="Text" />
      </ArtifactTable>,
    )
    expect(screen.getByText('../../etc/passwd')).toBeInTheDocument()
  })

  it('shows a hostile Unicode name as inert text', () => {
    const hostile = 'invoice\u202Etxt.exe\u0000<script>alert(1)</script>'
    render(
      <ArtifactTable columns={columns} caption="Extracted files">
        <ArtifactRow fileId={6} name={hostile} format="Text" />
      </ArtifactTable>,
    )
    expect(screen.getByText(hostile)).toBeInTheDocument()
    expect(document.querySelector('script')).toBeNull()
  })
})

describe('StreamRow', () => {
  it('shows the byte counts and the uncertainty flags', () => {
    render(
      <StreamRow
        streamId={2}
        protocol="FTP"
        endpoints="192.0.2.14:51822 → 192.0.2.50:21"
        bytesC2S={142}
        bytesS2C={402}
        packets={18}
        hasGap
        midstream
      />,
    )

    expect(screen.getByText('Stream 2')).toBeInTheDocument()
    expect(screen.getByText('142 B ↑')).toBeInTheDocument()
    expect(screen.getByText('402 B ↓')).toBeInTheDocument()
    expect(screen.getByText('18 pkts')).toBeInTheDocument()
    expect(screen.getByText('Gap in data')).toBeInTheDocument()
    expect(screen.getByText('Started mid-stream')).toBeInTheDocument()
  })

  it('can be selected with the keyboard', async () => {
    const onSelect = vi.fn()
    const user = userEvent.setup()
    render(<StreamRow streamId={3} onSelect={onSelect} />)

    screen.getByRole('option').focus()
    await user.keyboard('{Enter}')
    expect(onSelect).toHaveBeenCalled()
  })
})

describe('HexRow', () => {
  it('shows the offset, the bytes and the readable text', () => {
    render(
      <table>
        <tbody>
          <HexRow offset={0x4120} bytes={[0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x00]} packetNo={14} />
        </tbody>
      </table>,
    )

    expect(screen.getByRole('rowheader')).toHaveTextContent('00004120')
    expect(screen.getByText('#14')).toBeInTheDocument()
    expect(screen.getByText('48')).toBeInTheDocument()
    expect(screen.getByText('H')).toBeInTheDocument()
  })

  it('never fills a gap with zeros', () => {
    render(
      <table>
        <tbody>
          <HexRow offset={0x100} bytes={[]} gap missing={1460} />
        </tbody>
      </table>,
    )
    expect(
      screen.getByText(/Missing 1,460 bytes\. These packets are not in the capture\./),
    ).toBeInTheDocument()
    expect(screen.queryByText('00')).not.toBeInTheDocument()
  })

  it('shows a byte that is not printable as a middle dot', () => {
    expect(asciiOf(0x00)).toBe('·')
    expect(asciiOf(0x41)).toBe('A')
    expect(hexOf(0x0a)).toBe('0A')
  })
})

describe('TimeStrip', () => {
  it('shows a tick per event and selects one', async () => {
    const onSelect = vi.fn()
    const user = userEvent.setup()
    render(
      <TimeStrip
        ticks={[
          { id: 1, time: 1000, severity: 'info' },
          { id: 2, time: 2000, severity: 'critical' },
        ]}
        duration={4000}
        onSelect={onSelect}
      />,
    )

    const ticks = screen.getAllByRole('button', { name: /Event/ })
    expect(ticks).toHaveLength(2)
    await user.click(ticks[1])
    expect(onSelect).toHaveBeenCalledWith(2)
  })

  it('clears the range with Escape', async () => {
    const onRangeClear = vi.fn()
    const user = userEvent.setup()
    render(
      <TimeStrip
        ticks={[]}
        duration={4000}
        range={[1000, 2000]}
        onRangeClear={onRangeClear}
      />,
    )

    screen.getByRole('group', { name: 'Capture time strip' }).focus()
    await user.keyboard('{Escape}')
    expect(onRangeClear).toHaveBeenCalled()
  })
})

describe('Legend', () => {
  it('names both directions in words', () => {
    render(<DirectionLegend />)
    expect(screen.getByText('Client to server')).toBeInTheDocument()
    expect(screen.getByText('Server to client')).toBeInTheDocument()
  })

  it('counts the severities as text', () => {
    render(<SeverityLegend counts={{ info: 12, warning: 3, critical: 1 }} />)
    expect(screen.getByText('Info 12')).toBeInTheDocument()
    expect(screen.getByText('Warning 3')).toBeInTheDocument()
    expect(screen.getByText('Critical 1')).toBeInTheDocument()
  })
})

describe('StageStepper', () => {
  it('marks the stages that are done and the one that runs', () => {
    render(<StageStepper current="analyse" durations={{ capture: '1 s' }} />)

    const items = screen.getAllByRole('listitem')
    expect(items).toHaveLength(8)
    expect(items[0]).toHaveTextContent('done')
    expect(items[3]).toHaveAttribute('aria-current', 'step')
    expect(items[3]).toHaveTextContent('running')
    expect(items[5]).toHaveTextContent('not started')
    expect(items[0]).toHaveTextContent('1 s')
  })
})

describe('Dropzone', () => {
  it('asks for one capture at a time', () => {
    render(<Dropzone />)
    expect(screen.getByText('Drop a capture file here')).toBeInTheDocument()
    expect(screen.getByText('One capture at a time.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Choose a file…' })).toBeInTheDocument()
  })

  it('names the formats it reads when the file is wrong', () => {
    render(<Dropzone state="invalid" />)
    expect(
      screen.getByText("That doesn't look like a capture file. RACCOON reads .pcap and .pcapng files."),
    ).toBeInTheDocument()
  })

  it('names the size and the limit when the file is too large', () => {
    render(<Dropzone state="too-large" total={629_145_600} limitBytes={524_288_000} />)
    expect(screen.getByText(/This file is 600\.0 MB\./)).toBeInTheDocument()
    expect(screen.getByText(/The limit is 500\.0 MB\./)).toBeInTheDocument()
    // The exact size stays available in the tooltip.
    expect(screen.getByTitle('629,145,600 bytes')).toBeInTheDocument()
  })

  it('shows the upload progress and offers a cancel', () => {
    render(<Dropzone state="uploading" fileName="capture.pcap" uploaded={2048} total={4096} />)
    expect(screen.getByText('Uploading capture.pcap…')).toBeInTheDocument()
    expect(screen.getByText('2.0 KB of 4.0 KB (50%)')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Cancel upload' })).toBeInTheDocument()
  })

  it('offers a retry and another file when the upload failed', async () => {
    const onRetry = vi.fn()
    const user = userEvent.setup()
    render(
      <Dropzone
        state="failed"
        reason="The local server stopped answering."
        onRetry={onRetry}
        onChooseAnother={() => undefined}
      />,
    )

    expect(screen.getByText("The upload didn't finish.")).toBeInTheDocument()
    expect(screen.getByText('The local server stopped answering.')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(onRetry).toHaveBeenCalled()
  })

  it('reports the ignored files of a multi-file drop', () => {
    render(<Dropzone ignored={2} fileName="first.pcap" />)
    expect(
      screen.getByText(
        'RACCOON opens one capture at a time. Using first.pcap; the other 2 files were ignored.',
      ),
    ).toBeInTheDocument()
  })

  it('takes the first file of a drop', () => {
    const onFile = vi.fn()
    const { container } = render(<Dropzone onFile={onFile} />)
    const zone = container.querySelector('.dropzone') as HTMLElement

    const file = new File(['x'], 'capture.pcap', { type: 'application/octet-stream' })
    fireEvent.drop(zone, { dataTransfer: { files: [file] } })
    expect(onFile).toHaveBeenCalledWith(file)
  })
})

describe('a hostile value in a table cell', () => {
  it('is a text node, never markup', () => {
    const { container } = render(
      <ArtifactTable
        columns={[{ key: 'name', label: 'Name' }]}
        caption="Extracted files"
      >
        <ArtifactRow fileId={1} name="<script>alert(1)</script>" />
      </ArtifactTable>,
    )

    const cell = container.querySelector('td')
    expect(cell?.textContent).toContain('<script>alert(1)</script>')
    expect(cell?.querySelector('script')).toBeNull()
    expect(within(cell as HTMLElement).getByText('<script>alert(1)</script>')).toBeInTheDocument()
  })
})
