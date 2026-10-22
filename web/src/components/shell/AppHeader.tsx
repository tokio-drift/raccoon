import type { JSX } from 'react'

import { MaskMark } from '../../assets/brand'
import { formatCount, formatDuration, formatElapsed } from '../../lib/format'
import type { CaseSummary } from '../../api/types'
import { Button, IconButton } from '../primitives/Button'
import { StatusPill, type StatusKind } from '../primitives/StatusPill'

export interface AppHeaderProps {
  caseSummary: CaseSummary | null
  statusKind: StatusKind
  statusLabel: string
  /**
   * The report can be exported: the timeline is ready, the case is ready or
   * the analysis failed with usable data (UI_Design.md §8.12). While the
   * analysis runs before the timeline is ready, the control is disabled.
   */
  exportAvailable?: boolean
  /** The connection is lost, so a new capture cannot be uploaded. */
  disconnected?: boolean
  onOpenDashboard: () => void
  onUpload: () => void
  onExport: () => void
  onSettings: () => void
  onHelp: () => void
}

/** The header row of the app shell (UI_Design.md §4.2). */
export function AppHeader({
  caseSummary,
  statusKind,
  statusLabel,
  exportAvailable = false,
  disconnected = false,
  onOpenDashboard,
  onUpload,
  onExport,
  onSettings,
  onHelp,
}: AppHeaderProps): JSX.Element {
  const fileName = caseSummary?.fileName ?? ''
  const exportTitle = exportAvailable
    ? 'Export the report of this case.'
    : 'Available when the storyboard is ready.'

  return (
    <header className="app-header">
      <a
        className="brand"
        href="/"
        onClick={(event) => {
          event.preventDefault()
          onOpenDashboard()
        }}
      >
        <MaskMark size={28} />
        <span className="wordmark">RACCOON</span>
      </a>

      {caseSummary ? (
        <div className="app-header__case">
          <span
            className="app-header__case-name"
            dir="auto"
            title={`${fileName} · ${formatCount(caseSummary.size)} bytes · SHA-256 ${caseSummary.pcapSha256} · RACCOON ${caseSummary.toolVersion}`}
          >
            {fileName}
          </span>
          <StatusPill kind={statusKind} label={statusLabel} />
        </div>
      ) : (
        <div className="app-header__case" />
      )}

      <div className="app-header__actions">
        <Button
          variant="secondary"
          icon="upload"
          onClick={onUpload}
          disabled={disconnected}
          title={disconnected ? 'RACCOON cannot reach the local server right now.' : undefined}
        >
          Upload new capture
        </Button>
        <Button
          variant="primary"
          icon="export"
          onClick={onExport}
          disabled={!exportAvailable}
          title={exportTitle}
        >
          Export report
        </Button>
        <IconButton icon="settings" label="Settings" onClick={onSettings} />
        <IconButton icon="help" label="Help" onClick={onHelp} />
      </div>
    </header>
  )
}

/**
 * The header of the empty dashboard: the wordmark, Settings and Help only —
 * no tabs, no case strip, no upload or export control (§8.1).
 */
export function DashboardHeader({
  onSettings,
  onHelp,
}: {
  onSettings: () => void
  onHelp: () => void
}): JSX.Element {
  return (
    <header className="app-header">
      <a
        className="brand"
        href="/"
        onClick={(event) => {
          event.preventDefault()
        }}
      >
        <MaskMark size={28} />
        <span className="wordmark">RACCOON</span>
      </a>
      <div className="app-header__case" />
      <div className="app-header__actions">
        <IconButton icon="settings" label="Settings" onClick={onSettings} />
        <IconButton icon="help" label="Help" onClick={onHelp} />
      </div>
    </header>
  )
}

/** The quiet statistics line of the case strip (UI_Design.md §4.2). */
export function CaseStats({ caseSummary }: { caseSummary: CaseSummary | null }): JSX.Element | null {
  if (!caseSummary) return null
  const durationMs = caseSummary.durationNs / 1_000_000
  return (
    <span className="case-strip__stats">
      <span
        className="case-strip__stat"
        title={`A packet is a small chunk of data on the network. ${formatCount(caseSummary.packets)} packets were in this capture.`}
      >
        {formatCount(caseSummary.packets)} packets
      </span>
      <span
        className="case-strip__stat"
        title="A stream is one conversation between two computers."
      >
        {formatCount(caseSummary.streams)} streams
      </span>
      <span
        className="case-strip__stat case-strip__stat--events"
        title={`${formatCount(caseSummary.events)} events were found in this capture.`}
      >
        {formatCount(caseSummary.events)} events
      </span>
      <span
        className="case-strip__stat case-strip__stat--files"
        title={`${formatCount(caseSummary.files)} files were extracted from this capture.`}
      >
        {formatCount(caseSummary.files)} files
      </span>
      <span
        className="case-strip__stat"
        title={`The capture covers ${formatDuration(durationMs)} of network time.`}
      >
        {formatDuration(durationMs)} capture
      </span>
    </span>
  )
}

/** The elapsed time of a running analysis, used by the header tooltip. */
export function elapsedLabel(startedAt: string, now: number): string {
  const started = Date.parse(startedAt)
  if (Number.isNaN(started)) return ''
  return formatElapsed(now - started)
}
