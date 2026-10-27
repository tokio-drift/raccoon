import type { JSX } from 'react'
import { useState } from 'react'

import { Icon } from '../../assets/icons'
import { usePreferences, type TimeBasis } from '../../lib/preferences'
import { Button } from '../primitives/Button'
import { Drawer, Modal } from '../primitives/Overlay'

/** The help drawer (P1, UI_Design.md §8.13). */
export function HelpDrawer({
  onClose,
  toolVersion,
}: {
  onClose: () => void
  toolVersion?: string
}): JSX.Element {
  return (
    <Drawer title="Help" onClose={onClose}>
      <section className="overlay__section">
        <h3>Quick start</h3>
        <ol className="help-steps">
          <li>Drop a capture file on the dashboard. RACCOON reads it on this computer.</li>
          <li>Read the Storyboard: every event sits next to the bytes that prove it.</li>
          <li>Check the Files tab for threat-check results, then download only what you need.</li>
        </ol>
      </section>

      <section className="overlay__section">
        <h3>Terms</h3>
        <dl className="help-terms">
          <dt>Storyboard</dt>
          <dd>The events RACCOON found, in the order they happened.</dd>
          <dt>Event</dt>
          <dd>One moment in the capture: a login, a web request, a DNS lookup, a file, a verdict…</dd>
          <dt>Finding</dt>
          <dd>A conclusion drawn from one or more events.</dd>
          <dt>Files</dt>
          <dd>A file RACCOON pulled out of the traffic.</dd>
          <dt>Carved</dt>
          <dd>Found and cut out of the raw bytes by recognising the file&apos;s start.</dd>
          <dt>Stream</dt>
          <dd>One conversation between two computers.</dd>
          <dt>Packet</dt>
          <dd>A small chunk of data on the network.</dd>
          <dt>Verdict</dt>
          <dd>What threat intelligence says about a file.</dd>
          <dt>Hash</dt>
          <dd>A fingerprint of a file. Same file, same hash.</dd>
          <dt>Offset</dt>
          <dd>How many bytes into the stream something starts.</dd>
          <dt>Cleartext</dt>
          <dd>Sent without encryption, so anyone on the network could read it.</dd>
        </dl>
      </section>

      <section className="overlay__section">
        <h3>Privacy and safety</h3>
        <p>
          Everything runs on this computer. There is no account and no cloud. For threat checks, RACCOON
          sends only a file&apos;s hash (a fingerprint), never the file. RACCOON never opens, runs, or
          previews files taken from a capture. Everything from the capture, including names, URLs and
          banners, is shown as plain text. Downloads are saved under a neutral name.
        </p>
      </section>

      <section className="overlay__section">
        <h3>Keyboard shortcuts</h3>
        <ShortcutList />
      </section>

      <section className="overlay__section">
        <h3>About</h3>
        <p>
          RACCOON — Reliable and Consistent Cybersecurity Operations Over Network.
          {toolVersion ? ` Version ${toolVersion}.` : ''}
        </p>
      </section>
    </Drawer>
  )
}

const SHORTCUTS: Array<[string, string]> = [
  ['/', 'Focus the search of the current view'],
  ['g then s', 'Go to the Storyboard'],
  ['g then f', 'Go to Files'],
  ['g then t', 'Go to Streams'],
  ['?', 'Show the keyboard shortcuts'],
  ['Esc', 'Close the topmost overlay, or return focus to the list'],
  ['Ctrl/Cmd+Shift+E', 'Open Export report'],
  ['Arrow keys', 'Move within lists, tabs, menus and the hex table'],
  ['F6', 'Cycle between the list, the detail pane and the footer'],
]

/** The shortcut list, shared by the help drawer and the shortcut overlay. */
export function ShortcutList(): JSX.Element {
  return (
    <dl className="help-terms">
      {SHORTCUTS.map(([keys, description]) => (
        <div key={keys} className="help-term">
          <dt className="mono">{keys}</dt>
          <dd>{description}</dd>
        </div>
      ))}
    </dl>
  )
}

/** The shortcut overlay, opened with "?" (UI_Design.md §8.13). */
export function ShortcutOverlay({ onClose }: { onClose: () => void }): JSX.Element {
  return (
    <Modal title="Keyboard shortcuts" onClose={onClose}>
      <ShortcutList />
      <div className="overlay__actions">
        <Button variant="secondary" onClick={onClose} data-overlay-cancel>
          Close
        </Button>
      </div>
    </Modal>
  )
}

/** The settings popover (P4, UI_Design.md §8.13, §10.2). */
export function SettingsPopover({ onClose }: { onClose: () => void }): JSX.Element {
  const [preferences, setPreference] = usePreferences()

  return (
    <div className="popover" role="dialog" aria-label="Settings">
      <fieldset className="settings-group">
        <legend className="label">Theme</legend>
        {(['system', 'light', 'dark'] as const).map((option) => (
          <label key={option} className="settings-option">
            <input
              type="radio"
              name="theme"
              value={option}
              checked={preferences.theme === option}
              onChange={() => setPreference('theme', option)}
            />
            {option === 'system' ? 'System' : option === 'light' ? 'Light' : 'Dark'}
          </label>
        ))}
      </fieldset>

      <fieldset className="settings-group">
        <legend className="label">Time zone</legend>
        {(['utc', 'local'] as const).map((option) => (
          <label key={option} className="settings-option">
            <input
              type="radio"
              name="timeBasis"
              value={option}
              checked={preferences.timeBasis === option}
              onChange={() => setPreference('timeBasis', option as TimeBasis)}
            />
            {option === 'utc' ? 'UTC' : 'Local'}
          </label>
        ))}
      </fieldset>

      <fieldset className="settings-group">
        <legend className="label">Density</legend>
        {(['comfortable', 'compact'] as const).map((option) => (
          <label key={option} className="settings-option">
            <input
              type="radio"
              name="density"
              value={option}
              checked={preferences.density === option}
              onChange={() => setPreference('density', option)}
            />
            {option === 'comfortable' ? 'Comfortable' : 'Compact'}
          </label>
        ))}
      </fieldset>

      <fieldset className="settings-group">
        <legend className="label">Projector text</legend>
        <label className="settings-option">
          <input
            type="checkbox"
            checked={preferences.projectorText}
            onChange={(event) => setPreference('projectorText', event.target.checked)}
          />
          Use larger text for projection
        </label>
      </fieldset>

      <div className="overlay__actions">
        <Button variant="secondary" onClick={onClose}>
          Close
        </Button>
      </div>
    </div>
  )
}

/** The export dialog (P2, UI_Design.md §8.12). Downloads the HTML report. */
export function ExportDialog({
  onClose,
  onDownload,
  onCopyDiagnostics,
  partial = false,
  notChecked = 0,
  hasCredentials = false,
}: {
  onClose: () => void
  /** Called when the user confirms; resolves when the download is ready. */
  onDownload: () => Promise<void>
  /** Copies diagnostic details for troubleshooting. */
  onCopyDiagnostics?: () => void
  /** The analysis stopped early, so the report is marked as partial (§8.5). */
  partial?: boolean
  /** The number of files whose threat check never arrived. */
  notChecked?: number
  /** A credential was sent in cleartext and is part of the report. */
  hasCredentials?: boolean
}): JSX.Element {
  const [status, setStatus] = useState<'idle' | 'preparing' | 'error'>('idle')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  async function handleDownload() {
    setStatus('preparing')
    setErrorMsg(null)
    try {
      await onDownload()
      onClose()
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : String(err))
      setStatus('error')
    }
  }

  return (
    <Modal title="Export report" onClose={onClose}>
      <p>A single report of this case: summary, storyboard, files and their threat check results.</p>
      <p className="text-secondary">HTML report</p>
      {hasCredentials ? (
        <p className="text-secondary">The report includes passwords that were sent in cleartext.</p>
      ) : null}
      {notChecked > 0 ? (
        <p className="text-secondary">{`${notChecked} files are still marked Not checked.`}</p>
      ) : null}
      {partial ? (
        <p className="text-secondary">Report will be marked as partial.</p>
      ) : null}
      {status === 'error' && errorMsg ? (
        <div className="banner banner--error" role="alert">
          <p>{"Couldn't create the report."}</p>
          <p className="text-secondary">{errorMsg}</p>
          <div style={{ display: 'flex', gap: '0.5rem', marginTop: '0.5rem' }}>
            <Button variant="secondary" onClick={handleDownload}>
              Try again
            </Button>
            <Button
              variant="secondary"
              onClick={() => {
                if (onCopyDiagnostics) {
                  onCopyDiagnostics()
                } else {
                  void navigator.clipboard.writeText(errorMsg ?? '')
                }
              }}
            >
              Copy diagnostic info
            </Button>
          </div>
        </div>
      ) : null}
      <div className="overlay__actions">
        <Button variant="secondary" onClick={onClose} data-overlay-cancel>
          Cancel
        </Button>
        <Button
          variant="primary"
          disabled={status === 'preparing'}
          onClick={handleDownload}
        >
          {status === 'preparing' ? 'Preparing report\u2026' : 'Download report'}
        </Button>
      </div>
    </Modal>
  )
}

/** The "replace the current case?" confirmation (UI_Design.md §3.5). */
export function ReplaceCaseDialog({
  onCancel,
  onConfirm,
}: {
  onCancel: () => void
  onConfirm: () => void
}): JSX.Element {
  return (
    <Modal title="Replace the current case?" onClose={onCancel} risky>
      <p>
        RACCOON opens one capture at a time. Uploading a new capture replaces the case you are looking
        at now.
      </p>
      <div className="overlay__actions">
        <Button variant="secondary" onClick={onCancel} data-overlay-cancel>
          Cancel
        </Button>
        <Button variant="primary" onClick={onConfirm}>
          Replace the current case
        </Button>
      </div>
    </Modal>
  )
}

/** The empty-state paw mark, used by the "nothing here" pages. */
export function PawBadge(): JSX.Element {
  return <Icon name="bookmark" size={40} />
}
