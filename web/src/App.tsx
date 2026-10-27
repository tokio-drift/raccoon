import { useCallback, useEffect, useMemo, useRef, useState, type JSX } from 'react'

import { ApiClient } from './api/client'
import type { RaccoonApi } from './api/api'
import type { CaseSummary } from './api/types'
import { AppHeader, CaseStats, DashboardHeader } from './components/shell/AppHeader'
import { CaseStrip } from './components/shell/CaseStrip'
import { ExportDialog, HelpDrawer, ReplaceCaseDialog, SettingsPopover, ShortcutOverlay } from './components/shell/Overlays'
import { Banner, IncidentStrip, ProgressHairline, StatusBar } from './components/shell/StatusBar'
import { Button } from './components/primitives/Button'
import { useToast } from './components/primitives/Toast'
import { useCaseEvents } from './hooks/useCaseEvents'
import { useCaseSummary } from './hooks/useCaseSummary'
import { useNow } from './hooks/useNow'
import { useUpload } from './hooks/useUpload'
import { usePreferences } from './lib/preferences'
import { useRoute, type CaseTab, type URLParams } from './lib/router'
import { buildTitle, useDocumentTitle, useFavicon } from './lib/title'
import { captureTokenFromLocation, getSessionToken } from './lib/token'
import { formatClock, formatCount, formatDuration, formatPercent, formatZoneLabel } from './lib/format'
import { buildDiagnostics, copyText } from './lib/diagnostics'
import type { StageCounters } from './lib/stages'
import { EmptyDashboard } from './views/EmptyDashboard'
import { ProcessingView } from './views/ProcessingView'
import { FilesView } from './views/FilesView'
import { StoryboardView } from './views/StoryboardView'
import { StreamsView, type StreamsOrigin } from './views/StreamsView'
import { FailedCase } from './views/FailedCase'

type Overlay = 'help' | 'settings' | 'shortcuts' | 'export' | 'replace' | null

/** The time without a connection before the banner turns into an error. */
export const RECONNECT_GIVE_UP_MS = 30000

export interface AppProps {
  /** The API client; the app builds a real one when none is given. */
  api?: RaccoonApi
}

export function App({ api }: AppProps): JSX.Element {
  const { route, ignored, navigate } = useRoute()
  const client = useMemo(() => api ?? new ApiClient(), [api])
  const [overlay, setOverlay] = useState<Overlay>(null)
  const [preferences, setPreference] = usePreferences()
  const toast = useToast()
  const now = useNow()

  // Where the reader came from. The inspector shows it as a chip and the chip
  // survives a tab switch, but it is not part of the URL (§3.2, §7.11).
  const [streamsOrigin, setStreamsOrigin] = useState<StreamsOrigin | null>(null)

  // The session token is read from the URL once and then removed from the
  // address bar; it never appears in the DOM.
  useEffect(() => {
    captureTokenFromLocation()
  }, [])

  const caseId = route.kind === 'case' ? route.caseId : null
  const { caseSummary, error, reload } = useCaseSummary(caseId, client)
  // A case that does not exist has no event stream to follow: following it
  // would ask the server for a case that is not there, over and over.
  const caseGone = error !== null && (error.isNotFound || error.isAuthError)
  const events = useCaseEvents(caseGone ? null : caseId, client)

  const onUploaded = useCallback(
    (newCaseId: string) => {
      navigate(`/case/${encodeURIComponent(newCaseId)}/storyboard`)
    },
    [navigate],
  )
  const upload = useUpload(client, { onUploaded })

  const status = caseSummary?.status ?? 'queued'
  const running = status === 'running' || status === 'queued'
  const failed = status === 'failed'
  const timelineReady = events.timelineReady || status === 'ready'

  // The event stream is fresher than the polled summary.
  const progress = events.progress?.percent ?? caseSummary?.progress ?? 0
  const stage = events.progress?.stage ?? caseSummary?.stage ?? 'starting'
  const stale = events.stale

  // The analysis has finished: the polled summary is refreshed once.
  useEffect(() => {
    if (events.done) reload()
  }, [events.done, reload])

  // The connection dropped (UI_Design.md §8.7).
  const reconnecting = events.status === 'reconnecting'
  const [reconnectSince, setReconnectSince] = useState<number | null>(null)
  useEffect(() => {
    setReconnectSince((since) => (reconnecting ? (since ?? Date.now()) : null))
  }, [reconnecting])
  const reconnectAge = reconnectSince === null ? 0 : now - reconnectSince
  const reconnectGivenUp = reconnecting && reconnectAge >= RECONNECT_GIVE_UP_MS

  // The notes of the export dialog (§8.12): the files that were never
  // checked and the credentials that the report would carry.
  const [exportFacts, setExportFacts] = useState({ notChecked: 0, hasCredentials: false })

  // The files whose threat check has not arrived yet (UI_Design.md §8.4). The
  // state is shown while the analysis runs; a finished analysis marks the
  // files that were never checked as "Not checked".
  const checkedFiles = Object.keys(events.verdicts).length
  const checkingFiles =
    running && timelineReady && caseSummary !== null && checkedFiles < caseSummary.files

  // The analysis stopped early: the results may still be usable (§8.5).
  const partialResults =
    failed &&
    (timelineReady ||
      (caseSummary?.events ?? 0) > 0 ||
      (caseSummary?.files ?? 0) > 0 ||
      (caseSummary?.streams ?? 0) > 0)

  // The report can be exported when the timeline is ready, when the case is
  // ready or when the analysis failed with usable data (§8.12). A lost
  // connection disables the control (§14.5).
  const exportAvailable = (timelineReady || partialResults) && !reconnecting

  // The facts of the export dialog are read when the dialog opens.
  useEffect(() => {
    if (overlay !== 'export' || !caseId) return
    let cancelled = false
    void (async () => {
      try {
        const [eventPage, filePage] = await Promise.all([
          client.listEvents(caseId, { flat: true, limit: 1000 }),
          client.listFiles(caseId, { confidence: 'all' }),
        ])
        if (cancelled) return
        const notChecked = filePage.items.filter(
          (file) => !file.verdict || file.verdict.status === 'not_checked',
        ).length
        const hasCredentials = eventPage.items.some(
          (event) =>
            (event.type ?? '').startsWith('FTP_LOGIN') &&
            (event.details as Record<string, unknown> | undefined)?.password !== undefined,
        )
        setExportFacts({ notChecked, hasCredentials })
      } catch {
        // The notes are optional; the dialog opens without them.
      }
    })()
    return () => {
      cancelled = true
    }
  }, [overlay, caseId, client])

  const statusKind = failed
    ? 'failed'
    : reconnecting
      ? 'disconnected'
      : checkingFiles
        ? 'checking'
        : running
          ? 'running'
          : 'ready'
  const statusLabel = failed
    ? 'Analysis failed'
    : reconnecting
      ? 'Reconnecting…'
      : running && !checkingFiles
        ? `Analysing · ${stage} · ${formatPercent(progress)}`
        : checkingFiles && caseSummary
          ? `Timeline ready · checking files ${checkedFiles} of ${caseSummary.files}`
          : 'Ready'

  const view: CaseTab | null = route.kind === 'case' ? route.tab : null

  const title = buildTitle({
    fileName: caseSummary?.fileName,
    status: failed ? 'failed' : running ? 'running' : 'ready',
    percent: progress,
    view,
    unknown: route.kind === 'not-found',
  })
  useDocumentTitle(title)
  useFavicon(failed ? 'failed' : running ? 'working' : 'normal')

  // The analysis has finished while the reader was watching (UI_Design.md §8.9).
  const wasRunning = useRef(false)
  const storyboardHeading = useRef<HTMLHeadingElement | null>(null)
  const [completion, setCompletion] = useState<{ summary: CaseSummary; at: number } | null>(null)
  useEffect(() => {
    // Before the summary arrives the case counts as running; that is not a
    // run the reader watched, so the completion is not announced.
    if (running && caseSummary) {
      wasRunning.current = true
      return
    }
    if (!wasRunning.current || completion || !caseSummary || caseSummary.status !== 'ready') return
    wasRunning.current = false
    setCompletion({ summary: caseSummary, at: Date.now() })
  }, [running, caseSummary, completion])

  // The Processing view becomes the Storyboard: the focus follows (UI_Design.md
  // §8.9). On another tab the focus stays where it is.
  useEffect(() => {
    if (!completion) return
    if (view !== null && view !== 'storyboard') return
    storyboardHeading.current?.focus()
  }, [completion, view])

  // The critical escalations (UI_Design.md §8.10). A file that becomes
  // malicious while the reader watches raises the incident strip; the strip
  // stays until it is dismissed and never dismisses itself.
  const [incident, setIncident] = useState<{ fileId: number; name: string } | null>(null)
  const escalated = useRef<Set<number>>(new Set())
  const maliciousVerdicts = useMemo(
    () => Object.values(events.verdicts).filter((verdict) => verdict.status === 'malicious'),
    [events.verdicts],
  )
  useEffect(() => {
    if (!caseId || maliciousVerdicts.length === 0) return
    const fresh = maliciousVerdicts.find((verdict) => !escalated.current.has(verdict.fileId))
    if (!fresh) return
    escalated.current.add(fresh.fileId)
    let cancelled = false
    client
      .listFiles(caseId, { confidence: 'all' })
      .then((page) => {
        if (cancelled) return
        const file = page.items.find((item) => item.id === fresh.fileId)
        setIncident({
          fileId: fresh.fileId,
          name: file?.displayName ?? `File ${fresh.fileId}`,
        })
      })
      .catch(() => {
        if (cancelled) return
        setIncident({ fileId: fresh.fileId, name: `File ${fresh.fileId}` })
      })
    return () => {
      cancelled = true
    }
  }, [caseId, client, maliciousVerdicts])

  // The critical events of the finished analysis, for the announcement and the
  // first action of the banner (UI_Design.md §8.9). The count is exact up to
  // the page size of the server; beyond that it is a lower bound.
  const CRITICAL_PAGE_SIZE = 1000
  const [critical, setCritical] = useState<{ count: number; firstId: number | null; exact: boolean }>({
    count: 0,
    firstId: null,
    exact: true,
  })
  useEffect(() => {
    if (!completion || !caseId) return
    let cancelled = false
    client
      .listEvents(caseId, { severity: ['critical'], limit: CRITICAL_PAGE_SIZE })
      .then((page) => {
        if (cancelled) return
        const items = page.items
        setCritical({
          count: items.length,
          firstId: items.length > 0 ? items[0].id : null,
          exact: items.length < CRITICAL_PAGE_SIZE,
        })
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [completion, caseId, client])

  const announcement = completion
    ? `Analysis complete. ${formatCount(completion.summary.events)} events, ${formatCount(
        completion.summary.files,
      )} files, ${formatCount(completion.summary.streams)} streams${
        critical.count > 0
          ? `, ${formatCount(critical.count)}${critical.exact ? '' : '+'} critical event${
              critical.count === 1 ? '' : 's'
            }`
          : ''
      }.`
    : null

  // The technical detail of the partial-failure banner (§8.5).
  const [failureDetail, setFailureDetail] = useState(false)

  // The reader is on another tab: a toast points at the storyboard.
  useEffect(() => {
    if (!completion || !caseId) return
    if (view && view !== 'storyboard') {
      toast.push({
        tone: 'success',
        message: 'Analysis complete',
        action: {
          label: 'Open Storyboard',
          onClick: () => navigate(`/case/${encodeURIComponent(caseId)}/storyboard`),
        },
      })
    }
  }, [completion, caseId, view, navigate, toast])

  // The connection came back (UI_Design.md §8.7).
  const previousStatus = useRef(events.status)
  const verdictsAtDrop = useRef(0)
  const verdictCount = Object.keys(events.verdicts).length
  useEffect(() => {
    if (events.status === 'reconnecting') {
      verdictsAtDrop.current = verdictCount
    }
  }, [events.status, verdictCount])
  useEffect(() => {
    const was = previousStatus.current
    previousStatus.current = events.status
    if (was !== 'reconnecting' || events.status !== 'open') return
    const refreshed = verdictCount - verdictsAtDrop.current
    toast.push({
      tone: 'success',
      message:
        refreshed > 0 ? `Reconnected. Refreshed ${refreshed} file checks.` : 'Reconnected.',
      duration: 4000,
    })
  }, [events.status, verdictCount, toast])

  // Global shortcuts (UI_Design.md §13.2).
  useEffect(() => {
    let pending = ''
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      if (event.key === '?' && !event.metaKey && !event.ctrlKey && !event.altKey) {
        event.preventDefault()
        setOverlay('shortcuts')
        return
      }
      if (event.key === 'g') {
        pending = 'g'
        window.setTimeout(() => {
          pending = ''
        }, 1200)
        return
      }
      if (pending === 'g') {
        const tab = { s: 'storyboard', f: 'files', t: 'streams' }[event.key]
        if (tab && caseId) {
          event.preventDefault()
          navigate(`/case/${encodeURIComponent(caseId)}/${tab}`)
        }
        pending = ''
        return
      }
      if ((event.metaKey || event.ctrlKey) && event.shiftKey && event.key.toLowerCase() === 'e') {
        if (!exportAvailable) return
        event.preventDefault()
        setOverlay('export')
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [caseId, navigate, exportAvailable])

  const onSelectTab = (tab: CaseTab) => {
    if (!caseId) return
    navigate(`/case/${encodeURIComponent(caseId)}/${tab}`)
  }

  const openStoryboard = useCallback(() => {
    if (!caseId) return
    navigate(`/case/${encodeURIComponent(caseId)}/storyboard`)
  }, [caseId, navigate])

  const openFirstCritical = useCallback(() => {
    if (!caseId) return
    if (critical.firstId === null) {
      navigate(`/case/${encodeURIComponent(caseId)}/storyboard`)
      return
    }
    navigate(`/case/${encodeURIComponent(caseId)}/storyboard?event=${critical.firstId}`)
  }, [caseId, critical.firstId, navigate])

  const openFiles = useCallback(() => {
    if (!caseId) return
    navigate(`/case/${encodeURIComponent(caseId)}/files`)
  }, [caseId, navigate])

  // The filters of the storyboard live in the URL (§3.2). The event the reader
  // has selected is kept, because the filter bar does not own it.
  const onStoryboardParams = useCallback(
    (params: URLParams) => {
      if (!caseId) return
      const merged: URLParams = { ...params }
      const current = route.kind === 'case' ? route.params.event : undefined
      if (current && !merged.event) merged.event = current
      const search = new URLSearchParams()
      for (const [key, value] of Object.entries(merged)) {
        if (value) search.set(key, value)
      }
      const query = search.toString()
      const next = `/case/${encodeURIComponent(caseId)}/storyboard${query ? `?${query}` : ''}`
      const here = `${window.location.pathname}${window.location.search}`
      if (next === here) return
      navigate(next, { replace: true })
    },
    [caseId, navigate, route],
  )

  // The filters of the files gallery live in the URL (§3.2). The file the
  // reader has selected is kept, because the filter bar does not own it.
  const onFilesParams = useCallback(
    (params: URLParams) => {
      if (!caseId) return
      const merged: URLParams = { ...params }
      const current = route.kind === 'case' ? route.params.file : undefined
      if (current && !merged.file) merged.file = current
      const search = new URLSearchParams()
      for (const [key, value] of Object.entries(merged)) {
        if (value) search.set(key, value)
      }
      const query = search.toString()
      const next = `/case/${encodeURIComponent(caseId)}/files${query ? `?${query}` : ''}`
      const here = `${window.location.pathname}${window.location.search}`
      if (next === here) return
      navigate(next, { replace: true })
    },
    [caseId, navigate, route],
  )

  // The deep links of the stream inspector live in the URL (§3.2). The stream
  // the reader has selected is kept, because the panes do not own it.
  const onStreamsParams = useCallback(
    (params: URLParams) => {
      if (!caseId) return
      const merged: URLParams = { ...params }
      const current = route.kind === 'case' ? route.params.stream : undefined
      if (current && !merged.stream) merged.stream = current
      const search = new URLSearchParams()
      for (const [key, value] of Object.entries(merged)) {
        if (value) search.set(key, value)
      }
      const query = search.toString()
      const next = `/case/${encodeURIComponent(caseId)}/streams${query ? `?${query}` : ''}`
      const here = `${window.location.pathname}${window.location.search}`
      if (next === here) return
      navigate(next, { replace: true })
    },
    [caseId, navigate, route],
  )

  // The diagnostic text never holds the session token (UI_Design.md §8.5).
  const copyDiagnostics = useCallback(() => {
    const text = buildDiagnostics({
      caseId,
      fileName: caseSummary?.fileName,
      size: caseSummary?.size,
      sha256: caseSummary?.pcapSha256,
      toolVersion: caseSummary?.toolVersion,
      stage,
      progress,
      startedAt: caseSummary?.startedAt,
      errorCode: events.error?.code,
      errorMessage: events.error?.message,
    })
    void copyText(text).then((copied) => {
      toast.push(
        copied
          ? { tone: 'success', message: 'Diagnostic info copied.' }
          : { tone: 'error', message: "Couldn't copy the diagnostic info." },
      )
    })
  }, [caseId, caseSummary, stage, progress, events.error, toast])

  const handleExportDownload = useCallback(async () => {
    if (!caseId) return
    const { blob, filename } = await client.downloadReport(caseId, 'html')
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = filename || `raccoon-report-${caseSummary?.fileName || caseId}.html`
    anchor.rel = 'noopener'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
    const downloadedName = anchor.download
    toast.push({
      tone: 'success',
      message: `Report downloaded as ${downloadedName}`,
    })
  }, [caseId, caseSummary?.fileName, client, toast])

  const counters: StageCounters = {
    streams: events.progress?.streams ?? caseSummary?.streams ?? 0,
    files: events.progress?.files ?? caseSummary?.files ?? 0,
    timelineReady: events.timelineReady,
  }

  if (route.kind === 'not-found') {
    return (
      <div className="app-shell">
        <FullPageUnknown onGoHome={() => navigate('/')} />
      </div>
    )
  }

  if (error?.isAuthError || (error && error.status === 0)) {
    return (
      <div className="app-shell">
        <DashboardHeader
          onSettings={() => setOverlay('settings')}
          onHelp={() => setOverlay('help')}
        />
        <FullPageSession
          error={error}
          onRetry={() => window.location.reload()}
          onCopyDiagnostics={copyDiagnostics}
        />
        {overlay === 'help' ? <HelpDrawer onClose={() => setOverlay(null)} /> : null}
        {overlay === 'shortcuts' ? <ShortcutOverlay onClose={() => setOverlay(null)} /> : null}
        {overlay === 'settings' ? <SettingsPopover onClose={() => setOverlay(null)} /> : null}
      </div>
    )
  }

  if (route.kind === 'empty') {
    return (
      <div className="app-shell">
        <DashboardHeader
          onSettings={() => setOverlay('settings')}
          onHelp={() => setOverlay('help')}
        />
        <EmptyDashboard
          state={upload.state.status}
          fileName={upload.state.file?.name}
          uploaded={upload.state.uploaded}
          total={upload.state.total}
          reason={upload.state.reason}
          note={upload.state.note}
          ignored={upload.state.ignored}
          onFiles={upload.start}
          onCancel={upload.cancel}
          onRetry={upload.retry}
          onChooseAnother={upload.chooseAnother}
        />
        <StatusBar
          timeBasis={preferences.timeBasis}
          onToggleTimeBasis={() =>
            setPreference('timeBasis', preferences.timeBasis === 'utc' ? 'local' : 'utc')
          }
          onHelp={() => setOverlay('help')}
        />
        {overlay === 'help' ? <HelpDrawer onClose={() => setOverlay(null)} /> : null}
        {overlay === 'shortcuts' ? <ShortcutOverlay onClose={() => setOverlay(null)} /> : null}
        {overlay === 'settings' ? <SettingsPopover onClose={() => setOverlay(null)} /> : null}
      </div>
    )
  }

  const caseMissing = error?.isNotFound === true

  // A case that failed without usable data has its own page (S5). The tabs
  // are hidden; the header keeps the case name and the Failed pill.
  if (failed && !partialResults) {
    return (
      <div className="app-shell">
        <AppHeader
          caseSummary={caseSummary}
          statusKind={statusKind}
          statusLabel={statusLabel}
          exportAvailable={exportAvailable}
          onOpenDashboard={() => navigate('/')}
          onUpload={() => navigate('/')}
          onExport={() => setOverlay('export')}
          onSettings={() => setOverlay('settings')}
          onHelp={() => setOverlay('help')}
        />
        <main className="content-area" id="case-panel">
          <FailedCase
            caseSummary={caseSummary}
            stage={stage}
            progress={progress}
            errorCode={caseSummary?.error || null}
            errorMessage={events.error?.message ?? null}
            canRetry={upload.state.file !== null}
            onRetry={upload.retry}
            onChooseAnother={() => navigate('/')}
            onCopyDiagnostics={copyDiagnostics}
          />
        </main>
        <StatusBar
          timeBasis={preferences.timeBasis}
          onToggleTimeBasis={() =>
            setPreference('timeBasis', preferences.timeBasis === 'utc' ? 'local' : 'utc')
          }
          onHelp={() => setOverlay('help')}
        />
        {overlay === 'help' ? <HelpDrawer onClose={() => setOverlay(null)} /> : null}
        {overlay === 'shortcuts' ? <ShortcutOverlay onClose={() => setOverlay(null)} /> : null}
        {overlay === 'settings' ? <SettingsPopover onClose={() => setOverlay(null)} /> : null}
        {overlay === 'export' ? (
          <ExportDialog
            onClose={() => setOverlay(null)}
            onDownload={handleExportDownload}
            onCopyDiagnostics={copyDiagnostics}
            partial={partialResults}
            notChecked={exportFacts.notChecked}
            hasCredentials={exportFacts.hasCredentials}
          />
        ) : null}
      </div>
    )
  }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#case-panel">
        Skip to content
      </a>

      <AppHeader
        caseSummary={caseSummary}
        statusKind={statusKind}
        statusLabel={statusLabel}
        exportAvailable={exportAvailable}
        disconnected={reconnecting}
        onOpenDashboard={() => {
          if (running) setOverlay('replace')
          else navigate('/')
        }}
        onUpload={() => {
          if (running) setOverlay('replace')
          else navigate('/')
        }}
        onExport={() => setOverlay('export')}
        onSettings={() => setOverlay('settings')}
        onHelp={() => setOverlay('help')}
      />

      {running ? <ProgressHairline percent={progress} stale={stale} /> : null}

      <CaseStrip
        activeTab={view}
        onSelectTab={onSelectTab}
        filesCount={caseSummary?.files ?? 0}
        streamsCount={caseSummary?.streams ?? 0}
      >
        <CaseStats caseSummary={caseSummary} />
      </CaseStrip>

      <div className="banner-slot">
        {incident ? (
          <IncidentStrip
            more={0}
            onView={() => {
              if (!caseId) return
              navigate(`/case/${encodeURIComponent(caseId)}/files?file=${incident.fileId}`)
            }}
            onDismiss={() => setIncident(null)}
          >
            {`Critical: ${incident.name} now has a Malicious verdict.`}
          </IncidentStrip>
        ) : null}
        {ignored ? (
          <Banner tone="info">Ignored an unrecognised filter</Banner>
        ) : null}
        {caseMissing ? (
          <Banner tone="error">
            We can&apos;t find that case. It may have been removed or this server may have restarted.
          </Banner>
        ) : null}
        {reconnecting ? (
          <Banner
            tone={reconnectGivenUp ? 'error' : 'warning'}
            actions={
              reconnectGivenUp ? (
                <>
                  <Button variant="primary" onClick={events.reconnect}>
                    Try now
                  </Button>
                  <Button variant="secondary" onClick={copyDiagnostics}>
                    Copy diagnostic info
                  </Button>
                </>
              ) : null
            }
          >
            {reconnectGivenUp
              ? "Still can't reach RACCOON."
              : `Connection lost. Reconnecting… (attempt ${events.attempt})`}
          </Banner>
        ) : null}
        {events.error ? (
          <Banner tone="warning">
            {`The live connection reported a problem: ${events.error.message}`}
          </Banner>
        ) : null}
        {partialResults ? (
          <Banner
            tone="warning"
            actions={
              <>
                <Button variant="secondary" onClick={() => navigate('/')}>
                  Choose another capture
                </Button>
                <Button variant="secondary" onClick={copyDiagnostics}>
                  Copy diagnostic info
                </Button>
                <Button
                  variant="tertiary"
                  onClick={() => setFailureDetail((open) => !open)}
                >
                  See what went wrong
                </Button>
              </>
            }
          >
            {`Analysis stopped at "${stage}". Results below are partial. Events, files or streams may be missing.`}
          </Banner>
        ) : null}
        {partialResults && failureDetail ? (
          <Banner tone="info">
            {[
              caseSummary?.error ? `Error: ${caseSummary.error}` : null,
              events.error ? `Server message: ${events.error.message}` : null,
              `Stage: ${stage}`,
              `Progress: ${formatPercent(progress)}`,
              `Capture: ${caseSummary?.fileName ?? 'unknown'}`,
              `Tool version: ${caseSummary?.toolVersion ?? 'unknown'}`,
            ]
              .filter((line): line is string => line !== null)
              .join(' · ')}
          </Banner>
        ) : null}
        {completion ? (
          <Banner
            tone="info"
            onDismiss={() => setCompletion(null)}
            actions={
              <>
                <Button variant="primary" onClick={critical.firstId === null ? openStoryboard : openFirstCritical}>
                  {critical.firstId === null ? 'Start reading' : 'Go to first critical event'}
                </Button>
                <Button variant="secondary" onClick={openFiles}>
                  Open Files
                </Button>
                <Button variant="tertiary" onClick={() => setOverlay('export')}>
                  Export report
                </Button>
              </>
            }
          >
            {`Analysis finished in ${formatDuration(completion.summary.durationNs / 1_000_000)}.`}
          </Banner>
        ) : null}
      </div>

      <main className="content-area" id="case-panel" role="tabpanel" aria-labelledby="tab-storyboard">
        <p className="live-region" aria-live="polite">
          {announcement ?? ''}
        </p>
        {caseMissing ? (
          <FullPageUnknown onGoHome={() => navigate('/')} />
        ) : running && !timelineReady ? (
          <ProcessingView
            caseSummary={caseSummary}
            counters={counters}
            percent={progress}
            packets={events.progress?.packets}
            bytes={events.progress?.bytes}
            stale={stale}
            lastUpdateAt={events.lastUpdateAt}
          />
        ) : view === 'files' ? (
          <FilesView
            caseId={caseId as string}
            api={client}
            params={route.kind === 'case' ? route.params : {}}
            onParamsChange={onFilesParams}
            verdicts={events.verdicts}
            partial={running}
            partialResults={partialResults}
            onOpenStreams={() => caseId && navigate(`/case/${encodeURIComponent(caseId)}/streams`)}
            onShowInStream={(file) => {
              setStreamsOrigin({ kind: 'file', id: file.id, label: file.displayName })
              if (!caseId) return
              navigate(
                `/case/${encodeURIComponent(caseId)}/streams?stream=${file.streamId}&dir=${file.dir}&offset=${file.startOff}`,
              )
            }}
          />
        ) : view === 'streams' ? (
          <StreamsView
            caseId={caseId as string}
            api={client}
            params={route.kind === 'case' ? route.params : {}}
            onParamsChange={onStreamsParams}
            origin={streamsOrigin}
            onFollowOrigin={() => {
              if (!caseId || !streamsOrigin) return
              if (streamsOrigin.kind === 'file') {
                navigate(`/case/${encodeURIComponent(caseId)}/files?file=${streamsOrigin.id}`)
              } else {
                navigate(`/case/${encodeURIComponent(caseId)}/storyboard?event=${streamsOrigin.id}`)
              }
            }}
            onDismissOrigin={() => setStreamsOrigin(null)}
            onOpenFile={(fileId) =>
              caseId && navigate(`/case/${encodeURIComponent(caseId)}/files?file=${fileId}`)
            }
            partial={running}
            partialResults={partialResults}
            basis={preferences.timeBasis}
          />
        ) : (
          <StoryboardView
            caseId={caseId as string}
            api={client}
            totalEvents={caseSummary?.events ?? events.ready?.events ?? null}
            params={route.kind === 'case' ? route.params : {}}
            onParamsChange={onStoryboardParams}
            onOpenStreams={() => caseId && navigate(`/case/${encodeURIComponent(caseId)}/streams`)}
            headingRef={storyboardHeading}
            partial={running}
            partialResults={partialResults}
          />
        )}
      </main>

      <StatusBar
        timeBasis={preferences.timeBasis}
        onToggleTimeBasis={() =>
          setPreference('timeBasis', preferences.timeBasis === 'utc' ? 'local' : 'utc')
        }
        dataAsOf={
          stale && events.lastUpdateAt !== null
            ? `Data as of ${formatClock(events.lastUpdateAt, {
                basis: preferences.timeBasis,
                seconds: true,
              })} ${formatZoneLabel(preferences.timeBasis)}`
            : undefined
        }
        onHelp={() => setOverlay('help')}
      />

      {overlay === 'help' ? (
        <HelpDrawer onClose={() => setOverlay(null)} toolVersion={caseSummary?.toolVersion} />
      ) : null}
      {overlay === 'shortcuts' ? <ShortcutOverlay onClose={() => setOverlay(null)} /> : null}
      {overlay === 'settings' ? <SettingsPopover onClose={() => setOverlay(null)} /> : null}
      {overlay === 'export' ? (
        <ExportDialog
          onClose={() => setOverlay(null)}
          onDownload={handleExportDownload}
          onCopyDiagnostics={copyDiagnostics}
          partial={partialResults}
          notChecked={exportFacts.notChecked}
          hasCredentials={exportFacts.hasCredentials}
        />
      ) : null}
      {overlay === 'replace' ? (
        <ReplaceCaseDialog
          onCancel={() => setOverlay(null)}
          onConfirm={() => {
            setOverlay(null)
            navigate('/')
          }}
        />
      ) : null}
    </div>
  )
}

/** The "Nothing here" page (S7, UI_Design.md §8.11). */
function FullPageUnknown({ onGoHome }: { onGoHome: () => void }): JSX.Element {
  return (
    <div className="full-page">
      <h1 className="full-page__title">Nothing here</h1>
      <p className="full-page__body">That page doesn&apos;t exist.</p>
      <Button variant="primary" onClick={onGoHome}>
        Go to dashboard
      </Button>
    </div>
  )
}

/**
 * The session and connection error page (S6, UI_Design.md §8.6). The page
 * never shows the token, and the diagnostic text of it never holds it either.
 */
function FullPageSession({
  error,
  onRetry,
  onCopyDiagnostics,
}: {
  error: { status: number; code: string; message: string }
  onRetry: () => void
  onCopyDiagnostics: () => void
}): JSX.Element {
  const unauthorized = error.code === 'unauthorized' && error.status === 401
  // A token that was sent and refused has expired; a page that never carried
  // one was opened without its private link.
  const hadToken = getSessionToken() !== null
  const missing = unauthorized && !hadToken
  const expired = unauthorized && hadToken
  const title = missing
    ? 'This dashboard needs its private link'
    : expired
      ? 'This dashboard session has ended'
      : "Can't reach RACCOON on this computer"
  const body = missing
    ? 'RACCOON opens with a private link that only works on this computer. This page was opened without it.'
    : expired
      ? 'The private link for this session is no longer valid. This can happen after RACCOON restarts.'
      : 'The local RACCOON server isn\'t answering. It may have stopped, or it may still be starting.'
  return (
    <div className="full-page">
      <h1 className="full-page__title">{title}</h1>
      <p className="full-page__body">{body}</p>
      {missing || expired ? (
        <p className="full-page__body">Open RACCOON again from your terminal and use the link it prints.</p>
      ) : (
        <Button variant="primary" onClick={onRetry}>
          Try again
        </Button>
      )}
      {expired ? (
        <Button variant="secondary" onClick={onCopyDiagnostics}>
          Copy diagnostic info
        </Button>
      ) : null}
      {!missing && !expired ? (
        <Button variant="secondary" onClick={onCopyDiagnostics}>
          Copy diagnostic info
        </Button>
      ) : null}
    </div>
  )
}
