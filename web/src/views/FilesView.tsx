import { useCallback, useEffect, useMemo, useRef, useState, type JSX, type RefObject } from 'react'

import type { RaccoonApi } from '../api/api'
import { ApiError } from '../api/client'
import type { CarvedFile, VerdictEvent } from '../api/types'
import { ArtifactRow, ArtifactTable, type ArtifactColumn, type SortDirection } from '../components/content/ArtifactTable'
import { Icon } from '../assets/icons'
import { Button } from '../components/primitives/Button'
import { Drawer } from '../components/primitives/Overlay'
import { Skeleton } from '../components/primitives/Skeleton'
import { EmptyState, ErrorState } from '../components/primitives/States'
import { useToast } from '../components/primitives/Toast'
import { useFiles } from '../hooks/useFiles'
import { useIsWide } from '../hooks/useMediaQuery'
import {
  controlCharacterTokens,
  displayName,
  directionLabel,
  EXTRACTION_LABEL,
  fileEndpoints,
  fileVerdict,
  formatIconName,
  formatLabel,
  hasNonAscii,
  isPathLikeName,
  nameMismatch,
  neutralDownloadName,
  filtersFromParams,
  filtersToParams,
  sortFromParams,  sortToParams,
  tableName,
  type FileFilters,
  type FileSortKey,
} from '../lib/files'
import { formatHashShort } from '../lib/format'
import { buildDiagnostics, copyText } from '../lib/diagnostics'
import { useRoute, type URLParams } from '../lib/router'
import { FilesDetailPane } from './FilesDetailPane'
import { FilesDownloadDialog } from './FilesDownloadDialog'
import { FilesFilterBar } from './FilesFilterBar'

/**
 * The artifact gallery (UI_Design.md §4.4, §6). It lists the files RACCOON
 * carved out of the traffic; nothing is ever opened or previewed.
 */

export interface FilesViewProps {
  caseId: string
  api: RaccoonApi
  params: URLParams
  onParamsChange: (params: URLParams) => void
  /** The live verdicts of the case, by file id. */
  verdicts: Record<number, VerdictEvent>
  /** The analysis is still running; the checks are still arriving. */
  partial?: boolean
  onOpenStreams: () => void
  headingRef?: RefObject<HTMLHeadingElement>
}

interface DownloadState {
  busy: boolean
  error: string | null
  missing: boolean
}

const NO_DOWNLOAD: DownloadState = { busy: false, error: null, missing: false }

export function FilesView({
  caseId,
  api,
  params,
  onParamsChange,
  verdicts,
  partial = false,
  onOpenStreams,
  headingRef,
}: FilesViewProps): JSX.Element {
  const { navigate } = useRoute()
  const toast = useToast()
  const wide = useIsWide()
  const searchRef = useRef<HTMLInputElement | null>(null)

  const initialFilters = useMemo(() => filtersFromParams(params), [params])
  const [filters, setFilters] = useState<FileFilters>(initialFilters)
  const initialSort = useMemo(() => sortFromParams(params.sort), [params.sort])
  const [sort, setSort] = useState<{ key: FileSortKey; descending: boolean }>(initialSort)

  // The deep link of the file: `?file={id}` (§3.2).
  const deepLinkId = useMemo(() => {
    const value = params.file
    if (!value) return null
    const parsed = Number(value)
    return Number.isInteger(parsed) && parsed > 0 ? parsed : null
  }, [params.file])

  // The filters and the sort live in the URL (§3.2). The same set is never
  // written twice, so the view cannot loop over the address bar.
  const filterParams = useMemo(() => filtersToParams(filters), [filters])
  const pushed = useRef('')
  useEffect(() => {
    const next = { ...filterParams }
    if (sort.key !== 'verdict' || sort.descending) next.sort = sortToParams(sort.key, sort.descending)
    const key = JSON.stringify(next)
    if (pushed.current === key) return
    pushed.current = key
    onParamsChange(next)
  }, [filterParams, sort, onParamsChange])

  const onSortChange = useCallback(
    (key: FileSortKey, descending: boolean) => setSort({ key, descending }),
    [],
  )

  const files = useFiles({
    caseId,
    api,
    filters,
    sortKey: sort.key,
    sortDescending: sort.descending,
    verdicts,
    initialFileId: deepLinkId,
    onSortChange,
  })

  // The event every file was carved in, for the "Source event" button.
  const [sourceEvents, setSourceEvents] = useState<Record<number, number>>({})
  useEffect(() => {
    let cancelled = false
    api
      .listEvents(caseId, { type: ['FILE_CARVED'], limit: 1000, flat: true })
      .then((page) => {
        if (cancelled) return
        const map: Record<number, number> = {}
        for (const event of Array.isArray(page?.items) ? page.items : []) {
          if (event.fileId > 0 && map[event.fileId] === undefined) map[event.fileId] = event.id
        }
        setSourceEvents(map)
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [api, caseId])

  const selected = useMemo(
    () => files.rows.find((file) => file.id === files.selectedId) ?? null,
    [files.rows, files.selectedId],
  )

  const [downloads, setDownloads] = useState<Record<number, DownloadState>>({})
  const [dialogFile, setDialogFile] = useState<CarvedFile | null>(null)

  const save = useCallback(
    async (file: CarvedFile) => {
      setDownloads((current) => ({ ...current, [file.id]: { busy: true, error: null, missing: false } }))
      const savedAs = neutralDownloadName(file.sha256)
      try {
        const { blob } = await api.downloadFile(caseId, file.id)
        const url = URL.createObjectURL(blob)
        const anchor = document.createElement('a')
        anchor.href = url
        anchor.download = savedAs
        anchor.rel = 'noopener'
        document.body.appendChild(anchor)
        anchor.click()
        anchor.remove()
        URL.revokeObjectURL(url)
        setDownloads((current) => ({ ...current, [file.id]: NO_DOWNLOAD }))
        toast.push({ tone: 'success', message: `Downloaded ${savedAs}` })
      } catch (cause: unknown) {
        const missing = cause instanceof ApiError && cause.status === 404
        setDownloads((current) => ({
          ...current,
          [file.id]: {
            busy: false,
            error: missing ? null : "Couldn't download this file.",
            missing,
          },
        }))
        if (missing) return
        toast.push({
          tone: 'error',
          message: "Couldn't download this file.",
          action: {
            label: 'Try again',
            onClick: () => void save(file),
          },
        })
      }
    },
    [api, caseId, toast],
  )

  const onDownload = useCallback(
    (file: CarvedFile) => {
      const status = fileVerdict(file)
      if (status === 'malicious' || status === 'suspicious') {
        setDialogFile(file)
        return
      }
      void save(file)
    },
    [save],
  )

  // "/" focuses the search field (§6.9).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const target = event.target instanceof HTMLElement ? event.target : null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      if (event.key === '/') {
        event.preventDefault()
        searchRef.current?.focus()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [])

  // Escape closes the detail pane (§6.7).
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      if (dialogFile) return
      if (files.selectedId === null) return
      const target = event.target instanceof HTMLElement ? event.target : null
      const typing =
        target?.tagName === 'INPUT' || target?.tagName === 'TEXTAREA' || target?.isContentEditable
      if (typing) return
      event.preventDefault()
      files.select(null)
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [files, dialogFile])

  const onShowInStream = useCallback(
    (file: CarvedFile) => {
      navigate(
        `/case/${encodeURIComponent(caseId)}/streams?stream=${file.streamId}&dir=${file.dir}&offset=${file.startOff}`,
      )
    },
    [caseId, navigate],
  )

  const onShowSourceEvent = useCallback(
    (file: CarvedFile) => {
      const eventId = sourceEvents[file.id]
      if (eventId === undefined) return
      navigate(`/case/${encodeURIComponent(caseId)}/storyboard?event=${eventId}`)
    },
    [caseId, navigate, sourceEvents],
  )

  const clearAll = useCallback(
    () => setFilters({ ...filters, verdicts: [], formats: [], dir: null, extractions: [], query: '', showLowConfidence: false }),
    [filters],
  )

  // The diagnostic text of a failed download never holds the session token.
  const copyDiagnostics = useCallback(() => {
    const text = buildDiagnostics({ caseId })
    void copyText(text).then((copied) => {
      toast.push(
        copied
          ? { tone: 'success', message: 'Diagnostic info copied.' }
          : { tone: 'error', message: "Couldn't copy the diagnostic info." },
      )
    })
  }, [caseId, toast])

  const columns = useMemo<ArtifactColumn[]>(() => {
    const sortOf = (key: FileSortKey): SortDirection => {
      if (sort.key !== key) return 'none'
      return sort.descending ? 'descending' : 'ascending'
    }
    const sortable = (key: FileSortKey) => ({
      sortable: true,
      sort: sortOf(key),
      onSort: () => files.setSort(key),
    })
    return [
      { key: 'name', label: 'Name', ...sortable('name') },
      { key: 'format', label: 'Format', ...sortable('format') },
      { key: 'endpoints', label: 'From → to', optional: true },
      { key: 'size', label: 'Size', align: 'right', ...sortable('size') },
      { key: 'verdict', label: 'Verdict', ...sortable('verdict') },
      { key: 'extraction', label: 'Extraction', ...sortable('extraction') },
      { key: 'confidence', label: 'Confidence', optional: true, ...sortable('confidence') },
      { key: 'sha256', label: 'SHA-256', optional: true },
      { key: 'download', label: 'Download', align: 'center' },
    ]
  }, [files, sort])

  const nameTags = (file: CarvedFile) => {
    const name = displayName(file)
    const tags: { label: string; tooltip?: string; warning?: boolean }[] = []
    if (isPathLikeName(name)) {
      tags.push({
        label: 'Path-like name',
        warning: true,
        tooltip:
          'The sender supplied a name containing path characters. RACCOON displays it as text and never uses it as a file path.',
      })
    }
    if (controlCharacterTokens(name).length > 0) {
      tags.push({
        label: 'Unusual characters',
        warning: true,
        tooltip: 'The name holds control or bidirectional characters. They are shown as visible tokens.',
      })
    }
    if (hasNonAscii(name)) {
      tags.push({ label: 'Unicode', tooltip: 'The name holds characters outside the ASCII range.' })
    }
    if (nameMismatch(name, file.ext)) {
      tags.push({
        label: "Name doesn't match content",
        warning: true,
        tooltip: `The name says .${name.split('.').pop()} but the content looks like a ${file.format} file.`,
      })
    }
    return tags
  }

  const pane = selected ? (
    <FilesDetailPane
      file={selected}
      stream={files.streams.get(selected.streamId) ?? null}
      hasSourceEvent={sourceEvents[selected.id] !== undefined}
      onClose={() => files.select(null)}
      onShowInStream={() => onShowInStream(selected)}
      onShowSourceEvent={() => onShowSourceEvent(selected)}
      busy={downloads[selected.id]?.busy ?? false}
      error={downloads[selected.id]?.error ?? null}
      missing={downloads[selected.id]?.missing ?? false}
      onDownload={() => onDownload(selected)}
      onCopyDiagnostics={copyDiagnostics}
    />
  ) : null

  if (files.error) {
    return (
      <section className="files" aria-label="Extracted files">
        <ErrorState
          title="Couldn't load files"
          explanation="RACCOON could not read the list of extracted files from the local server."
          code={files.error.code}
          detail={files.error.message}
          diagnostic={buildDiagnostics({
            caseId,
            errorCode: files.error.code,
            errorMessage: files.error.message,
          })}
          actions={[
            { label: 'Try again', onClick: files.reload, variant: 'primary' },
            { label: 'Copy diagnostic info', onClick: copyDiagnostics, variant: 'secondary' },
          ]}
        />
      </section>
    )
  }

  return (
    <section className="files" aria-label="Extracted files">
      <div className="files__heading">
        <h1 className="files__title" tabIndex={-1} ref={headingRef}>
          Extracted files
        </h1>
        <p className="files__subtitle">
          Files RACCOON found in the traffic. Nothing here is opened or previewed.
        </p>
      </div>

      <FilesFilterBar
        filters={filters}
        onChange={setFilters}
        total={files.files.length}
        matching={files.filtered.length}
        formats={files.formats}
        onClearAll={clearAll}
        searchRef={searchRef}
      />

      {partial ? (
        <p className="files__pending">
          Threat checks are still arriving. Files marked Not checked will update here as checks finish.
        </p>
      ) : null}

      {files.hiddenCount > 0 && !filters.showLowConfidence ? (
        <div className="files__hidden-notice">
          <span>
            {`${files.hiddenCount} low-confidence file${files.hiddenCount === 1 ? '' : 's'} ${
              files.hiddenCount === 1 ? 'is' : 'are'
            } hidden. They matched only a short signature and may not be real files.`}
          </span>
          <Button
            variant="tertiary"
            onClick={() => setFilters({ ...filters, showLowConfidence: true })}
          >
            Show them
          </Button>
        </div>
      ) : null}

      {files.orderChanged ? (
        <div className="files__resort">
          <span>Order changed</span>
          <Button variant="tertiary" onClick={files.reSort}>
            Re-sort
          </Button>
        </div>
      ) : null}

      <div className="files__body">
        <div className="files__table-area">
          {files.loading ? (
            <div className="files__skeletons">
              {Array.from({ length: 5 }).map((_, index) => (
                <Skeleton key={index} />
              ))}
            </div>
          ) : files.rows.length === 0 ? (
            files.filtered.length === 0 && files.files.length > 0 ? (
              <EmptyState
                kind="filtered"
                title="No files match these filters"
                actions={[
                  { label: 'Clear all filters', onClick: clearAll, variant: 'primary' },
                  ...(files.hiddenCount > 0 && !filters.showLowConfidence
                    ? [
                        {
                          label: 'Show low-confidence files',
                          onClick: () => setFilters({ ...filters, showLowConfidence: true }),
                          variant: 'secondary' as const,
                        },
                      ]
                    : []),
                ]}
              >
                {filters.verdicts.map((verdict) => (
                  <span key={verdict} className="tag tag--plain">
                    {verdict}
                  </span>
                ))}
                {filters.formats.map((format) => (
                  <span key={format} className="tag tag--plain">
                    {format}
                  </span>
                ))}
              </EmptyState>
            ) : (
              <EmptyState
                title="No files were extracted"
                body="RACCOON found no files in the traffic it could identify. The raw conversations are still available."
                actions={[{ label: 'Open Streams', onClick: onOpenStreams, variant: 'primary' }]}
              />
            )
          ) : (
            <ArtifactTable
              columns={columns}
              caption={`${files.rows.length} extracted files`}
            >
              {files.rows.map((file, index) => {
                const endpoints = fileEndpoints(file, files.streams.get(file.streamId))
                const download = downloads[file.id] ?? NO_DOWNLOAD
                return (
                  <ArtifactRow
                    key={file.id}
                    fileId={file.id}
                    name={displayName(file)}
                    shortName={tableName(file)}
                    nameSubline={file.ext ? `.${file.ext}` : ''}
                    nameTags={nameTags(file)}
                    icon={formatIconName(file.format)}
                    format={formatLabel(file.format, file.ext)}
                    endpoints={endpoints ?? undefined}
                    direction={{
                      label: directionLabel(file.dir),
                      icon: file.dir === 'c2s' ? 'direction-right' : 'direction-left',
                    }}
                    size={file.size}
                    verdict={
                      file.verdict
                        ? {
                            status: file.verdict.status,
                            score: file.verdict.score,
                            total: file.verdict.total,
                            source: file.verdict.source,
                            checkedAt: file.verdict.checkedAt,
                          }
                        : { status: 'not_checked' }
                    }
                    extraction={EXTRACTION_LABEL[file.status]}
                    extractionIcon={file.status === 'complete' ? 'file' : 'warning'}
                    extractionWarning={file.status !== 'complete'}
                    confidence={file.confidence}
                    sha256={formatHashShort(file.sha256)}
                    selected={file.id === files.selectedId}
                    lowConfidence={file.confidence === 'low'}
                    updated={files.updatedIds.includes(file.id)}
                    onSelect={() => files.select(file.id)}
                    rowIndex={index + 1}
                    rowCount={files.rows.length}
                    actions={
                      <button
                        type="button"
                        className="icon-button"
                        aria-label={`Download ${displayName(file)}`}
                        title={`Download file ${displayName(file)}. RACCOON will never open or run it.`}
                        disabled={download.busy || download.missing}
                        onClick={(event) => {
                          event.stopPropagation()
                          onDownload(file)
                        }}
                      >
                        <Icon name="download" size={20} />
                      </button>
                    }
                  />
                )
              })}
            </ArtifactTable>
          )}
        </div>

        {pane && wide ? pane : null}
      </div>

      {pane && !wide ? (
        <Drawer title="File details" onClose={() => files.select(null)} className="drawer--files">
          {pane}
        </Drawer>
      ) : null}

      {dialogFile ? (
        <FilesDownloadDialog
          file={dialogFile}
          onCancel={() => setDialogFile(null)}
          onConfirm={() => {
            const file = dialogFile
            setDialogFile(null)
            void save(file)
          }}
        />
      ) : null}
    </section>
  )
}
