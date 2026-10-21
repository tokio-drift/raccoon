import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { CopyButton } from './CopyButton'
import { DownloadButton } from './DownloadButton'
import { FilterChip } from './FilterChip'
import { SearchField, TextInput } from './Field'
import { MultiSelect, Select } from './Select'
import { ToastProvider, ToastStack, useToast } from './Toast'
import { Tabs } from './Tabs'
import { Tooltip } from './Tooltip'
import { LoadMorePill, PagingBar } from './Pagination'
import { ProgressBar } from './ProgressBar'
import { Skeleton } from './Skeleton'
import { EmptyState, ErrorState } from './States'

afterEach(() => {
  vi.useRealTimers()
})

describe('TextInput', () => {
  it('labels the field and links the helper text', () => {
    render(<TextInput label="Capture name" helper="Only letters and digits." />)
    const input = screen.getByLabelText('Capture name')
    expect(input).toHaveAccessibleDescription('Only letters and digits.')
  })

  it('shows the error with an icon and marks the field as invalid', () => {
    render(<TextInput label="Capture name" error="That name is too long." />)
    const input = screen.getByLabelText('Capture name')
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByText('That name is too long.')).toBeInTheDocument()
  })
})

describe('SearchField', () => {
  it('debounces the search and then reports the text', () => {
    vi.useFakeTimers()
    const onChange = vi.fn()
    render(<SearchField label="Search events" value="" onChange={onChange} />)

    fireEvent.change(screen.getByRole('searchbox', { name: 'Search events' }), {
      target: { value: 'login' },
    })
    expect(onChange).not.toHaveBeenCalled()

    act(() => {
      vi.advanceTimersByTime(250)
    })
    expect(onChange).toHaveBeenCalledWith('login')
  })

  it('offers a clear button only when there is text', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<SearchField label="Search events" value="log" onChange={onChange} />)

    await user.click(screen.getByRole('button', { name: 'Clear search' }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(''))
  })
})

describe('Select', () => {
  const options = [
    { value: 'all', label: 'All' },
    { value: 'info', label: 'Info' },
    { value: 'warning', label: 'Warning' },
  ]

  it('opens the menu and picks an option', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    render(<Select label="Severity" options={options} value="all" onChange={onChange} />)

    const trigger = screen.getByRole('button', { name: /Severity/ })
    expect(trigger).toHaveAttribute('aria-expanded', 'false')

    await user.click(trigger)
    const listbox = screen.getByRole('listbox')
    expect(listbox).toBeInTheDocument()

    await user.click(within(listbox).getByRole('option', { name: 'Warning' }))
    expect(onChange).toHaveBeenCalledWith('warning')
  })

  it('closes the menu on Escape', async () => {
    const user = userEvent.setup()
    render(<Select label="Severity" options={options} value="all" onChange={() => undefined} />)

    await user.click(screen.getByRole('button', { name: /Severity/ }))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('listbox')).not.toBeInTheDocument()
  })
})

describe('MultiSelect', () => {
  it('counts the chosen options and toggles them', async () => {
    const onChange = vi.fn()
    const user = userEvent.setup()
    const options = [
      { value: 'info', label: 'Info' },
      { value: 'critical', label: 'Critical' },
    ]
    render(
      <MultiSelect label="Severity" options={options} values={['info']} onChange={onChange} />,
    )

    expect(screen.getByRole('button', { name: /Severity/ })).toHaveTextContent('Severity · 1')
    await user.click(screen.getByRole('button', { name: /Severity/ }))
    await user.click(screen.getByRole('checkbox', { name: 'Critical' }))
    expect(onChange).toHaveBeenCalledWith(['info', 'critical'])
  })
})

describe('FilterChip', () => {
  it('removes the filter with its own button', async () => {
    const onRemove = vi.fn()
    const user = userEvent.setup()
    render(<FilterChip label="Severity: Warning" onRemove={onRemove} />)

    expect(screen.getByText('Severity: Warning')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Remove filter Severity: Warning' }))
    expect(onRemove).toHaveBeenCalled()
  })
})

describe('Tooltip', () => {
  it('opens on focus and closes on Escape', async () => {
    const user = userEvent.setup()
    render(
      <Tooltip text="A fingerprint of the file.">
        <button type="button">Hash</button>
      </Tooltip>,
    )

    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
    await user.tab()
    expect(await screen.findByRole('tooltip')).toHaveTextContent('A fingerprint of the file.')
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('tooltip')).not.toBeInTheDocument()
  })
})

describe('CopyButton', () => {
  it('copies the exact value and confirms it', async () => {
    const writeText = vi.fn(async () => undefined)
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true })
    render(<CopyButton value="../../etc/passwd" label="Copy file name" />)

    fireEvent.click(screen.getByRole('button', { name: 'Copy file name' }))
    expect(writeText).toHaveBeenCalledWith('../../etc/passwd')
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })
})

describe('DownloadButton', () => {
  it('never suggests opening the file', () => {
    render(<DownloadButton fileName="invoice.zip" onDownload={() => undefined} />)
    const button = screen.getByRole('button', { name: 'Download file' })
    expect(button).toHaveAttribute('title', expect.stringContaining('never open or run it'))
  })

  it('is disabled with a reason', () => {
    render(
      <DownloadButton
        fileName="invoice.zip"
        onDownload={() => undefined}
        disabled
        disabledReason="This file is no longer available."
      />,
    )
    expect(screen.getByRole('button', { name: 'Download file' })).toBeDisabled()
  })
})

describe('ProgressBar', () => {
  it('carries the value as text, never as colour alone', () => {
    render(<ProgressBar percent={62} valueText="62%" />)
    const bar = screen.getByRole('progressbar')
    expect(bar).toHaveAttribute('aria-valuenow', '62')
    expect(bar).toHaveAttribute('aria-valuetext', '62%')
  })

  it('is indeterminate without a percent', () => {
    render(<ProgressBar />)
    expect(screen.getByRole('progressbar')).not.toHaveAttribute('aria-valuenow')
  })
})

describe('Skeleton', () => {
  it('is hidden from the screen reader', () => {
    const { container } = render(<Skeleton kind="row" count={3} />)
    expect(container.querySelectorAll('.skeleton')).toHaveLength(3)
    expect(container.firstElementChild).toHaveAttribute('aria-hidden', 'true')
  })
})

describe('EmptyState', () => {
  it('shows the filters of a filtered-empty state', () => {
    render(
      <EmptyState kind="filtered" title="No events match these filters">
        <FilterChip label="Severity: Warning" />
      </EmptyState>,
    )
    expect(screen.getByRole('heading', { name: 'No events match these filters' })).toBeInTheDocument()
    expect(screen.getByText('Severity: Warning')).toBeInTheDocument()
  })
})

describe('ErrorState', () => {
  it('has a title, an explanation, actions and collapsible details', async () => {
    const user = userEvent.setup()
    render(
      <ErrorState
        title="This file is too large"
        explanation="The file is 600 MB. The limit is 500 MB."
        code="UI-UPLOAD-SIZE"
        detail="request body too large"
        actions={[{ label: 'Choose another file', onClick: () => undefined }]}
      />,
    )

    expect(screen.getByRole('heading', { name: 'This file is too large' })).toBeInTheDocument()
    expect(screen.getByText('The file is 600 MB. The limit is 500 MB.')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Choose another file' })).toBeInTheDocument()
    expect(screen.queryByText('UI-UPLOAD-SIZE')).not.toBeInTheDocument()

    await user.click(screen.getByRole('button', { name: 'Show technical details' }))
    expect(screen.getByText('UI-UPLOAD-SIZE')).toBeInTheDocument()
    expect(screen.getByText('request body too large')).toBeInTheDocument()
  })
})

describe('Pagination', () => {
  it('hides the pill when nothing arrived', () => {
    const { container } = render(<LoadMorePill count={0} onShow={() => undefined} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('offers the new events without re-sorting on its own', async () => {
    const onShow = vi.fn()
    const user = userEvent.setup()
    render(<LoadMorePill count={3} onShow={onShow} />)

    expect(screen.getByText('3 new events')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Show' }))
    expect(onShow).toHaveBeenCalled()
  })

  it('never pages past the end of the stream', () => {
    render(
      <PagingBar offset={0} length={4096} total={18230} onPrevious={() => undefined} onNext={() => undefined} />,
    )
    expect(screen.getByRole('button', { name: 'Previous 4 KB' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Next 4 KB' })).not.toBeDisabled()
  })
})

describe('Tabs', () => {
  const items = [
    { id: 'storyboard' as const, label: 'Storyboard' },
    { id: 'files' as const, label: 'Files', count: 5 },
  ]

  it('marks the selected tab and gives the count a name', () => {
    render(<Tabs items={items} active="files" onSelect={() => undefined} label="Case views" />)
    const list = screen.getByRole('tablist', { name: 'Case views' })
    expect(within(list).getByRole('tab', { name: /Files/ })).toHaveAttribute(
      'aria-selected',
      'true',
    )
    expect(within(list).getByLabelText('5 files')).toBeInTheDocument()
  })

  it('moves between the tabs with the arrow keys', async () => {
    const onSelect = vi.fn()
    const user = userEvent.setup()
    render(<Tabs items={items} active="storyboard" onSelect={onSelect} label="Case views" />)

    await user.tab()
    await user.keyboard('{ArrowRight}')
    expect(onSelect).toHaveBeenCalledWith('files')
    await user.keyboard('{End}')
    expect(onSelect).toHaveBeenCalledWith('files')
  })
})

describe('Toast', () => {
  function Trigger() {
    const toast = useToast()
    return (
      <button type="button" onClick={() => toast.push({ tone: 'info', message: 'Copied' })}>
        push
      </button>
    )
  }

  it('shows a toast and announces it politely', async () => {
    const user = userEvent.setup()
    render(
      <ToastProvider>
        <Trigger />
      </ToastProvider>,
    )

    await user.click(screen.getByRole('button', { name: 'push' }))
    expect(await screen.findByText('Copied')).toBeInTheDocument()
    expect(screen.getByRole('status')).toHaveAttribute('aria-live', 'polite')
  })

  it('dismisses a toast with its button', async () => {
    const user = userEvent.setup()
    const onDismiss = vi.fn()
    render(
      <ToastStack
        toasts={[{ id: 1, tone: 'error', message: "The upload didn't finish." }]}
        onDismiss={onDismiss}
      />,
    )

    await user.click(screen.getByRole('button', { name: 'Dismiss' }))
    expect(onDismiss).toHaveBeenCalledWith(1)
  })
})
