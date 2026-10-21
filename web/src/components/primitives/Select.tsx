import { useEffect, useId, useRef, useState, type JSX } from 'react'

import { Icon, type IconName } from '../../assets/icons'

export interface SelectOption {
  value: string
  label: string
  description?: string
  /** The icon shown in front of the label. */
  icon?: IconName
}

export interface SelectProps {
  label: string
  options: SelectOption[]
  value?: string
  onChange: (value: string) => void
  /** Shows the number of chosen options next to the label. */
  showCount?: boolean
}

/**
 * A single-select control (UI_Design.md §11). The menu is keyboard operable:
 * the arrow keys move, Enter picks, Escape closes.
 */
export function Select({
  label,
  options,
  value,
  onChange,
  showCount = false,
}: SelectProps): JSX.Element {
  const id = useId()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const root = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!open) return
    const onDocumentClick = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false)
    }
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    document.addEventListener('mousedown', onDocumentClick)
    document.addEventListener('keydown', onKeyDown)
    return () => {
      document.removeEventListener('mousedown', onDocumentClick)
      document.removeEventListener('keydown', onKeyDown)
    }
  }, [open])

  const current = options.find((option) => option.value === value)

  return (
    <div className="select" ref={root}>
      <button
        type="button"
        className="select__trigger"
        id={id}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((state) => !state)}
        onKeyDown={(event) => {
          if (event.key === 'ArrowDown') {
            event.preventDefault()
            setOpen(true)
            setActive((index) => Math.min(options.length - 1, index + 1))
          }
        }}
      >
        <span className="select__label">{label}</span>
        {showCount && current ? <span className="select__count">{current.label}</span> : null}
        <Icon name="chevron-down" size={16} />
      </button>
      {open ? (
        <ul className="select__menu" role="listbox" aria-labelledby={id} tabIndex={-1}>
          {options.map((option, index) => (
            <li
              key={option.value}
              role="option"
              aria-selected={option.value === value}
              className={index === active ? 'select__option select__option--active' : 'select__option'}
              onMouseEnter={() => setActive(index)}
              onClick={() => {
                onChange(option.value)
                setOpen(false)
              }}
            >
              {option.label}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  )
}

export interface MultiSelectProps {
  label: string
  options: SelectOption[]
  values: string[]
  onChange: (values: string[]) => void
  /** Adds a search field to the menu. */
  searchable?: boolean
}

/**
 * A multi-select control (UI_Design.md §11). The trigger shows the label and
 * the number of chosen options; the menu uses checkboxes and a type-ahead.
 */
export function MultiSelect({
  label,
  options,
  values,
  onChange,
  searchable = false,
}: MultiSelectProps): JSX.Element {
  const id = useId()
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const [query, setQuery] = useState('')
  const [typed, setTyped] = useState('')
  const root = useRef<HTMLDivElement | null>(null)

  const visible = query
    ? options.filter((option) => option.label.toLowerCase().includes(query.toLowerCase()))
    : options

  useEffect(() => {
    if (!open) return
    const onDocumentClick = (event: MouseEvent) => {
      if (root.current && !root.current.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocumentClick)
    return () => document.removeEventListener('mousedown', onDocumentClick)
  }, [open])

  const toggle = (value: string) => {
    onChange(values.includes(value) ? values.filter((item) => item !== value) : [...values, value])
  }

  const onTriggerKeyDown = (event: React.KeyboardEvent<HTMLButtonElement>) => {
    if (event.key === 'ArrowDown' || event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      setOpen(true)
      return
    }
    if (event.key.length === 1 && /[\w ]/.test(event.key)) {
      setTyped((current) => current + event.key)
      const index = options.findIndex((option) =>
        option.label.toLowerCase().startsWith(typed.toLowerCase() + event.key.toLowerCase()),
      )
      if (index >= 0) setActive(index)
    }
  }

  return (
    <div className="select" ref={root}>
      <button
        type="button"
        className="select__trigger"
        id={id}
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((state) => !state)}
        onKeyDown={onTriggerKeyDown}
      >
        <span className="select__label">{label}</span>
        <span className="select__count">{`${label} · ${values.length}`}</span>
        <Icon name="chevron-down" size={16} />
      </button>
      {open ? (
        <div className="select__menu select__menu--multi" role="listbox" aria-labelledby={id}>
          {searchable ? (
            <div className="select__search">
              <input
                type="search"
                value={query}
                aria-label={`Search ${label}`}
                onChange={(event) => setQuery(event.target.value)}
              />
            </div>
          ) : null}
          {visible.map((option) => {
            const index = options.indexOf(option)
            return (
              <label
                key={option.value}
                className={index === active ? 'select__option select__option--active' : 'select__option'}
                onMouseEnter={() => setActive(index)}
              >
                <input
                  type="checkbox"
                  checked={values.includes(option.value)}
                  onChange={() => toggle(option.value)}
                />
                {option.icon ? <Icon name={option.icon} size={14} /> : null}
                <span>{option.label}</span>
              </label>
            )
          })}
        </div>
      ) : null}
    </div>
  )
}
