import {
  useEffect,
  useId,
  useRef,
  useState,
  type InputHTMLAttributes,
  type JSX,
  type RefObject,
} from 'react'

import { Icon } from '../../assets/icons'

export interface TextInputProps extends Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> {
  label: string
  /** The helper text under the field. */
  helper?: string
  /** The error message; the field turns critical and shows an octagon icon. */
  error?: string
}

/**
 * A text field (UI_Design.md §11). The error state is never colour alone: the
 * field gets a critical outline, an octagon icon and a message below.
 */
export function TextInput({
  label,
  helper,
  error,
  className,
  id,
  ...rest
}: TextInputProps): JSX.Element {
  const generatedId = useId()
  const fieldId = id ?? generatedId
  const messageId = `${fieldId}-message`

  return (
    <div className={className ? `field ${className}` : 'field'}>
      <label className="field__label" htmlFor={fieldId}>
        {label}
      </label>
      <input
        {...rest}
        id={fieldId}
        className={error ? 'text-input text-input--error' : 'text-input'}
        aria-invalid={error ? true : undefined}
        aria-describedby={error || helper ? messageId : undefined}
      />
      {error ? (
        <p className="field__error" id={messageId}>
          <Icon name="critical" size={16} />
          <span>{error}</span>
        </p>
      ) : helper ? (
        <p className="field__helper" id={messageId}>
          {helper}
        </p>
      ) : null}
    </div>
  )
}

export interface SearchFieldProps {
  /** The label of the field, used as the accessible name. */
  label: string
  value: string
  /** Called with the new text after the debounce. */
  onChange: (value: string) => void
  placeholder?: string
  /** The debounce in milliseconds. */
  delay?: number
  /** The reference of the input, so a shortcut can focus it. */
  inputRef?: RefObject<HTMLInputElement>
}

/**
 * A search field (UI_Design.md §11). The magnifier sits left, the clear button
 * right (only when there is text) and the "/" hint appears while the field is
 * empty and unfocused.
 */
export function SearchField({
  label,
  value,
  onChange,
  placeholder,
  delay = 250,
  inputRef,
}: SearchFieldProps): JSX.Element {
  const id = useId()
  const [text, setText] = useState(value)
  const [focused, setFocused] = useState(false)
  const timer = useRef<number | null>(null)

  useEffect(() => {
    setText(value)
  }, [value])

  useEffect(() => {
    return () => {
      if (timer.current !== null) window.clearTimeout(timer.current)
    }
  }, [])

  const push = (next: string) => {
    setText(next)
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => onChange(next), delay)
  }

  const showHint = text.length === 0 && !focused

  return (
    <div className="search-field">
      <span className="search-field__icon" aria-hidden="true">
        <Icon name="search" size={16} />
      </span>
      <input
        id={id}
        className="search-field__input"
        type="search"
        ref={inputRef}
        value={text}
        placeholder={placeholder}
        aria-label={label}
        onChange={(event) => push(event.target.value)}
        onFocus={() => setFocused(true)}
        onBlur={() => setFocused(false)}
      />
      {text.length > 0 ? (
        <button
          type="button"
          className="search-field__clear"
          aria-label="Clear search"
          onClick={() => {
            setText('')
            if (timer.current !== null) window.clearTimeout(timer.current)
            onChange('')
          }}
        >
          <Icon name="close" size={16} />
        </button>
      ) : showHint ? (
        <span className="search-field__hint" aria-hidden="true">
          /
        </span>
      ) : null}
    </div>
  )
}
