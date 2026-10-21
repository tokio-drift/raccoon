import type { ButtonHTMLAttributes, JSX, ReactNode } from 'react'

import { Icon, type IconName } from '../../assets/icons'

export type ButtonVariant = 'primary' | 'secondary' | 'tertiary' | 'destructive'

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: 'default' | 'large'
  /** A leading icon. */
  icon?: IconName
  /** Shows a spinner and keeps the label, for in-progress actions. */
  busy?: boolean
  children?: ReactNode
}

/** A button (UI_Design.md §11). One primary button per screen state. */
export function Button({
  variant = 'secondary',
  size = 'default',
  icon,
  busy = false,
  className,
  children,
  disabled,
  type = 'button',
  ...rest
}: ButtonProps): JSX.Element {
  const classes = ['button', `button--${variant}`]
  if (size === 'large') classes.push('button--large')
  if (className) classes.push(className)
  return (
    <button
      {...rest}
      type={type}
      className={classes.join(' ')}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
    >
      {busy ? <span className="spinner" aria-hidden="true" /> : icon ? <Icon name={icon} size={20} /> : null}
      {children}
    </button>
  )
}

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'title'> {
  icon: IconName
  /** The accessible name; it is also the tooltip. */
  label: string
  size?: number
  /** Renders the button in its pressed state. */
  pressed?: boolean
}

/** An icon-only button. It always carries an accessible name and a tooltip. */
export function IconButton({
  icon,
  label,
  size = 20,
  pressed,
  className,
  type = 'button',
  ...rest
}: IconButtonProps): JSX.Element {
  const classes = ['icon-button']
  if (className) classes.push(className)
  return (
    <button
      {...rest}
      type={type}
      className={classes.join(' ')}
      title={label}
      aria-label={label}
      aria-pressed={pressed}
    >
      <Icon name={icon} size={size} />
    </button>
  )
}
