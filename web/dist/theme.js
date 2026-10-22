// Applies the stored theme before the first paint so the page never flashes
// the wrong theme (UI_Design.md §10.2). The manual choice wins; "system"
// follows the OS. This file is served on its own because the strict
// Content-Security-Policy allows no inline script.
;(function () {
  var theme = 'light'
  try {
    var stored = window.localStorage.getItem('raccoon.theme')
    if (stored === 'light' || stored === 'dark') {
      theme = stored
    } else if (
      stored !== 'system' &&
      window.matchMedia &&
      window.matchMedia('(prefers-color-scheme: dark)').matches
    ) {
      theme = 'dark'
    }
  } catch (err) {
    theme = 'light'
  }
  document.documentElement.setAttribute('data-theme', theme)
})()
