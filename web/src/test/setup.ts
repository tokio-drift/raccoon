import '@testing-library/jest-dom/vitest'

// jsdom has no object URLs; the download flow needs them.
if (typeof URL.createObjectURL !== 'function') {
  URL.createObjectURL = () => 'blob:raccoon-test'
}
if (typeof URL.revokeObjectURL !== 'function') {
  URL.revokeObjectURL = () => undefined
}
