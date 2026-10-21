import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'

import { App } from './App'
import { createApi } from './api'
import { ToastProvider } from './components/primitives/Toast'
import { loadPreferences } from './lib/preferences'
import { captureTokenFromLocation } from './lib/token'
import './styles/tokens.css'
import './styles/base.css'
import './styles/shell.css'
import './styles/components.css'
import './styles/views.css'

// Read the stored preferences (theme, density) before the first React render so
// the document never shows the wrong theme.
loadPreferences()

// Take the session token out of the address bar before the first request, so it
// never appears in the URL of a request, in the DOM or in the page title.
captureTokenFromLocation()

const container = document.getElementById('root')
if (!container) {
  throw new Error('RACCOON: the #root container is missing from index.html')
}
const root: HTMLElement = container

// The API client is built before the first render: with VITE_MOCK=1 the mock
// adapter serves the fixtures of web/mock instead of the local server.
async function start(): Promise<void> {
  const api = await createApi()
  createRoot(root).render(
    <StrictMode>
      <ToastProvider>
        <App api={api} />
      </ToastProvider>
    </StrictMode>,
  )
}

void start()
