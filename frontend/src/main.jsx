import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './App.jsx'
import ErrorBoundary from './ErrorBoundary.jsx'
import NotFound from './NotFound.jsx'
import './index.css'

const isHomePage = window.location.pathname === '/'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      {isHomePage ? <App /> : <NotFound />}
    </ErrorBoundary>
  </StrictMode>
)