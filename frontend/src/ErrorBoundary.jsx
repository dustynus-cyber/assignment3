import { Component } from 'react'

class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError() {
    return { hasError: true }
  }

  render() {
    if (this.state.hasError) {
      return (
        <main>
          <section className="view block" role="alert">
            <h1>Something went wrong</h1>
            <p>
              The page could not display correctly.
              Reload it to try again.
            </p>
            <button
              type="button"
              onClick={() => window.location.reload()}
            >
              Reload page
            </button>
          </section>
        </main>
      )
    }

    return this.props.children
  }
}

export default ErrorBoundary