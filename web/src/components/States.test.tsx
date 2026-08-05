import '@testing-library/jest-dom/vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { EmptyState, ErrorState, LoadingState, PartialState } from './States'

describe('designed list states', () => {
  afterEach(cleanup)
  it('renders loading', () => { render(<LoadingState />); expect(screen.getByRole('status')).toHaveTextContent('Loading') })
  it('renders empty', () => { render(<EmptyState />); expect(screen.getByText('Nothing here yet')).toBeInTheDocument() })
  it('renders error', () => { render(<ErrorState message="offline" />); expect(screen.getByRole('alert')).toHaveTextContent('offline') })
  it('renders partial success', () => { render(<PartialState errors={2} />); expect(screen.getByRole('status')).toHaveTextContent('unknown facts are never treated as safe') })
})
