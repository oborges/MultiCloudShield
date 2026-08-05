import '@testing-library/jest-dom/vitest'
import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

describe('provider text rendering', () => {
  it('renders hostile metadata inertly', () => { const value = "<script>alert('x')</script> =cmd|'/c calc'!A1"; render(<p>{value}</p>); expect(screen.getByText(value)).toBeInTheDocument(); expect(document.querySelector('script')).toBeNull() })
})
