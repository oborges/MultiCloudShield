import type { ReactNode } from 'react'

export function LoadingState({ label = 'Loading secure posture data' }: { label?: string }) {
  return <div className="state" role="status"><span className="spinner" aria-hidden="true"/><p>{label}…</p></div>
}

export function EmptyState({ title = 'Nothing here yet', children }: { title?: string; children?: ReactNode }) {
  return <div className="state empty"><div className="state-icon">○</div><h3>{title}</h3><p>{children ?? 'Run a scan or adjust the active filters.'}</p></div>
}

export function ErrorState({ message }: { message: string }) {
  return <div className="state error" role="alert"><div className="state-icon">!</div><h3>We could not load this view</h3><p>{message}</p><button onClick={() => location.reload()}>Try again</button></div>
}

export function PartialState({ errors }: { errors: number }) {
  return <aside className="partial" role="status"><strong>Partial results</strong><span>{errors} collection {errors === 1 ? 'path was' : 'paths were'} unavailable. Successful results are retained; unknown facts are never treated as safe.</span></aside>
}

export function DemoBanner() {
  return <div className="demo-banner"><span>DEMO</span> Synthetic data — no cloud account was contacted.</div>
}
