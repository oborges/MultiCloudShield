import { useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { NavLink, Route, Routes, useNavigate, useParams, useSearchParams } from 'react-router'
import { api, stringify, type Json, type Page } from './api/client'
import { DemoBanner, EmptyState, ErrorState, LoadingState, PartialState } from './components/States'

const nav = [
  ['/', 'Overview', '⌁'], ['/connections', 'Connections', '◇'], ['/scans', 'Scans', '◌'],
  ['/assets', 'Assets', '▦'], ['/findings', 'Findings', '△'], ['/policies', 'Policies', '§'],
] as const

function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) { return <span className={`badge ${tone}`}>{children}</span> }
function severityTone(value: unknown) { return `severity-${String(value)}` }
function fmtDate(value: unknown) { return value ? new Date(String(value)).toLocaleString() : '—' }

function Layout() {
  const me = useQuery({ queryKey: ['me'], queryFn: () => api<Json>('/auth/me'), retry: false })
  if (me.isLoading) return <LoadingState label="Checking your session" />
  if (me.isError) return <Login />
  return <div className="shell">
    <aside className="sidebar">
      <NavLink className="brand" to="/"><span className="mark">M</span><span>MultiCloud<br/><b>Shield</b></span></NavLink>
      <nav aria-label="Primary navigation">{nav.map(([to, label, icon]) => <NavLink key={to} end={to === '/'} to={to}><span aria-hidden="true">{icon}</span>{label}</NavLink>)}</nav>
      <div className="sidebar-foot"><div className="avatar">{String(me.data?.role ?? 'U').slice(0, 1).toUpperCase()}</div><div><strong>{String(me.data?.role)}</strong><small>Authenticated</small></div></div>
    </aside>
    <main><header className="topbar"><div><span className="eyebrow">READ-ONLY POSTURE</span></div><a className="docs" href="/api/v1/docs">API docs ↗</a></header><Routes>
      <Route path="/" element={<Overview />} />
      <Route path="/connections" element={<Connections />} />
      <Route path="/connections/:id" element={<ConnectionDetail />} />
      <Route path="/scans" element={<Scans />} />
      <Route path="/scans/:id" element={<ScanDetail />} />
      <Route path="/assets" element={<Assets />} />
      <Route path="/assets/:id" element={<AssetDetail />} />
      <Route path="/findings" element={<Findings />} />
      <Route path="/findings/:id" element={<FindingDetail />} />
      <Route path="/policies" element={<Policies />} />
      <Route path="/policies/:id" element={<PolicyDetail />} />
    </Routes></main>
  </div>
}

function Login() {
  const client = useQueryClient()
  const [message, setMessage] = useState('')
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault(); const data = new FormData(event.currentTarget)
    try { await api('/auth/login', { method: 'POST', body: JSON.stringify({ email: data.get('email'), password: data.get('password') }) }); await client.invalidateQueries({ queryKey: ['me'] }) }
    catch (error) { setMessage(error instanceof Error ? error.message : 'Login failed') }
  }
  return <main className="login"><section className="login-card"><div className="mark large">M</div><p className="eyebrow">MULTICLOUDSHIELD</p><h1>See what your clouds expose.</h1><p>One read-only view across AWS, Azure, GCP and IBM Cloud.</p><form onSubmit={submit}><label>Email<input name="email" type="email" autoComplete="username" required /></label><label>Password<input name="password" type="password" minLength={12} autoComplete="current-password" required /></label>{message && <p className="form-error" role="alert">{message}</p>}<button type="submit">Sign in</button></form></section></main>
}

function Heading({ eyebrow, title, detail, action }: { eyebrow: string; title: string; detail: string; action?: ReactNode }) { return <div className="heading"><div><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{detail}</p></div>{action}</div> }

function Overview() {
  const summary = useQuery({ queryKey: ['summary'], queryFn: () => api<Json>('/summary') })
  const findings = useQuery({ queryKey: ['findings', 'overview'], queryFn: () => api<Page>('/findings?limit=6') })
  const scans = useQuery({ queryKey: ['scans', 'overview'], queryFn: () => api<Page>('/scans?limit=4'), refetchInterval: 5000 })
  if (summary.isLoading || findings.isLoading || scans.isLoading) return <LoadingState />
  if (summary.isError || findings.isError || scans.isError) return <ErrorState message="The posture overview is temporarily unavailable." />
  const counts = (summary.data?.open_findings as Json | undefined) ?? {}
  return <section className="page">{findings.data?.meta.is_demo && <DemoBanner />}<Heading eyebrow="COMMAND CENTER" title="Cloud posture, without the fog." detail="Live inventory and explainable findings from your persisted scan data." action={<NavLink className="button" to="/connections">Start a scan</NavLink>} />
    <div className="metrics">{['critical','high','medium','low'].map(level => <article key={level}><span className={`metric-dot ${severityTone(level)}`}/><p>{level}</p><strong>{String(counts[level] ?? 0)}</strong><small>open findings</small></article>)}</div>
    <div className="split"><article className="panel"><div className="panel-head"><h2>Priority findings</h2><NavLink to="/findings">View all</NavLink></div><FindingRows items={findings.data?.items ?? []} /></article><article className="panel"><div className="panel-head"><h2>Recent scans</h2><NavLink to="/scans">View all</NavLink></div><ScanRows items={scans.data?.items ?? []} /></article></div>
  </section>
}

function Connections() {
  const query = useQuery({ queryKey: ['connections'], queryFn: () => api<Page>('/connections') })
  const client = useQueryClient(); const [show, setShow] = useState(false)
  const create = useMutation({ mutationFn: (payload: Json) => api('/connections', { method: 'POST', body: JSON.stringify(payload) }), onSuccess: () => { setShow(false); client.invalidateQueries({ queryKey: ['connections'] }) } })
  if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Connections could not be loaded." />
  return <section className="page">{query.data?.meta.is_demo && <DemoBanner />}<Heading eyebrow="CLOUD ACCESS" title="Connections" detail="Only credential mechanisms and non-secret references are stored." action={<button onClick={() => setShow(!show)}>Add connection</button>} />
    {show && <ConnectionForm busy={create.isPending} onSubmit={payload => create.mutate(payload)} />}
    {!query.data?.items.length ? <EmptyState title="No cloud connections">Add the deterministic demo estate or a read-only live scope.</EmptyState> : <div className="card-grid">{query.data.items.map(row => <NavLink className="connection-card" key={String(row.id)} to={`/connections/${row.id}`}><div><Badge tone={String(row.provider)}>{String(row.provider)}</Badge>{Boolean(row.is_demo) && <Badge tone="demo">demo</Badge>}</div><h2>{String(row.name)}</h2><p>{String(row.scope_id)}</p><footer><span className={`status ${row.enabled ? 'ok' : 'off'}`}>{row.enabled ? 'Enabled' : 'Disabled'}</span><span>{String(row.last_verification_status).replaceAll('_',' ')}</span></footer></NavLink>)}</div>}
  </section>
}

function ConnectionForm({ busy, onSubmit }: { busy: boolean; onSubmit: (value: Json) => void }) {
  const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); const provider = String(form.get('provider')); onSubmit({ name: form.get('name'), provider, scope_id: form.get('scope'), credential_mechanism: provider === 'demo' ? 'demo_none' : `${provider}_${provider === 'gcp' ? 'adc' : provider === 'aws' ? 'default_chain' : provider === 'azure' ? 'default_credential' : 'trusted_profile'}`, credential_reference: {}, region_allowlist: [] }) }
  return <form className="inline-form" onSubmit={submit}><label>Display name<input name="name" required /></label><label>Provider<select name="provider"><option value="demo">Demo</option><option value="aws">AWS</option><option value="azure">Azure</option><option value="gcp">GCP</option><option value="ibm">IBM Cloud</option></select></label><label>Scope ID<input name="scope" defaultValue="deterministic-v1" required /></label><button disabled={busy}>{busy ? 'Adding…' : 'Add securely'}</button></form>
}

function ConnectionDetail() {
  const { id } = useParams(); const navigate = useNavigate(); const query = useQuery({ queryKey: ['connections'], queryFn: () => api<Page>('/connections') }); const row = query.data?.items.find(item => item.id === id)
  const start = useMutation({ mutationFn: () => api<Json>(`/scans?connection_id=${id}`, { method: 'POST' }), onSuccess: value => navigate(`/scans/${value.scan_id}`) })
  if (query.isLoading) return <LoadingState />; if (!row) return <EmptyState title="Connection not found" />
  return <section className="page">{Boolean(row.is_demo) && <DemoBanner />}<Heading eyebrow={String(row.provider)} title={String(row.name)} detail={String(row.scope_id)} action={<button onClick={() => start.mutate()} disabled={start.isPending || !row.enabled}>{start.isPending ? 'Queuing…' : 'Start scan'}</button>} /><DetailGrid value={row} omit={['credential_reference']} /></section>
}

function Scans() {
  const query = useQuery({ queryKey: ['scans'], queryFn: () => api<Page>('/scans'), refetchInterval: 4000 })
  if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Scan history could not be loaded." />
  return <section className="page">{query.data?.meta.is_demo && <DemoBanner />}<Heading eyebrow="SCAN HISTORY" title="Scans" detail="Progress, coverage gaps and terminal outcomes for every run." />{!query.data?.items.length ? <EmptyState title="No scans yet" /> : <article className="panel table-panel"><ScanRows items={query.data.items} /></article>}</section>
}

function ScanRows({ items }: { items: Json[] }) { return <div className="rows">{items.length ? items.map(row => <NavLink className="row" key={String(row.id)} to={`/scans/${row.id}`}><div><strong>{String(row.id).slice(0, 8)}</strong><small>{fmtDate(row.started_at ?? row.queued_at)}</small></div><Badge tone={`scan-${row.status}`}>{String(row.status).replaceAll('_',' ')}</Badge><span>{row.is_demo ? 'Demo estate' : 'Live scope'}</span><span className="arrow">→</span></NavLink>) : <EmptyState title="No recent scans" />}</div> }

function ScanDetail() {
  const { id } = useParams(); const query = useQuery({ queryKey: ['scan', id], queryFn: () => api<Json>(`/scans/${id}`), refetchInterval: value => ['queued','running'].includes(String(value.state.data?.status)) ? 2000 : false })
  if (query.isLoading) return <LoadingState label="Loading scan progress" />; if (query.isError) return <ErrorState message="Scan detail could not be loaded." />; const data = query.data ?? {}; const errors = (data.errors as Json[] | undefined) ?? []
  return <section className="page">{Boolean(data.is_demo) && <DemoBanner />}<Heading eyebrow="SCAN DETAIL" title={`Scan ${String(data.scan_id ?? id).slice(0, 8)}`} detail={`${String(data.status).replaceAll('_',' ')} · ${fmtDate(data.started_at)}`} />{String(data.status) === 'partially_completed' && <PartialState errors={errors.length} />}<DetailGrid value={(data.stats as Json) ?? data} /><div className="split"><article className="panel"><div className="panel-head"><h2>Errors and coverage gaps</h2><Badge>{errors.length}</Badge></div>{errors.length ? errors.map(item => <div className="error-row" key={String(item.id)}><Badge tone="warning">{String(item.category)}</Badge><div><strong>{String(item.collector_id)}</strong><p>{String(item.message)}</p>{Boolean(item.remediation_hint) && <code>{String(item.remediation_hint)}</code>}</div></div>) : <EmptyState title="No collection errors">Every planned target completed.</EmptyState>}</article><article className="panel"><div className="panel-head"><h2>Result</h2></div><p>{((data.assets as unknown[]) ?? []).length} assets discovered</p><p>{((data.findings as unknown[]) ?? []).length} findings produced</p><p>{((data.evaluations as unknown[]) ?? []).length} policy evaluations</p></article></div></section>
}

function Assets() { const [params, setParams] = useSearchParams(); const queryString = params.toString(); const query = useQuery({ queryKey: ['assets', queryString], queryFn: () => api<Page>(`/assets?${queryString}`) }); if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Asset inventory could not be loaded." />; return <section className="page">{query.data?.meta.is_demo && <DemoBanner />}<Heading eyebrow="NORMALIZED INVENTORY" title="Assets" detail="Provider resources translated into one typed fact model." /><Filters params={params} setParams={setParams} fields={['provider','resource_type','connection_id']} />{!query.data?.items.length ? <EmptyState title="No assets match these filters" /> : <article className="panel table-panel"><div className="rows">{query.data.items.map(row => <NavLink className="row" key={String(row.id)} to={`/assets/${row.id}`}><Badge tone={String(row.provider)}>{String(row.provider)}</Badge><div><strong>{String(row.name)}</strong><small>{String(row.resource_type)}</small></div><span>{String(row.scope_id)}</span><span className="arrow">→</span></NavLink>)}</div></article>}</section> }

function AssetDetail() { const { id } = useParams(); const query = useQuery({ queryKey: ['asset', id], queryFn: () => api<Json>(`/assets/${id}`) }); if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Asset detail could not be loaded." />; const data = query.data ?? {}; return <section className="page">{Boolean(data.is_demo) && <DemoBanner />}<Heading eyebrow={String(data.provider)} title={String(data.name)} detail={String(data.asset_urn)} /><DetailGrid value={data} /></section> }

function Findings() {
  const [params, setParams] = useSearchParams(); const queryString = params.toString(); const query = useQuery({ queryKey: ['findings', queryString], queryFn: () => api<Page>(`/findings?${queryString}`) })
  if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Findings could not be loaded." />
  return <section className="page">{query.data?.meta.is_demo && <DemoBanner />}<Heading eyebrow="ACTIVE RISK" title="Findings" detail="Every verdict is tied to recorded facts and provider-call provenance." action={<a className="button secondary" href="/api/v1/exports/findings?format=csv">Export CSV</a>} /><Filters params={params} setParams={setParams} fields={['provider','severity','policy','resource_type','connection','scan','status']} /><p className="result-count">{query.data?.items.length ?? 0} results</p><article className="panel table-panel"><FindingRows items={query.data?.items ?? []} /></article></section>
}

function FindingRows({ items }: { items: Json[] }) { return <div className="rows">{items.length ? items.map(row => <NavLink className="row finding-row" key={String(row.id)} to={`/findings/${row.id}`}><Badge tone={severityTone(row.severity)}>{String(row.severity)}</Badge><div><strong>{String(row.title)}</strong><small>{String(row.policy_id)} · {String(row.status)}</small></div><span>{String(row.resource_name ?? String(row.asset_id).slice(0, 8))}</span><span className="arrow">→</span></NavLink>) : <EmptyState title="No findings match these filters" />}</div> }

function FindingDetail() { const { id } = useParams(); const query = useQuery({ queryKey: ['finding', id], queryFn: () => api<Json>(`/findings/${id}`) }); const client = useQueryClient(); const transition = useMutation({ mutationFn: (payload: Json) => api(`/findings/${id}/status`, { method: 'POST', body: JSON.stringify(payload) }), onSuccess: () => client.invalidateQueries({ queryKey: ['finding', id] }) }); if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Finding detail could not be loaded." />; const data = query.data ?? {}; const evidence = (data.evidence as Json | undefined) ?? {}; const remediation = (data.remediation_snapshot as Json | undefined) ?? {}; return <section className="page">{Boolean(data.is_demo) && <DemoBanner />}<Heading eyebrow={String(data.policy_id)} title={String(data.title)} detail={String(data.fingerprint)} action={<Badge tone={severityTone(data.severity)}>{String(data.severity)}</Badge>} /><div className="split detail"><article className="panel"><h2>Why this matters</h2><p>{String(data.risk_explanation)}</p><h2>Evidence</h2><pre>{JSON.stringify(evidence.observed_facts ?? {}, null, 2)}</pre><h3>Provider-call provenance</h3><pre>{JSON.stringify(evidence.provenance ?? {}, null, 2)}</pre></article><article className="panel"><h2>Remediation guidance</h2><p>{String(remediation.summary ?? 'Review the policy guidance before changing the provider resource.')}</p><ol>{((remediation.steps as string[]) ?? []).map(step => <li key={step}>{step}</li>)}</ol><p className="notice">Guidance is never executed by MultiCloudShield.</p><StatusForm current={String(data.status)} busy={transition.isPending} onSubmit={payload => transition.mutate(payload)} /></article></div></section> }

function StatusForm({ current, busy, onSubmit }: { current: string; busy: boolean; onSubmit: (payload: Json) => void }) { const submit = (event: FormEvent<HTMLFormElement>) => { event.preventDefault(); const form = new FormData(event.currentTarget); onSubmit({ status: form.get('status'), reason: form.get('reason') }) }; return <form className="status-form" onSubmit={submit}><h3>Finding status</h3><label>Status<select name="status" defaultValue={current}><option value="open">Open</option><option value="suppressed">Suppressed</option><option value="risk_accepted">Risk accepted</option><option value="false_positive">False positive</option></select></label><label>Reason<textarea name="reason" minLength={3} required /></label><button disabled={busy}>Save audited change</button></form> }

function Policies() { const query = useQuery({ queryKey: ['policies'], queryFn: () => api<Page>('/policies') }); if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Policy catalog could not be loaded." />; return <section className="page"><Heading eyebrow="POLICY BUNDLE" title="Policy catalog" detail="23 deterministic checks with original guidance and identifier-only compliance mappings." /><div className="policy-grid">{query.data?.items.map(row => <NavLink className="policy-card" key={String(row.id)} to={`/policies/${row.id}`}><Badge tone={severityTone(row.severity)}>{String(row.severity)}</Badge><h2>{String(row.title)}</h2><p>{String(row.description)}</p><footer><code>{String(row.id)}</code><span>{String(row.version)}</span></footer></NavLink>)}</div></section> }

function PolicyDetail() { const { id } = useParams(); const query = useQuery({ queryKey: ['policy', id], queryFn: () => api<Json>(`/policies/${id}`) }); if (query.isLoading) return <LoadingState />; if (query.isError) return <ErrorState message="Policy detail could not be loaded." />; return <section className="page"><Heading eyebrow={String(query.data?.id)} title={String(query.data?.title)} detail={String(query.data?.description)} action={<Badge tone={severityTone(query.data?.severity)}>{String(query.data?.severity)}</Badge>} /><DetailGrid value={query.data ?? {}} /></section> }

function Filters({ params, setParams, fields }: { params: URLSearchParams; setParams: (next: URLSearchParams) => void; fields: string[] }) { const set = (name: string, value: string) => { const next = new URLSearchParams(params); if (value) next.set(name, value); else next.delete(name); setParams(next) }; return <div className="filters" aria-label="Result filters">{fields.map(field => <label key={field}><span>{field.replaceAll('_',' ')}</span><input value={params.get(field) ?? ''} placeholder="Any" onChange={event => set(field, event.target.value)} /></label>)}{params.size > 0 && <button className="clear" onClick={() => setParams(new URLSearchParams())}>Clear all</button>}</div> }

function DetailGrid({ value, omit = [] }: { value: Json; omit?: string[] }) { const entries = useMemo(() => Object.entries(value).filter(([key]) => !omit.includes(key) && !['result_payload'].includes(key)), [value, omit]); return <dl className="detail-grid">{entries.map(([key, item]) => <div key={key}><dt>{key.replaceAll('_',' ')}</dt><dd>{typeof item === 'object' && item !== null ? <pre>{JSON.stringify(item, null, 2)}</pre> : stringify(item)}</dd></div>)}</dl> }

export default function App() { return <Layout /> }
