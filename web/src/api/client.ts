export type Json = Record<string, unknown>
export type Page<T = Json> = { items: T[]; next_cursor: string | null; meta: { is_demo?: boolean; generated_at?: string } }

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message) }
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const csrf = document.cookie.split('; ').find(item => item.startsWith('mcs_csrf='))?.split('=')[1]
  const response = await fetch(`/api/v1${path}`, {
    credentials: 'same-origin',
    ...init,
    headers: { 'Content-Type': 'application/json', ...(csrf ? { 'X-CSRF-Token': decodeURIComponent(csrf) } : {}), ...(init?.headers ?? {}) },
  })
  if (!response.ok) {
    const problem = await response.json().catch(() => ({ detail: 'The request failed.' }))
    throw new ApiError(response.status, String(problem.detail ?? 'The request failed.'))
  }
  return response.status === 204 ? (undefined as T) : response.json() as Promise<T>
}

export function stringify(value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}
