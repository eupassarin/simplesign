import type { CertificateView, PkiView, Publication, SandboxFaults, SandboxInfo, SandboxRequest } from "./types"

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    headers: body === undefined ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`
    try {
      const problem = await response.json()
      message = problem.error ?? problem.detail ?? message
    } catch {
      // Not JSON: keep the status line.
    }
    throw new Error(message)
  }
  return response.status === 204 ? (undefined as T) : ((await response.json()) as T)
}

export const api = {
  info: () => request<SandboxInfo>("GET", "/api/info"),
  pki: () => request<PkiView>("GET", "/api/pki"),
  revoke: (id: string, reason: string, publication: Publication) => request<CertificateView>("POST", `/api/certificates/${encodeURIComponent(id)}/revoke`, { reason, publication }),
  unrevoke: (id: string) => request<CertificateView>("POST", `/api/certificates/${encodeURIComponent(id)}/unrevoke`),
  pfxUrl: (id: string) => `/api/certificates/${encodeURIComponent(id)}/pfx`,
  cerUrl: (id: string) => `/api/certificates/${encodeURIComponent(id)}/cer`,
  faults: () => request<SandboxFaults>("GET", "/api/faults"),
  setFaults: (faults: SandboxFaults) => request<SandboxFaults>("PUT", "/api/faults", faults),
  log: (after: number) => request<SandboxRequest[]>("GET", `/api/log?after=${after}`),
  reset: () => request<void>("POST", "/api/reset"),
}
