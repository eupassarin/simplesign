import type { CertificateView, PkiView, Publication, SandboxFaults, SandboxInfo, SandboxRequest } from "./types"

// The connected Sandbox's admin API, passed through by the TestBench (SandboxApi.Forward): one origin for the page.
/** A failed call; `unsupported` when the Sandbox does not know the route (an older version). */
export class ApiError extends Error {
  constructor(message: string, readonly status: number, readonly unsupported = false) {
    super(message)
  }
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    headers: body === undefined ? { Accept: "application/json" } : { Accept: "application/json", "Content-Type": "application/json" },
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
    throw new ApiError(message, response.status, response.status === 404 || response.status === 405)
  }
  if (response.status === 204) return undefined as T
  // An older Sandbox answers a route it does not have with the page (200, HTML).
  if (!(response.headers.get("Content-Type") ?? "").includes("json")) {
    throw new ApiError(`${method} ${url}: the Sandbox did not answer JSON (an older version without this route?)`, response.status, true)
  }
  return (await response.json()) as T
}

/** PATCH and DELETE on /api/faults, or a read and a PUT on a Sandbox that does not have them. */
async function changeFaults(method: "PATCH" | "DELETE", change: (current: SandboxFaults) => Partial<SandboxFaults>, body?: Partial<SandboxFaults>): Promise<SandboxFaults> {
  try {
    return await request<SandboxFaults>(method, "/api/sandbox/admin/faults", body)
  } catch (e) {
    if (!(e instanceof ApiError) || !e.unsupported) throw e
    const current = await request<SandboxFaults>("GET", "/api/sandbox/admin/faults")
    return request<SandboxFaults>("PUT", "/api/sandbox/admin/faults", { ...current, ...change(current) })
  }
}

export const api = {
  info: () => request<SandboxInfo>("GET", "/api/sandbox/admin/info"),
  pki: () => request<PkiView>("GET", "/api/sandbox/admin/pki"),
  revoke: (id: string, reason: string, publication: Publication) => request<CertificateView>("POST", `/api/sandbox/admin/certificates/${encodeURIComponent(id)}/revoke`, { reason, publication }),
  unrevoke: (id: string) => request<CertificateView>("POST", `/api/sandbox/admin/certificates/${encodeURIComponent(id)}/unrevoke`),
  pfxUrl: (id: string) => `/api/sandbox/admin/certificates/${encodeURIComponent(id)}/pfx`,
  cerUrl: (id: string) => `/api/sandbox/admin/certificates/${encodeURIComponent(id)}/cer`,
  faults: () => request<SandboxFaults>("GET", "/api/sandbox/admin/faults"),
  setFaults: (faults: SandboxFaults) => request<SandboxFaults>("PUT", "/api/sandbox/admin/faults", faults),
  patchFaults: (change: Partial<SandboxFaults>) => changeFaults("PATCH", () => change, change),
  faultsOff: () => changeFaults("DELETE", () => ({ tsa: "None", crl: "None", ocsp: "None", trustedList: "None" })),
  log: (after: number, limit?: number) => request<SandboxRequest[]>("GET", `/api/sandbox/admin/log?after=${after}${limit ? `&limit=${limit}` : ""}`),
  clearLog: () => request<void>("DELETE", "/api/sandbox/admin/log"),
  reset: () => request<void>("POST", "/api/sandbox/admin/reset"),
}
