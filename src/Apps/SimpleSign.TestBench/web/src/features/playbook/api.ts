import { ApiError, apiLocale } from "@/lib/api"
import type { PlaybookLoaded, PlaybookSample, PlaybookSandboxReference, PlaybookStateView, PlaybookStepPreview } from "./types"

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Accept-Language": apiLocale() }
  if (body !== undefined) headers["Content-Type"] = "application/json"
  const init: RequestInit = { method, headers }
  if (body !== undefined) init.body = JSON.stringify(body)
  const response = await fetch(url, init)
  const text = await response.text()
  const data = text ? JSON.parse(text) : undefined
  if (!response.ok) throw new ApiError(data?.error ?? data?.title ?? `${response.status} ${response.statusText}`)
  return data as T
}

/** The playbook API (Endpoints/PlaybookApi.cs). */
export const playbookApi = {
  samples: () => call<PlaybookSample[]>("GET", "/api/playbook/samples"),
  loadSample: (id: string) => call<PlaybookLoaded>("POST", `/api/playbook/samples/${encodeURIComponent(id)}`),
  load: (json: string) => call<PlaybookLoaded>("POST", "/api/playbook/load", { json }),
  loaded: () => call<PlaybookLoaded | undefined>("GET", "/api/playbook/loaded"),
  state: () => call<PlaybookStateView>("GET", "/api/playbook/state"),
  run: (request: { engine?: string | null; sectionId?: string | null; stepId?: string | null }) => call<PlaybookStateView>("POST", "/api/playbook/run", request),
  clear: (stepId?: string | null) =>
    call<PlaybookStateView>("DELETE", stepId ? `/api/playbook/results/${encodeURIComponent(stepId)}` : "/api/playbook/results"),
  cancel: () => call<void>("POST", "/api/playbook/cancel"),
  preview: (stepId: string, engine?: string | null) =>
    call<PlaybookStepPreview>("GET", `/api/playbook/steps/${encodeURIComponent(stepId)}/preview${engine ? `?engine=${encodeURIComponent(engine)}` : ""}`),
  sandbox: () => call<PlaybookSandboxReference>("GET", "/api/playbook/sandbox"),
  loadedJson: async () => {
    const response = await fetch("/api/playbook/loaded/json")
    return response.ok && response.status !== 204 ? await response.text() : null
  },
  loadedJsonUrl: "/api/playbook/loaded/json",
  evidenceHtmlUrl: "/api/playbook/evidence.html",
  evidenceZipUrl: "/api/playbook/evidence.zip",
  schemaUrl: "/api/playbook/schema",
  optionsUrl: "/api/playbook/options",
}
