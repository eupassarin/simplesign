import { ApiError } from "@/lib/api"
import type { ScriptLoaded, ScriptRunView, ScriptSample } from "./types"

async function call<T>(method: string, url: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: body === undefined ? {} : { "Content-Type": "application/json" } }
  if (body !== undefined) init.body = JSON.stringify(body)
  const response = await fetch(url, init)
  const text = await response.text()
  const data = text ? JSON.parse(text) : undefined
  if (!response.ok) throw new ApiError(data?.error ?? data?.title ?? `${response.status} ${response.statusText}`)
  return data as T
}

/** The certification script API (Endpoints/ScriptApi.cs). */
export const scriptApi = {
  samples: () => call<ScriptSample[]>("GET", "/api/script/samples"),
  loadSample: (id: string) => call<ScriptLoaded>("POST", `/api/script/samples/${encodeURIComponent(id)}`),
  load: (json: string) => call<ScriptLoaded>("POST", "/api/script/load", { json }),
  loaded: () => call<ScriptLoaded | undefined>("GET", "/api/script/loaded"),
  history: () => call<ScriptRunView[]>("GET", "/api/script/runs"),
  start: (request: { engine?: string | null; sectionId?: string | null; stepId?: string | null }) => call<ScriptRunView>("POST", "/api/script/runs", request),
  run: (id: string) => call<ScriptRunView>("GET", `/api/script/runs/${id}`),
  cancel: (id: string) => call<void>("POST", `/api/script/runs/${id}/cancel`),
  decide: (id: string, stepId: string, decision: { passed: boolean; note?: string | null; attachmentIds?: string[] }) =>
    call<void>("POST", `/api/script/runs/${id}/steps/${encodeURIComponent(stepId)}/decision`, decision),
  evidenceHtmlUrl: (id: string) => `/api/script/runs/${id}/evidence.html`,
  evidenceZipUrl: (id: string) => `/api/script/runs/${id}/evidence.zip`,
  schemaUrl: "/api/script/schema",
  optionsUrl: "/api/script/options",
}
