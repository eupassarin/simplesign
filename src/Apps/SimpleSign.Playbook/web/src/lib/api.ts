import type {
  CliCheck, PlaybookDefinition, PlaybookIssue, RunListItem, RunRecord, SandboxStatus, SettingsView, WorkspaceView, WorkspacesView,
} from "./types"

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const response = await fetch(url, {
    method,
    headers: body === undefined || body instanceof FormData ? undefined : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
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

const files = (list: FileList | File[]) => {
  const form = new FormData()
  for (const file of Array.from(list)) form.append("files", file, file.name)
  return form
}

export const api = {
  settings: () => request<SettingsView>("GET", "/api/settings"),
  saveSettings: (cliCommand: string | null, cliPrefix: string[]) => request<SettingsView>("PUT", "/api/settings", { cliCommand, cliPrefix }),
  checkCli: () => request<CliCheck>("POST", "/api/settings/check"),

  workspaces: () => request<WorkspacesView>("GET", "/api/workspaces"),
  open: (path: string) => request<WorkspaceView>("POST", "/api/workspaces/open", { path }),
  create: (path: string, name: string | null, sample: string | null) => request<WorkspaceView>("POST", "/api/workspaces/create", { path, name, sample }),

  workspace: () => request<WorkspaceView>("GET", "/api/workspace"),
  savePlaybook: (text: string) => request<WorkspaceView>("PUT", "/api/workspace/playbook", { text }),
  checkPlaybook: (text: string) => request<{ playbook?: PlaybookDefinition | null; issues: PlaybookIssue[] }>("POST", "/api/workspace/playbook/check", { text }),
  uploadAssets: (list: FileList | File[]) => request<WorkspaceView>("POST", "/api/workspace/assets", files(list)),
  deleteAsset: (path: string) => request<WorkspaceView>("DELETE", `/api/workspace/assets?path=${encodeURIComponent(path)}`),
  setSecret: (key: string, value: string | null) => request<WorkspaceView>("PUT", `/api/workspace/secrets/${encodeURIComponent(key)}`, { value }),

  sandbox: (url: string) => request<SandboxStatus>("GET", `/api/sandbox?url=${encodeURIComponent(url)}`),

  runs: () => request<RunListItem[]>("GET", "/api/runs"),
  run: (id: string) => request<RunRecord>("GET", `/api/runs/${encodeURIComponent(id)}`),
  start: (selection: string[] | null) => request<{ id?: string | null }>("POST", "/api/runs", { selection }),
  cancel: () => request<void>("DELETE", "/api/runs/active"),
  decide: (runId: string, stepId: string, status: string, note: string | null) =>
    request<void>("POST", `/api/runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}/decision`, { status, note }),
  attach: (runId: string, stepId: string, list: FileList | File[]) =>
    request<string[]>("POST", `/api/runs/${encodeURIComponent(runId)}/steps/${encodeURIComponent(stepId)}/attachments`, files(list)),
  eventsUrl: "/api/runs/active/events",
  fileUrl: (runId: string, path: string, download = false) =>
    `/api/runs/${encodeURIComponent(runId)}/files/${path.split("/").map(encodeURIComponent).join("/")}${download ? "?download=true" : ""}`,
  zipUrl: (runId: string) => `/api/runs/${encodeURIComponent(runId)}/zip`,
}
