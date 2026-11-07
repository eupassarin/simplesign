import type {
  CredentialFacts,
  CscCredentialSummary,
  DocumentFacts,
  EnvironmentInfo,
  EnvironmentMode,
  OptionInfo,
  Pkcs11Driver,
  SampleDocument,
  SandboxRequest,
  StoreCertificate,
  BulkReport,
  InspectionReport,
  ValidationSample,
  ValidationSettings,
  CadesSample,
  CmsFacts,
  XmlSample,
} from "./types"

import type { DssComparison, DssSettings, DssStatus, Evaluation, Format, Options, RealEnvironment, RunSummary, RunView, SandboxFaults, SandboxState, ValidationSampleView, WorkbenchSchema } from "@/features/workbench/schema"

export class ApiError extends Error {}

let locale = "en-US"

/** The language sent as Accept-Language, so the server's explanations and errors match the UI. */
export function setApiLocale(value: string) {
  locale = value
}

async function request<T>(method: string, url: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { "Accept-Language": locale }
  const init: RequestInit = { method, headers }
  if (body instanceof FormData) {
    init.body = body
  } else if (body !== undefined) {
    init.body = JSON.stringify(body)
    headers["Content-Type"] = "application/json"
  }
  const response = await fetch(url, init)
  const text = await response.text()
  const data = text ? JSON.parse(text) : undefined
  if (!response.ok) {
    throw new ApiError(data?.error ?? data?.title ?? `${response.status} ${response.statusText}`)
  }
  return data as T
}

function upload(file: File) {
  const form = new FormData()
  form.append("file", file)
  return form
}

export const api = {
  env: () => request<EnvironmentInfo>("GET", "/api/env"),
  catalog: () => request<Record<string, OptionInfo>>("GET", "/api/catalog"),
  sandboxLog: () => request<SandboxRequest[]>("GET", "/api/sandbox/log"),
  samples: () => request<SampleDocument[]>("GET", "/api/documents/samples"),
  uploadDocument: (file: File) => request<DocumentFacts>("POST", "/api/documents", upload(file)),
  uploadFile: (file: File) => request<{ id: string; fileName: string; size: number }>("POST", "/api/uploads", upload(file)),
  fileUrl: (id: string, download = false) => `/api/files/${encodeURIComponent(id)}${download ? "?download=true" : ""}`,
  validation: {
    samples: () => request<ValidationSample[]>("GET", "/api/validation/samples"),
    bulk: (fileIds: string[], settings: ValidationSettings, maxConcurrency: number) => request<BulkReport>("POST", "/api/validation/bulk", { fileIds, settings, maxConcurrency }),
    inspect: (fileId: string) => request<InspectionReport>("POST", "/api/inspect", { fileId }),
    cmsUrl: (fileId: string, field: string) => `/api/files/${encodeURIComponent(fileId)}/cms/${encodeURIComponent(field)}`,
  },
  cades: {
    samples: () => request<CadesSample[]>("GET", "/api/cades/samples"),
    inspect: (fileId: string) => request<CmsFacts>("POST", "/api/cades/inspect", { fileId }),
  },
  xml: {
    samples: () => request<XmlSample[]>("GET", "/api/xml/samples"),
  },
  credentials: {
    sandbox: (signerId: string) => request<CredentialFacts>("POST", "/api/credentials/sandbox", { signerId }),
    pfx: (uploadId: string, password: string) => request<CredentialFacts>("POST", "/api/credentials/pfx", { uploadId, password }),
    store: () => request<StoreCertificate[]>("GET", "/api/credentials/store"),
    openStore: (thumbprint: string) => request<CredentialFacts>("POST", "/api/credentials/store", { thumbprint }),
    pkcs11: () => request<Pkcs11Driver[]>("GET", "/api/credentials/pkcs11"),
    openPkcs11: (body: { libraryPath: string; tokenSerial?: string; certificateThumbprint?: string; pin?: string; usePinPad: boolean }) =>
      request<CredentialFacts>("POST", "/api/credentials/pkcs11", body),
    cscList: (environment: EnvironmentMode, body: Record<string, unknown>) =>
      request<CscCredentialSummary[]>("POST", `/api/credentials/csc/list?environment=${environment}`, body),
    csc: (environment: EnvironmentMode, body: Record<string, unknown>) =>
      request<CredentialFacts>("POST", `/api/credentials/csc?environment=${environment}`, body),
    close: (id: string) => request<void>("DELETE", `/api/credentials/${id}`),
  },
  workbench: {
    schema: () => request<WorkbenchSchema>("GET", "/api/schema"),
    evaluate: (format: Format, options: Options) => request<Evaluation>("POST", "/api/workbench/options", { format, options }),
    start: (format: Format | "", options: Options, crossValidate: boolean, kind: "sign" | "validate" = "sign") =>
      request<{ id: string }>("POST", "/api/runs", { format, options, crossValidate, kind }),
    samples: () => request<ValidationSampleView[]>("GET", "/api/validation/samples/all"),
    run: (id: string) => request<RunView | undefined>("GET", `/api/runs/${id}`),
    eventsUrl: (id: string) => `/api/runs/${id}/events`,
    history: () => request<RunSummary[]>("GET", "/api/runs"),
  },
  environment: {
    real: () => request<RealEnvironment>("GET", "/api/environment/real"),
  },
  sandbox: {
    state: () => request<SandboxState>("GET", "/api/sandbox/state"),
    faults: (faults: SandboxFaults) => request<SandboxState>("PUT", "/api/sandbox/faults", faults),
    revoke: (signerId: string) => request<SandboxState>("POST", `/api/sandbox/signers/${signerId}/revoke`),
    reset: () => request<SandboxState>("POST", "/api/sandbox/reset"),
    certificateUrl: (id: string) => `/api/sandbox/certificates/${id}`,
    crlUrl: (name: "root" | "intermediate") => `/api/sandbox/crls/${name}.crl`,
    rootPemUrl: "/api/sandbox/root.pem",
  },
  dss: {
    settings: () => request<DssSettings>("GET", "/api/dss/settings"),
    save: (settings: DssSettings) => request<DssSettings>("PUT", "/api/dss/settings", settings),
    status: () => request<DssStatus>("GET", "/api/dss/status"),
    validate: (fileId: string, dataId?: string | null) => request<DssComparison>("POST", "/api/dss/validate", { fileId, dataId }),
  },
}
