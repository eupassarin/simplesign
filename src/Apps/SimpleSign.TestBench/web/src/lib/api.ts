import type {
  CredentialFacts,
  CscCredentialSummary,
  DocumentFacts,
  EnvironmentInfo,
  EnvironmentMode,
  IcpPolicyKind,
  IcpVersion,
  MatrixCase,
  MatrixRunResult,
  OptionInfo,
  OptionsResponse,
  Pkcs11Driver,
  SampleDocument,
  SandboxRequest,
  SigningOptions,
  SigningResult,
  StoreCertificate,
  BulkReport,
  InspectionReport,
  ValidationReport,
  ValidationSample,
  ValidationSettings,
  CadesOptions,
  CadesOptionsResponse,
  CadesSample,
  CadesSignResult,
  CadesValidationView,
  CmsFacts,
  XmlOptions,
  XmlOptionsResponse,
  XmlSample,
  XmlSignResult,
  XmlValidationView,
} from "./types"

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
  options: (options: SigningOptions) => request<OptionsResponse>("POST", "/api/options", options),
  icpVersions: (policy: IcpPolicyKind, credentialId?: string | null) =>
    request<IcpVersion[]>("GET", `/api/icp/versions?policy=${policy}${credentialId ? `&credentialId=${credentialId}` : ""}`),
  sign: (options: SigningOptions) => request<SigningResult>("POST", "/api/sign", options),
  preview: (options: SigningOptions) => request<{ fileId: string }>("POST", "/api/preview", options),
  validation: {
    samples: () => request<ValidationSample[]>("GET", "/api/validation/samples"),
    validate: (fileId: string, settings: ValidationSettings) => request<ValidationReport>("POST", "/api/validation", { fileId, settings }),
    bulk: (fileIds: string[], settings: ValidationSettings, maxConcurrency: number) => request<BulkReport>("POST", "/api/validation/bulk", { fileIds, settings, maxConcurrency }),
    inspect: (fileId: string) => request<InspectionReport>("POST", "/api/inspect", { fileId }),
    cmsUrl: (fileId: string, field: string) => `/api/files/${encodeURIComponent(fileId)}/cms/${encodeURIComponent(field)}`,
  },
  cades: {
    samples: () => request<CadesSample[]>("GET", "/api/cades/samples"),
    options: (options: CadesOptions) => request<CadesOptionsResponse>("POST", "/api/cades/options", options),
    sign: (options: CadesOptions) => request<CadesSignResult>("POST", "/api/cades/sign", options),
    validate: (signatureId: string, dataId: string | null, settings: ValidationSettings) =>
      request<CadesValidationView>("POST", "/api/cades/validate", { signatureId, dataId, settings }),
    inspect: (fileId: string) => request<CmsFacts>("POST", "/api/cades/inspect", { fileId }),
  },
  xml: {
    samples: () => request<XmlSample[]>("GET", "/api/xml/samples"),
    options: (options: XmlOptions) => request<XmlOptionsResponse>("POST", "/api/xml/options", options),
    sign: (options: XmlOptions) => request<XmlSignResult>("POST", "/api/xml/sign", options),
    validate: (signatureId: string, dataId: string | null, settings: ValidationSettings) =>
      request<XmlValidationView>("POST", "/api/xml/validate", { signatureId, dataId, settings }),
  },
  credentials: {
    sandbox: (signerId: string) => request<CredentialFacts>("POST", "/api/credentials/sandbox", { signerId }),
    pfx: (uploadId: string, password: string) => request<CredentialFacts>("POST", "/api/credentials/pfx", { uploadId, password }),
    store: () => request<StoreCertificate[]>("GET", "/api/credentials/store"),
    openStore: (thumbprint: string) => request<CredentialFacts>("POST", "/api/credentials/store", { thumbprint }),
    pkcs11: () => request<Pkcs11Driver[]>("GET", "/api/credentials/pkcs11"),
    openPkcs11: (body: { libraryPath: string; tokenSerial?: string; certificateThumbprint?: string; pin?: string; usePinPad: boolean }) =>
      request<CredentialFacts>("POST", "/api/credentials/pkcs11", body),
    psc: (environment: EnvironmentMode, flow: "browser" | "password", body: Record<string, unknown>) =>
      request<CredentialFacts>("POST", `/api/credentials/psc/${flow}?environment=${environment}`, body),
    cscList: (environment: EnvironmentMode, body: Record<string, unknown>) =>
      request<CscCredentialSummary[]>("POST", `/api/credentials/csc/list?environment=${environment}`, body),
    csc: (environment: EnvironmentMode, body: Record<string, unknown>) =>
      request<CredentialFacts>("POST", `/api/credentials/csc?environment=${environment}`, body),
    close: (id: string) => request<void>("DELETE", `/api/credentials/${id}`),
  },
  matrix: {
    cases: (format = "pades") => request<MatrixCase[]>("GET", `/api/matrix/cases?format=${format}`),
    run: (body: { group?: string; limit?: number; caseId?: string; format?: string }) => request<MatrixRunResult>("POST", "/api/matrix/run", body),
  },
}
