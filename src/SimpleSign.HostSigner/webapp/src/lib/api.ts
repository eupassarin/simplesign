const API = 'http://localhost:21590'

export interface CertificateInfo {
  name: string
  thumbprint: string
  issuerName: string
  expireDate: string
  notBefore: string
  signatureAlgorithm?: string
  hashAlgorithm?: string
}

export interface SignFileOptions {
  filePath: string
  thumbprint: string
  tsaUrl?: string | null
  reason?: string | null
  location?: string | null
  signerName?: string | null
  contactInfo?: string | null
  fieldName?: string | null
  hashAlgorithm?: string
  enableLtv?: boolean
  preservePdfA?: boolean
  archivalTimestamp?: boolean
  certificationLevel?: string
  visibleStamp?: boolean
}

export async function fetchCertificates(): Promise<CertificateInfo[]> {
  const resp = await fetch(`${API}/api/certificates`)
  return resp.json()
}

export async function signFile(options: SignFileOptions) {
  const resp = await fetch(`${API}/api/sign-file`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(options),
  })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || 'Sign failed')
  return data
}

export async function inspectFile(filePath: string) {
  const resp = await fetch(`${API}/api/inspect`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath }),
  })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || 'Inspect failed')
  return data
}

export async function validateFile(filePath: string) {
  const resp = await fetch(`${API}/api/validate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filePath }),
  })
  const data = await resp.json()
  if (!resp.ok) throw new Error(data.error || 'Validate failed')
  return data
}

export async function fetchVersion() {
  const resp = await fetch(`${API}/api/version`)
  return resp.json()
}

export async function fetchHealth() {
  const resp = await fetch(`${API}/api/health`)
  return resp.json()
}

export function browseFiles() {
  window.chrome?.webview?.postMessage({ action: 'browseFiles' })
}

export function browseInspect() {
  window.chrome?.webview?.postMessage({ action: 'browseInspect' })
}

export function browseValidate() {
  window.chrome?.webview?.postMessage({ action: 'browseValidate' })
}

export function openUrl(url: string) {
  window.chrome?.webview?.postMessage({ action: 'openUrl', url })
}

declare global {
  interface Window {
    chrome?: { webview?: { postMessage: (msg: any) => void } }
    _hostInfo?: { pid?: string; runtime?: string }
  }
}
