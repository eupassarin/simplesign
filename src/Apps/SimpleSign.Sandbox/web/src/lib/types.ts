// Mirrors src/Apps/SimpleSign.Sandbox/Endpoints/AdminEndpoints.cs and Services/SandboxFaults.cs (camelCase JSON, enums as names).

export interface SandboxInfo {
  name: string
  version: string
  baseUrl: string
  createdAt: string
  rootThumbprint: string
  rootSubject: string
  urls: { rootCertificate: string; intermediateCertificate: string; rootPem: string; chainPem: string; rootCrl: string; intermediateCrl: string }
  tsa: { url: string; authenticatedUrl: string; untrustedUrl: string; user: string; password: string }
  csc: {
    baseUrl: string
    clientId: string
    clientSecret: string
    serviceToken: string
    pin: string
    otp: string
    credentials: { id: string; description: string; certificateId: string; authMode: string; scal: string; multiSign: number }[]
  }
  pfxPassword: string
}

export interface CertificateView {
  id: string
  title: string
  description: string
  subject: string
  issuer: string
  serialNumber: string
  thumbprint: string
  notBefore: string
  notAfter: string
  keyType?: string | null
  problem?: string | null
  isUsable: boolean
  revokedAt?: string | null
  revocationReason?: string | null
}

export interface PkiView {
  root: CertificateView
  intermediate: CertificateView
  tsa: CertificateView
  untrustedTsa: CertificateView
  certificates: CertificateView[]
}

export type TsaFault = "None" | "Down" | "Slow" | "InvalidToken" | "Untrusted"
export type CrlFault = "None" | "Down" | "Slow" | "Expired"

export interface SandboxFaults {
  tsa: TsaFault
  tsaDelayMs: number
  crl: CrlFault
  crlDelayMs: number
}

export interface SandboxRequest {
  id: number
  time: string
  method: string
  path: string
  status: number
  service: string
  fault?: string | null
  ms: number
  client?: string | null
}

export const revocationReasons = ["KeyCompromise", "CACompromise", "AffiliationChanged", "Superseded", "CessationOfOperation", "CertificateHold", "PrivilegeWithdrawn"] as const
