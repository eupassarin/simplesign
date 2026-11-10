// Mirrors src/Apps/SimpleSign.Sandbox/Endpoints/AdminEndpoints.cs and Services/SandboxFaults.cs (camelCase JSON, enums as names).

export interface SandboxInfo {
  name: string
  version: string
  baseUrl: string
  httpsBaseUrl: string
  ldapBaseUrl: string
  createdAt: string
  rootThumbprint: string
  rootSubject: string
  urls: { rootCertificate: string; intermediateCertificate: string; rootPem: string; chainPem: string; rootCrl: string; intermediateCrl: string }
  authorities: { id: string; certificate: string; crl: string; httpsCrl: string; ldapCrl: string; ocsp: string }[]
  tsa: { url: string; authenticatedUrl: string; untrustedUrl: string; revokedUrl: string; wrongNameUrl: string; wrongName: string; user: string; password: string }
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
  loopbackOrigins: string[]
  trustedLists?: { lotlUrl: string; tlUrl: string; lotlSignerUrl: string; tlSignerUrl: string; territory: string } | null
}

export interface CertificateView {
  id: string
  title: string
  description: string
  subject: string
  issuer: string
  issuerId?: string | null
  serialNumber: string
  thumbprint: string
  notBefore: string
  notAfter: string
  keyType?: string | null
  usage?: "Signing" | "Timestamping" | "OcspSigning" | "TlsServer" | null
  pointers?: string | null
  problem?: string | null
  isUsable: boolean
  revokedAt?: string | null
  revocationReason?: string | null
  publication?: Publication | null
}

export type Publication = "Both" | "CrlOnly" | "OcspOnly"

export interface PkiView {
  authorities: CertificateView[]
  untrustedTsa: CertificateView
  certificates: CertificateView[]
}

export type TsaFault = "None" | "Down" | "Slow" | "InvalidToken" | "Untrusted"
export type CrlFault = "None" | "Down" | "Slow" | "Expired" | "WrongKey" | "Stale"
export type OcspFault = "None" | "Down" | "Slow" | "TryLater" | "Expired" | "Unauthorized" | "Unknown"
export type OcspSigner = "Issuer" | "Delegated"
export type TlFault = "None" | "Expired" | "WrongSigner" | "Tampered"

export interface SandboxFaults {
  tsa: TsaFault
  tsaDelayMs: number
  crl: CrlFault
  crlDelayMs: number
  ocsp: OcspFault
  ocspDelayMs: number
  ocspSigner: OcspSigner
  trustedList: TlFault
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
