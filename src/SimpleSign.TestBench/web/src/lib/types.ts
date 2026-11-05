// Mirrors src/SimpleSign.TestBench/Signing/SigningOptions.cs and the API records (camelCase JSON, enums as names).

export type EnvironmentMode = "Sandbox" | "Real"
export type SignatureKind = "Baseline" | "IcpBrasil" | "CustomPolicy"
export type BaselineLevel = "BB" | "BT" | "BLT" | "BLTA"
export type IcpPolicyKind = "AdRb" | "AdRt" | "AdRc" | "AdRa"
export type TsaProvider = "Sandbox" | "SandboxAuthenticated" | "DigiCert" | "Sectigo" | "FreeTsa" | "Custom"
export type TsaAuth = "None" | "Basic" | "Bearer"
export type HashChoice = "Sha256" | "Sha384" | "Sha512" | "Sha3_256" | "Sha3_384" | "Sha3_512"
export type RsaPadding = "Pkcs1" | "Pss"
export type SubFilterChoice = "EtsiCadesDetached" | "AdbePkcs7Detached" | "PbadPades"
export type FieldMode = "New" | "Existing"
export type CertificationChoice = "None" | "NoChanges" | "FormFilling" | "FormFillingAndAnnotations"
export type SignerDetailsKind = "Metadata" | "Aea"
export type RunMode = "Sign" | "Deferred" | "Batch"
export type CredentialKind = "SandboxA1" | "Pfx" | "OsStore" | "Pkcs11" | "Psc" | "Csc"

export interface TimestampChoice {
  provider: TsaProvider
  url?: string | null
  auth: TsaAuth
  user?: string | null
  password?: string | null
  token?: string | null
  clientCertificateUploadId?: string | null
  clientCertificatePassword?: string | null
}

export interface AppearanceChoice {
  visible: boolean
  autoPosition: boolean
  page: number
  x: number
  y: number
  width: number | null
  height: number | null
  textAlignment: "Left" | "Center" | "Right"
  verticalAlignment: "Top" | "Middle" | "Bottom"
  shrinkToFit: boolean
  maxTextLength: number
  showDate: boolean
  showReason: boolean
  showLocation: boolean
  signedByLabel?: string | null
  reasonLabel?: string | null
  locationLabel?: string | null
  dateLabel?: string | null
  signerDisplayName?: string | null
  extraLines: string[]
  dateFormat?: string | null
  timeZoneId?: string | null
  culture?: string | null
  backgroundColor?: string | null
  textColor?: string | null
  borderColor?: string | null
  borderWidth: number
  baseFont: string
  fontSize?: number | null
  labelFontSize?: number | null
  verificationUrl?: string | null
  imageUploadId?: string | null
  imageFit: "Stretch" | "Contain" | "Cover"
}

export interface MetadataChoice {
  signerName?: string | null
  signerId?: string | null
  signerIdType?: string | null
  email?: string | null
  ipAddress?: string | null
  authenticationMethod?: string | null
  institutionName?: string | null
  institutionId?: string | null
  institutionIdType?: string | null
  commitmentType: string
  legalBasis?: string | null
  policyOid?: string | null
  policyUri?: string | null
}

export interface AeaChoice {
  signerName: string
  cpf: string
  authMethod: string
  email?: string | null
  ipAddress?: string | null
  commitmentType: string
  institutionName?: string | null
  institutionCnpj?: string | null
  policyOid?: string | null
  policyUri?: string | null
}

export interface ProfessionalChoice {
  council: string
  registrationNumber: string
  stateCode?: string | null
  specialty?: string | null
}

export interface SigningOptions {
  environment: EnvironmentMode
  documentId?: string | null
  credentialId?: string | null
  kind: SignatureKind
  level: BaselineLevel
  icpPolicy: IcpPolicyKind
  icpVersionOid?: string | null
  icpAdRbTimestamp: boolean
  customPolicy: { oid: string; hashAlgorithm: HashChoice; hashHex: string; uri?: string | null }
  timestamp: TimestampChoice
  separateArchiveTsa: boolean
  archiveTimestamp: TimestampChoice
  returnLowerLevel: boolean
  hash: HashChoice
  padding: RsaPadding
  subFilter: SubFilterChoice
  contentsReservedBytes?: number | null
  preservePdfA: boolean
  fieldMode: FieldMode
  fieldName: string
  existingFieldName?: string | null
  appearance: AppearanceChoice
  reason?: string | null
  location?: string | null
  contactInfo?: string | null
  signerName?: string | null
  signingTime?: string | null
  useSignerDetails: boolean
  signerDetails: SignerDetailsKind
  metadata: MetadataChoice
  aea: AeaChoice
  health: { enabled: boolean; type: string; professionals: ProfessionalChoice[] }
  certification: CertificationChoice
  documentInfo: { key: string; value: string }[]
  operationId?: string | null
  mode: RunMode
  batchCopies: number
  maxConcurrency: number
  validate: boolean
}

export interface OptionState {
  visible: boolean
  disabled?: string | null
  note?: string | null
}

export type IssueSeverity = "Info" | "Warning" | "Error"

export interface OptionIssue {
  severity: IssueSeverity
  step: string
  message: string
}

export interface OptionsReport {
  options: Record<string, OptionState>
  issues: OptionIssue[]
  effective: SigningOptions
  effectiveLevel: string
  canSign: boolean
}

export interface ExistingSignature {
  fieldName: string
  subFilter?: string | null
  signer?: string | null
  isDocumentTimestamp: boolean
}

export interface DocumentFacts {
  id: string
  title: string
  fileName: string
  size: number
  pdfVersion: string
  pdfALevel: string
  isPdfA: boolean
  isPdfA1: boolean
  isEncrypted: boolean
  docMdpLevel: number
  signatures: ExistingSignature[]
  emptyFields: string[]
  error?: string | null
}

export interface CredentialFacts {
  id: string
  kind: CredentialKind
  source: string
  holder: string
  subject: string
  issuer: string
  cpf?: string | null
  cnpj?: string | null
  keyAlgorithm: string
  keySize: number
  notBefore: string
  notAfter: string
  isExpired: boolean
  isNotYetValid: boolean
  hasNonRepudiation: boolean
  chainsToIcpBrasil: boolean
  hashes: HashChoice[]
  paddings: RsaPadding[]
  canSignHashLocally: boolean
  notes: string[]
  certificateBase64: string
}

export interface OptionsResponse {
  report: OptionsReport
  document?: DocumentFacts | null
  credential?: CredentialFacts | null
}

export interface OptionInfo {
  title: string
  summary: string
  details?: string | null
  spec?: string | null
  api?: string | null
}

export interface SandboxSigner {
  id: string
  title: string
  description: string
  keyType: string
  isUsable: boolean
  problem?: string | null
  holder: string
  notAfter: string
}

export interface CscCredentialSummary {
  id: string
  holder: string
  authMode: string
  scal: string
  multiSign: number
  algorithms: string[]
  enabled: boolean
}

export interface EnvironmentInfo {
  signers: SandboxSigner[]
  tsaUrl: string
  authenticatedTsaUrl: string
  tsaUser: string
  tsaPassword: string
  pscUrl: string
  pscCpf: string
  pscOtp: string
  cscUrl: string
  cscPin: string
  cscOtp: string
  cscCredentials: CscCredentialSummary[]
  runtime: string
  sha3Supported: boolean
  version: string
}

export interface SampleDocument {
  id: string
  title: string
  description: string
  facts: DocumentFacts
}

export interface IcpVersion {
  oid: string
  version: string
  notBefore: string
  notAfter: string
  revokedAt?: string | null
  inForce: boolean
  isAutomatic: boolean
  disabled?: string | null
  acceptedRoots: string[]
  requirements: string[]
  uri: string
}

export interface CheckRow {
  name: string
  status: "pass" | "fail" | "warn" | "n/a"
  detail?: string | null
}

export interface SignatureReport {
  fieldName: string
  indication: "Valid" | "Invalid" | "Indeterminate"
  isDocumentTimestamp: boolean
  signer?: string | null
  subFilter?: string | null
  digest?: string | null
  signingTime?: string | null
  policyLevel?: string | null
  signerId?: string | null
  checks: CheckRow[]
  errors: string[]
  warnings: string[]
  metadata?: Record<string, string> | null
}

export interface SigningResult {
  success: boolean
  error?: string | null
  errorType?: string | null
  outputId?: string | null
  fileName?: string | null
  bytes: number
  requestedLevel: string
  achievedLevel?: string | null
  hasSignatureTimestamp: boolean
  hasLongTermValidation: boolean
  hasArchiveTimestamp: boolean
  warnings: string[]
  signMs: number
  validateMs: number
  validation: SignatureReport[]
  output?: {
    signatureCount: number
    detectedLevel?: string | null
    hasDss: boolean
    dssCertificates: number
    dssCrls: number
    dssOcsps: number
    pdfALevel?: string | null
    docMdpLevel: number
  } | null
  deferred?: { hashToSignHex: string; digestAlgorithm: string; signatureAlgorithmOid: string; sessionBytes: number; rawSignatureHex: string } | null
  batch: { id: string; ok: boolean; error?: string | null; outputId?: string | null; bytes: number }[]
  code: { cSharp: string; cli: string; cliNotes: string[] }
  issues: OptionIssue[]
}

export interface StoreCertificate {
  thumbprint: string
  holder: string
  issuer: string
  notAfter: string
  hasPrivateKey: boolean
}

export interface Pkcs11Driver {
  driver: string
  libraryPath: string
  error?: string | null
  tokens: {
    libraryPath: string
    driver: string
    tokenLabel: string
    tokenSerial: string
    hasPinPad: boolean
    pinLocked: boolean
    certificates: StoreCertificate[]
  }[]
}

export interface MatrixCase {
  id: string
  group: string
  values: Record<string, string>
}

export interface MatrixCaseResult extends MatrixCase {
  status: "pass" | "fail" | "skip"
  ms: number
  detail?: string | null
  achievedLevel?: string | null
  checks: string[]
}

export interface MatrixRunResult {
  total: number
  passed: number
  failed: number
  skipped: number
  ms: number
  uncoverablePairs: number
  cases: MatrixCaseResult[]
}

export interface SandboxRequest {
  time: string
  method: string
  url: string
  status: number
  service: string
}
