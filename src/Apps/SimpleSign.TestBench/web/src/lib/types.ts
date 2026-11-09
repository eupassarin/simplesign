// Mirrors src/Apps/SimpleSign.TestBench/Signing/SigningOptions.cs and the API records (camelCase JSON, enums as names).

export type SignatureKind = "Baseline" | "CustomPolicy"
export type BaselineLevel = "BB" | "BT" | "BLT" | "BLTA"
export type TsaProvider = "Sandbox" | "SandboxAuthenticated" | "SandboxUntrusted" | "SandboxRevoked" | "SandboxWrongName" | "DigiCert" | "Sectigo" | "FreeTsa" | "Custom"
export type TsaAuth = "None" | "Basic" | "Bearer"
export type HashChoice = "Sha256" | "Sha384" | "Sha512" | "Sha3_256" | "Sha3_384" | "Sha3_512"
export type RsaPadding = "Pkcs1" | "Pss"
export type RevocationPreference = "OcspFirst" | "CrlFirst"
export type XadesCanonicalization = "Exclusive" | "Inclusive"
export type SubFilterChoice = "EtsiCadesDetached" | "AdbePkcs7Detached"
export type FieldMode = "New" | "Existing"
export type CertificationChoice = "None" | "NoChanges" | "FormFilling" | "FormFillingAndAnnotations"
export type RunMode = "Sign" | "Deferred" | "Batch"
export type CredentialKind = "SandboxA1" | "Pfx" | "OsStore" | "Pkcs11" | "Csc"

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

export interface SigningOptions {
  documentId?: string | null
  credentialId?: string | null
  kind: SignatureKind
  level: BaselineLevel
  customPolicy: { oid: string; hashAlgorithm: HashChoice; hashHex: string; uri?: string | null }
  timestamp: TimestampChoice
  separateArchiveTsa: boolean
  archiveTimestamp: TimestampChoice
  returnLowerLevel: boolean
  revocationPreference: RevocationPreference
  /** Uploaded signing policy (JSON); null: the library's default. */
  signingPolicyId?: string | null
  hash: HashChoice
  padding: RsaPadding
  subFilter: SubFilterChoice
  contentsReservedBytes?: number | null
  preservePdfA: boolean
  fieldMode: FieldMode
  fieldName: string
  existingFieldName?: string | null
  reason?: string | null
  location?: string | null
  contactInfo?: string | null
  signerName?: string | null
  signingTime?: string | null
  useSignerDetails: boolean
  metadata: MetadataChoice
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
  keyAlgorithm: string
  keySize: number
  notBefore: string
  notAfter: string
  isExpired: boolean
  isNotYetValid: boolean
  hasNonRepudiation: boolean
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

/** The connected SimpleSign Sandbox (src/Apps/SimpleSign.Sandbox). */
export interface SandboxInfo {
  url: string
  name: string
  rootSubject: string
  rootThumbprint: string
  loopbackOrigins: string[]
  signers: SandboxSigner[]
  tsaUrl: string
  authenticatedTsaUrl: string
  untrustedTsaUrl: string
  revokedTsaUrl: string
  wrongNameTsaUrl: string
  cscUrl: string
  cscPin: string
  cscOtp: string
  cscCredentials: CscCredentialSummary[]
}

export interface EnvironmentInfo {
  /** The connected Sandbox, or null. */
  sandbox: SandboxInfo | null
  /** Why the remembered Sandbox could not be connected. */
  sandboxError?: string | null
  rememberedSandboxUrl?: string | null
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

export interface CodeSnippets {
  cSharp: string
  cli: string
  cliNotes: string[]
}

export interface CheckRow {
  id: string
  name: string
  status: "pass" | "fail" | "warn" | "n/a"
  detail?: string | null
}

export interface SignatureReport {
  fieldName: string
  indication: "Valid" | "Invalid" | "Indeterminate"
  /** The ETSI EN 319 102-1 sub-indication (HASH_FAILURE, TRY_LATER…) when the result is not valid. */
  subIndication?: string | null
  isDocumentTimestamp: boolean
  signer?: string | null
  subFilter?: string | null
  digest?: string | null
  signingTime?: string | null
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

// ── Validation area ─────────────────────────────────────────────────
export type TrustChoice = "Sandbox" | "System"

export interface ValidationSettings {
  trust: TrustChoice[]
  customRootUploadIds: string[]
  timeoutSeconds: number
  /** Uploaded validation policy (JSON); null: the library's default. */
  policyId?: string | null
  level?: ValidationLevel
  revocationStrategy?: RevocationStrategy
}

export type ValidationLevel = "BasicSignatures" | "Timestamps" | "LongTermData" | "ArchivalData"
export type RevocationStrategy = "OcspFirst" | "CrlFirst"

export interface ValidationSample {
  id: string
  fileId: string
  title: string
  description: string
  expectedIndication: string
  expectedCheck: string
}

export interface CertificateView {
  subject: string
  issuer: string
  serialNumber: string
  notBefore: string
  notAfter: string
  keyAlgorithm: string
  keySize?: number | null
  hasNonRepudiation: boolean
  thumbprint: string
}

export interface DetailedSignature {
  report: SignatureReport
  padesLevel?: string | null
  signer?: CertificateView | null
  embeddedCertificates: CertificateView[]
  timestamp?: { time: string; tsa?: string | null; policyOid?: string | null; hashAlgorithm?: string | null; serialNumber?: string | null } | null
  coverage?: { signedUntil: number; fileSize: number; coversWholeFile: boolean; revision: number; revisions: number } | null
  signatureAlgorithm?: string | null
  deprecatedAlgorithm: boolean
  commitmentTypeOid?: string | null
  policyOid?: string | null
  reason?: string | null
  location?: string | null
  contactInfo?: string | null
}

export interface ValidationReport {
  fileId: string
  document: DocumentFacts
  overall: "Valid" | "Invalid" | "Indeterminate" | "NoSignatures" | "Error"
  signatures: DetailedSignature[]
  dss?: { certificates: number; crls: number; ocsps: number; hasVri: boolean; vriEntries: number; warnings: string[] } | null
  ms: number
  code: { cSharp: string; cli: string; cliNotes: string[] }
  error?: string | null
}

export interface BulkReport {
  items: { fileId: string; fileName: string; valid: number; total: number; overall: string; ms: number; error?: string | null }[]
  processed: number
  failed: number
  averageMs: number
  totalMs: number
}

export interface InspectionReport {
  fileId: string
  document: DocumentFacts
  revisions: number
  objects: {
    objectNumber: number
    label: string
    icon: string
    badges: string[]
    entries: { key: string; value: string; explanation?: string | null }[]
    references: number[]
    streamInfo?: string | null
    cmsContentType?: string | null
    cmsSigner?: string | null
  }[]
  signatureFields: string[]
  error?: string | null
}

// ── CAdES ───────────────────────────────────────────────────────────
export type CadesOperation = "Sign" | "CoSign" | "CounterSign"
export type CadesContentChoice = "Detached" | "Enveloped"
export type CadesKind = "Baseline" | "CustomPolicy"
export type CadesExtendedChoice = "None" | "CompleteReferences" | "ExtendedLong" | "Archive"

export interface CadesOptions {
  operation: CadesOperation
  dataId?: string | null
  existingSignatureId?: string | null
  signerIndex: number
  contentType: CadesContentChoice
  credentialId?: string | null
  kind: CadesKind
  level: BaselineLevel
  policyOid: string
  policyUri?: string | null
  policyDocumentId?: string | null
  policySpecification: string
  extendedForm: CadesExtendedChoice
  timestamp: TimestampChoice
  hash: HashChoice
  padding: RsaPadding
  signingTime?: string | null
  commitment?: string | null
  contentTimestamp: boolean
  revocationPreference: RevocationPreference
  /** Uploaded signing policy (JSON); null: the library's default. */
  signingPolicyId?: string | null
  signerCountry?: string | null
  signerLocality?: string | null
  signerPostalAddress: string[]
  signerRoles: string[]
  attributeCertificateId?: string | null
  signedAssertionId?: string | null
  mimeType?: string | null
  contentDescription?: string | null
  operationId?: string | null
  validate: boolean
  validation?: ValidationSettings | null
}

export interface CmsAttributeView {
  oid: string
  name: string
}

export interface CmsSignerView {
  index: number
  subject?: string | null
  issuer?: string | null
  serialNumber?: string | null
  digestAlgorithm: string
  signatureAlgorithm: string
  signingTime?: string | null
  policyOid?: string | null
  commitmentTypeOid?: string | null
  hasSignatureTimestamp: boolean
  hasArchiveTimestamp: boolean
  signedAttributes: CmsAttributeView[]
  unsignedAttributes: CmsAttributeView[]
  counterSignatures: CmsSignerView[]
}

export interface CmsFacts {
  fileId: string
  fileName: string
  size: number
  isDetached: boolean
  contentSize?: number | null
  contentType?: string | null
  certificates: number
  signers: CmsSignerView[]
  error?: string | null
}

export interface CadesOptionsResponse {
  report: {
    options: Record<string, OptionState>
    issues: OptionIssue[]
    effective: CadesOptions
    effectiveLevel: string
    canSign: boolean
  }
  inputs: { dataName?: string | null; existing?: CmsFacts | null; dataMatchesExisting?: boolean | null }
  credential?: CredentialFacts | null
}

export interface CadesSignerReport {
  index: number
  signer?: string | null
  indication: "Valid" | "Invalid" | "Indeterminate"
  /** The ETSI EN 319 102-1 sub-indication (HASH_FAILURE, TRY_LATER…) when the result is not valid. */
  subIndication?: string | null
  signingTime?: string | null
  checks: CheckRow[]
  errors: string[]
  warnings: string[]
  counterSignatures: CadesSignerReport[]
}

export interface CadesValidationView {
  overall: "Valid" | "Invalid" | "Indeterminate"
  signers: CadesSignerReport[]
  errors: string[]
  structure: CmsFacts
  ms: number
  code: SigningResult["code"]
}

export interface CadesSignResult {
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
  validation?: CadesValidationView | null
  code: SigningResult["code"]
  issues: OptionIssue[]
}

export interface CadesSample {
  id: string
  kind: "data" | "signature" | "validation"
  fileId: string
  fileName: string
  dataId?: string | null
  title: string
  description: string
  expectedIndication?: string | null
  expectedCheck?: string | null
}

// ── XML: XAdES ──────────────────────────────────────────────────────
export type XadesFormChoice = "Enveloped" | "Detached" | "Enveloping"
export type XadesKind = "Baseline" | "CustomPolicy"
export type XadesExtendedChoice = "None" | "CompleteReferences" | "ExtendedLong" | "Archive"

export interface XmlOptions {
  dataId?: string | null
  credentialId?: string | null
  form: XadesFormChoice
  dataUri: string
  kind: XadesKind
  level: BaselineLevel
  policyOid: string
  policyUri?: string | null
  policyDocumentId?: string | null
  policySpecification: string
  extendedForm: XadesExtendedChoice
  timestamp: TimestampChoice
  hash: HashChoice
  padding: RsaPadding
  counterSign: boolean
  counterSignatureId?: string | null
  dataObjectsTimestamp: boolean
  canonicalization: XadesCanonicalization
  signingCertificateV1: boolean
  signerRoles: string[]
  attributeCertificateId?: string | null
  signedAssertionId?: string | null
  embeddedObjectId?: string | null
  externalObjectId?: string | null
  mimeType?: string | null
  placeCity?: string | null
  placeStreet?: string | null
  placeState?: string | null
  placePostalCode?: string | null
  placeCountry?: string | null
  revocationPreference: RevocationPreference
  /** Uploaded signing policy (JSON); null: the library's default. */
  signingPolicyId?: string | null
  commitment?: string | null
  signingTime?: string | null
  operationId?: string | null
  validate: boolean
  validation?: ValidationSettings | null
}

export interface XmlFacts {
  fileId: string
  fileName: string
  size: number
  root?: string | null
  namespace?: string | null
  signatures: number
  error?: string | null
}

export interface XmlOptionsResponse {
  report: {
    options: Record<string, OptionState>
    issues: OptionIssue[]
    effective: XmlOptions
    effectiveLevel: string
    canSign: boolean
  }
  data?: XmlFacts | null
  credential?: CredentialFacts | null
}

export interface XmlSignatureReport {
  index: number
  reference?: string | null
  signer?: string | null
  indication: "Valid" | "Invalid" | "Indeterminate"
  /** The ETSI EN 319 102-1 sub-indication (HASH_FAILURE, TRY_LATER…) when the result is not valid. */
  subIndication?: string | null
  level?: string | null
  signingTime?: string | null
  checks: CheckRow[]
  errors: string[]
  warnings: string[]
}

export interface XmlValidationView {
  overall: "Valid" | "Invalid" | "Indeterminate"
  signatures: XmlSignatureReport[]
  errors: string[]
  signatureXml?: string | null
  documentPreview: string
  ms: number
  code: SigningResult["code"]
}

export interface XmlSignResult {
  success: boolean
  error?: string | null
  errorType?: string | null
  outputId?: string | null
  fileName?: string | null
  bytes: number
  requestedLevel: string
  achievedLevel?: string | null
  warnings: string[]
  signMs: number
  validation?: XmlValidationView | null
  code: SigningResult["code"]
  issues: OptionIssue[]
}

export interface XmlSample {
  id: string
  kind: "data" | "validation"
  fileId: string
  fileName: string
  dataId?: string | null
  title: string
  description: string
  expectedIndication?: string | null
  expectedCheck?: string | null
}

// ── Policy viewer ───────────────────────────────────────────────────
export type PolicyKind = "signing" | "validation"
export type PolicyLevel = "FAIL" | "WARN" | "INFORM" | "IGNORE"

export interface PolicyNodeView {
  name: string
  path: string
  kind: "section" | "crypto" | "constraint"
  level?: PolicyLevel | null
  explanation: string
  standard?: string | null
  evaluation: "evaluated" | "toConnect" | "toImplement" | "none"
  ids: string[]
  algorithms: { name: string; size?: number | null; date?: string | null }[]
  attributes: Record<string, string>
  children: PolicyNodeView[]
}

export interface PolicyView {
  kind: PolicyKind
  name?: string | null
  description?: string | null
  digest?: string | null
  json: string
  error?: string | null
  root?: PolicyNodeView | null
  counts?: { fail: number; warn: number; inform: number; ignore: number; evaluated: number; toConnect: number; toImplement: number } | null
  levels: Record<PolicyLevel, string>
}
