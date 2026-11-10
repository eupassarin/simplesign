import type { CheckRow, CodeSnippets, CredentialFacts, DocumentFacts, OptionIssue, OptionState } from "@/lib/types"

// The workbench is drawn from the schema the server sends (/api/schema): the options, their
// explanations, the standards and the library calls are written once, in the backend.

export type Format = "pades" | "cades" | "xades"

export interface StandardRef {
  document: string
  clause: string
}

export interface SchemaValue {
  value: string
  title: string
  summary?: string | null
  details?: string | null
  standards: StandardRef[]
  api?: string | null
  support: "supported" | "notInLibrary"
}

export interface SchemaCondition {
  path: string
  in: string[]
}

export interface SchemaOption {
  id: string
  section: string
  formats: Format[]
  kind: string
  path?: string | null
  stateKey?: string | null
  valueStateKey?: string | null
  title: string
  summary: string
  details?: string | null
  values: SchemaValue[]
  standards: StandardRef[]
  api?: string | null
  support: "supported" | "notInLibrary"
  when: SchemaCondition[]
}

export interface SchemaSection {
  id: string
  title: string
  summary: string
}

export interface SchemaFormat {
  id: Format
  title: string
  summary: string
  standards: StandardRef[]
  signerApi: string
  validatorApi: string
}

export interface SchemaStage {
  id: string
  title: string
  summary: string
  standards: Record<Format, StandardRef[]>
}

export interface SchemaPreset {
  id: string
  title: string
  summary: string
  formats: Format[]
  set: Record<string, string>
}

export type Options = Record<string, unknown>

export interface WorkbenchSchema {
  formats: SchemaFormat[]
  sections: SchemaSection[]
  options: SchemaOption[]
  stages: SchemaStage[]
  presets: SchemaPreset[]
  defaults: Record<Format, Options>
}

/** The rules applied to the current options of a format (/api/workbench/options). */
export interface Evaluation {
  format: Format
  states: Record<string, OptionState>
  issues: OptionIssue[]
  canSign: boolean
  effectiveLevel: string
  effective: Options
  document?: DocumentFacts | null
  credential?: CredentialFacts | null
  inputs?: unknown
}

export interface RunLogEntry {
  seq: number
  ms: number
  level: "Trace" | "Debug" | "Information" | "Warning" | "Error" | "Critical"
  eventId: number
  source: "library" | "network" | "testbench"
  stage: string
  message: string
}

export interface RunVerdict {
  label: string
  signer?: string | null
  indication: "Valid" | "Invalid" | "Indeterminate"
  level?: string | null
  signingTime?: string | null
  checks: CheckRow[]
  errors: string[]
  warnings: string[]
  children: RunVerdict[]
  isTimestamp?: boolean
  /** The ETSI indication (EN 319 102-1 §5.1.3): TOTAL_PASSED, TOTAL_FAILED or INDETERMINATE. */
  etsiIndication?: string | null
  subIndication?: string | null
  /** The policy constraints that failed, warned or informed, one per constraint with all its messages. */
  findings?: Finding[] | null
}

export interface Finding {
  constraint: string
  title: string
  standard?: string | null
  status: "fail" | "warn" | "info"
  messages: string[]
}

export interface DssSignature {
  id?: string | null
  indication: string
  subIndication?: string | null
  format?: string | null
  signedBy?: string | null
  signingTime?: string | null
  errors: string[]
  warnings: string[]
}

export interface DssComparisonRow {
  label: string
  topic: "indication" | "level"
  library?: string | null
  dss?: string | null
  agree: boolean
  note?: string | null
  /** For a difference: what DSS concluded, in plain words. */
  reason?: string | null
  cause?: "setup" | "disagreement" | "unknown" | null
  action?: string | null
}

export interface DssComparison {
  available: boolean
  error?: string | null
  url: string
  ms: number
  agree: boolean
  signatures: DssSignature[]
  rows: DssComparisonRow[]
  notes: string[]
  reportId?: string | null
  /** One sentence: whether they agree, and on what they differ. */
  summary?: string | null
}

export interface DssSettings {
  enabled: boolean
  url: string
}

export interface DssStatus extends DssSettings {
  reachable: boolean
  error?: string | null
  ms: number
}

export type RunKind = "sign" | "validate"

/** How a run makes the signature: through the library, or by running the generated command through the simplesign CLI. */
export type RunEngine = "library" | "cli"

/** One command a CLI run executed (secrets kept as their $NAMES), its exit code and what it printed. */
export interface CliStep {
  command: string
  exitCode: number
  output: string
  ms: number
}

export interface RunView {
  id: string
  kind: RunKind
  engine?: RunEngine
  /** The commands of a run through the CLI. */
  cli?: CliStep[] | null
  format: Format
  status: "running" | "done" | "failed"
  startedAt: string
  totalMs: number
  options: Options
  success: boolean
  error?: string | null
  errorType?: string | null
  outputId?: string | null
  fileName?: string | null
  bytes: number
  requestedLevel?: string | null
  achievedLevel?: string | null
  warnings: string[]
  signMs: number
  validateMs: number
  code?: CodeSnippets | null
  issues: OptionIssue[]
  overall?: "Valid" | "Invalid" | "Indeterminate" | null
  validation: RunVerdict[]
  /** The format's own result (SigningResult, CadesSignResult or XmlSignResult). */
  detail?: unknown
  crossValidation?: DssComparison | null
  logs: RunLogEntry[]
  /** SimpleSign's JSON report of the verdicts (a stored file; open it in the report viewer). */
  reportId?: string | null
}

/** A validation report (SimpleSign's or DSS's), read by the server for the report viewer. */
export interface ReportView {
  source: "simplesign" | "dss"
  document?: string | null
  validationTime?: string | null
  policy?: string | null
  signatures: ReportSignature[]
}

export interface ReportSignature {
  id: string
  kind: "signature" | "counterSignature" | "timestamp"
  format?: string | null
  indication: "Valid" | "Invalid" | "Indeterminate"
  etsiIndication: string
  subIndication?: string | null
  /** The indication and sub-indication in plain words. */
  explanation: string
  signedBy?: string | null
  signingTime?: string | null
  bestSignatureTime?: string | null
  chain: ReportCertificate[]
  timestamps: ReportTimestamp[]
  revocation: ReportRevocation[]
  constraints: ReportConstraint[]
  errors: string[]
  warnings: string[]
  infos: string[]
}

export interface ReportCertificate {
  name: string
  subject?: string | null
  issuer?: string | null
  serialNumber?: string | null
  notBefore?: string | null
  notAfter?: string | null
  selfSigned: boolean
  trusted?: boolean | null
  revocationStatus?: string | null
}

export interface ReportTimestamp {
  time?: string | null
  type?: string | null
  producedBy?: string | null
  indication?: string | null
  subIndication?: string | null
}

export interface ReportRevocation {
  type: string
  indication?: string | null
  subIndication?: string | null
  producedAt?: string | null
  thisUpdate?: string | null
  nextUpdate?: string | null
  origin?: string | null
  url?: string | null
  certificate?: string | null
  status?: string | null
  /** Who issued it: the CRL issuer or the OCSP responder. */
  issuer?: string | null
}

export interface ReportConstraint {
  key: string
  title: string
  standard?: string | null
  status: "pass" | "warn" | "fail" | "info" | "skip"
  messages: string[]
  count: number
}

/** A file to try validation with, and the indication it should get. */
export interface ValidationSampleView {
  format: Format
  id: string
  fileId: string
  fileName: string
  dataId?: string | null
  title: string
  description: string
  expectedIndication?: string | null
}

export interface RunSummary {
  id: string
  kind: RunKind
  engine?: RunEngine
  format: Format
  status: "running" | "done" | "failed"
  startedAt: string
  totalMs: number
  success: boolean
  requestedLevel?: string | null
  achievedLevel?: string | null
  overall?: string | null
  fileName?: string | null
  error?: string | null
}

export interface RunEvent {
  type: "log" | "result"
  log?: RunLogEntry | null
  run?: RunView | null
}

/** What the Real environment has: how many roots validation can trust and the public TSAs with a preset. */
export interface RealEnvironment {
  systemRootCount: number
  publicTsas: { name: string; url: string; api: string }[]
}


/** Reads "timestamp.provider" from the options. */
export function getPath(options: Options, path: string): unknown {
  let node: unknown = options
  for (const part of path.split(".")) {
    if (typeof node !== "object" || node === null) return undefined
    node = (node as Options)[part]
  }
  return node
}

/** Returns a copy of the options with the value at the path replaced. */
export function setPath(options: Options, path: string, value: unknown): Options {
  const [head, ...rest] = path.split(".")
  if (rest.length === 0) return { ...options, [head]: value }
  const child = options[head]
  return { ...options, [head]: setPath(typeof child === "object" && child !== null ? (child as Options) : {}, rest.join("."), value) }
}

export function hasPath(options: Options, path: string): boolean {
  let node: unknown = options
  for (const part of path.split(".")) {
    if (typeof node !== "object" || node === null || !(part in (node as Options))) return false
    node = (node as Options)[part]
  }
  return true
}

/** The value as the conditions and choices compare it: enum names as they are, booleans as "true"/"false". */
export function asText(value: unknown): string {
  return value === null || value === undefined ? "" : String(value)
}
