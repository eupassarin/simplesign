// The certification script and its runs, as the TestBench API sends them (Scripts/*.cs).

export type ScriptEngine = "library" | "cli" | "both"
export type ScriptStatus = "pending" | "running" | "waiting" | "passed" | "failed" | "skipped" | "notApplicable" | "done" | "cancelled"

export interface ScriptRequirement {
  id: string
  group?: string | null
  text: string
  reference?: string | null
  applies: boolean
  justification?: string | null
}

export interface ScriptExpectation {
  outcome?: string | null
  reason?: string | null
  indication?: string | null
  subIndication?: string | null
  level?: string | null
  dssAgrees?: boolean | null
  logContains: string[]
}

export interface ScriptStep {
  id: string
  title: string
  description?: string | null
  kind: "sign" | "validate" | "manual"
  requirements: string[]
  format?: string | null
  engine?: ScriptEngine | null
  crossValidate?: boolean | null
  sandbox?: { crl?: string | null; ocsp?: string | null; tsa?: string | null; trustedList?: string | null; revoke: string[] } | null
  options?: unknown
  expect?: ScriptExpectation | null
  manual?: { instructions: string; attachment: boolean } | null
}

export interface ScriptSection {
  id: string
  title: string
  description?: string | null
  steps: ScriptStep[]
}

export interface CertificationScript {
  schema: number
  id: string
  title: string
  authority?: string | null
  standard?: string | null
  description?: string | null
  language: string
  defaults: { engine: ScriptEngine; format: string; crossValidate: boolean }
  requirements: ScriptRequirement[]
  sections: ScriptSection[]
}

export interface ScriptIssue {
  path: string
  message: string
  isError: boolean
}

export interface ScriptLoaded {
  script?: CertificationScript | null
  issues: ScriptIssue[]
  canRun: boolean
}

export interface ScriptSample {
  id: string
  title: string
  authority?: string | null
}

export interface ScriptCheckRow {
  what: string
  expected: string
  found: string
  passed: boolean
}

export interface ScriptEngineRun {
  engine: string
  runId: string
  success: boolean
  error?: string | null
  errorType?: string | null
  outputId?: string | null
  fileName?: string | null
  achievedLevel?: string | null
  indication?: string | null
  subIndication?: string | null
  dssAgrees?: boolean | null
  reportId?: string | null
  etsiReportId?: string | null
  ms: number
  checks: ScriptCheckRow[]
  passed: boolean
}

export interface ScriptStepView {
  sectionId: string
  stepId: string
  title: string
  kind: string
  requirements: string[]
  status: ScriptStatus
  message?: string | null
  runs: ScriptEngineRun[]
  note?: string | null
  attachments: { id: string; fileName: string }[]
  ms: number
}

export interface ScriptRequirementView {
  id: string
  group?: string | null
  text: string
  applies: boolean
  justification?: string | null
  status: ScriptStatus
  steps: string[]
}

export interface ScriptRunView {
  id: string
  scriptId: string
  title: string
  language: string
  status: ScriptStatus
  startedAt: string
  endedAt?: string | null
  version: number
  waitingFor?: string | null
  steps: ScriptStepView[]
  requirements: ScriptRequirementView[]
}
