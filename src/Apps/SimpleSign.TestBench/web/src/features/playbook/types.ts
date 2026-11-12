// A playbook and its results, as the TestBench API sends them (Playbooks/*.cs).
import type { CodeSnippets, OptionIssue } from "@/lib/types"

export type PlaybookEngine = "library" | "cli" | "both"
export type PlaybookStatus = "pending" | "queued" | "running" | "passed" | "failed"

export interface PlaybookExpectation {
  outcome?: string | null
  reason?: string | null
  indication?: string | null
  subIndication?: string | null
  level?: string | null
  dssAgrees?: boolean | null
  etsiReport?: string | null
  failedConstraints?: string[]
  logContains: string[]
}

export interface PlaybookStep {
  id: string
  title: string
  description?: string | null
  tags: string[]
  kind: "sign" | "validate" | "augment"
  format?: string | null
  engine?: PlaybookEngine | null
  crossValidate?: boolean | null
  sandbox?: { crl?: string | null; ocsp?: string | null; tsa?: string | null; trustedList?: string | null; revoke: string[] } | null
  options?: unknown
  expect?: PlaybookExpectation | null
}

export interface PlaybookSection {
  id: string
  title: string
  description?: string | null
  steps: PlaybookStep[]
}

export interface Playbook {
  schema: number
  id: string
  title: string
  description?: string | null
  defaults: { engine: PlaybookEngine; format: string; crossValidate: boolean }
  sections: PlaybookSection[]
}

export interface PlaybookIssue {
  path: string
  message: string
  isError: boolean
}

export interface PlaybookLoaded {
  playbook?: Playbook | null
  issues: PlaybookIssue[]
  canRun: boolean
}

export interface PlaybookSample {
  id: string
  title: string
  description?: string | null
}

export interface PlaybookCheckRow {
  what: string
  expected: string
  found: string
  passed: boolean
}

export interface PlaybookEngineRun {
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
  crossValidated: boolean
  dssError?: string | null
  reportId?: string | null
  etsiReportId?: string | null
  ms: number
  checks: PlaybookCheckRow[]
  passed: boolean
}

export interface PlaybookStepResult {
  status: PlaybookStatus
  message?: string | null
  runs: PlaybookEngineRun[]
  ms: number
  at: string
}

export interface PlaybookStepView {
  sectionId: string
  stepId: string
  title: string
  kind: string
  tags: string[]
  status: PlaybookStatus
  result?: PlaybookStepResult | null
}

export interface PlaybookStateView {
  key?: string | null
  playbookId?: string | null
  title?: string | null
  running: boolean
  runningStep?: string | null
  version: number
  steps: PlaybookStepView[]
}

export interface PreviewItem {
  key: string
  label: string
  value: string
}

export interface PreviewSetting {
  id: string
  title: string
  value: string
  fromPlaybook: boolean
  changed: boolean
}

export interface PreviewGroup {
  id: string
  title: string
  settings: PreviewSetting[]
}

export interface PlaybookStepPreview {
  stepId: string
  kind: string
  format: string
  engine: string
  crossValidate: boolean
  crossValidateFrom: "step" | "defaults"
  target: PreviewItem[]
  signer: PreviewItem[]
  groups: PreviewGroup[]
  sandbox: PreviewItem[]
  expect: PreviewItem[]
  code?: CodeSnippets | null
  issues: OptionIssue[]
  needsSteps: string[]
  codeError?: string | null
}

/** What a step's sandbox block and sandbox:ID values can name (/api/playbook/sandbox). */
export interface PlaybookSandboxReference {
  connected: boolean
  signers: { id: string; title: string }[]
  certificates: { id: string; title: string }[]
  faults: Record<string, string[]>
}
