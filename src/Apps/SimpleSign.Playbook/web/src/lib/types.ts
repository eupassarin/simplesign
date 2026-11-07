// The Playbook app's API types (they mirror the C# records, camelCase).

export interface SandboxAction {
  sandbox: string
  certificate?: string | null
  reason?: string | null
  publication?: string | null
  id?: string | null
  as?: string | null
  seconds?: number | null
  crl?: string | null
  ocsp?: string | null
  tsa?: string | null
  ocspSigner?: string | null
}

export interface RunDefinition {
  args: string[]
  timeoutSeconds?: number
  network?: string | null
}

export interface SandboxRequestExpectation {
  service?: string | null
  pathContains?: string | null
  min?: number
  max?: number | null
}

export interface Expectation {
  exitCode?: number | null
  json?: Record<string, unknown>
  stdoutContains?: string[]
  stderrContains?: string[]
  stdoutMatches?: string[]
  files?: string[]
  sandboxRequests?: SandboxRequestExpectation[]
}

export interface StepDefinition {
  id: string
  title: string
  description?: string | null
  manual?: boolean
  setup?: SandboxAction[]
  run?: RunDefinition | null
  expect?: Expectation | null
  teardown?: SandboxAction[]
}

export interface SectionDefinition {
  id: string
  title: string
  description?: string | null
  steps: StepDefinition[]
}

export interface AssetDefinition {
  id: string
  file: string
  secret?: string | null
  description?: string | null
}

export interface PlaybookDefinition {
  schema: number
  name: string
  description?: string | null
  sandbox?: { url: string; resetBeforeRun: boolean } | null
  variables?: Record<string, string>
  assets?: AssetDefinition[]
  sections: SectionDefinition[]
}

export interface PlaybookIssue {
  path: string
  message: string
  isError: boolean
}

export interface CertificateView {
  subject: string
  issuer: string
  notBefore: string
  notAfter: string
  hasPrivateKey: boolean
  keyAlgorithm: string
  thumbprint: string
}

export interface AssetView {
  path: string
  bytes: number
  modified: string
  certificate?: CertificateView | null
  certificateProblem?: string | null
}

export type Status = "pending" | "running" | "waiting" | "passed" | "failed" | "error" | "skipped" | "cancelled"

export interface RunSummary {
  total: number
  passed: number
  failed: number
  errors: number
  skipped: number
  pending: number
}

export interface RunListItem {
  id: string
  playbookName: string
  startedAt: string
  finishedAt?: string | null
  status: Status
  summary: RunSummary
}

export interface CheckResult {
  name: string
  passed: boolean
  expected: string
  actual: string
}

export interface SandboxRequestRecord {
  id: number
  time: string
  method: string
  path: string
  status: number
  service: string
  fault?: string | null
  ms: number
}

export interface StepRecord {
  sectionId: string
  sectionTitle: string
  stepId: string
  title: string
  description?: string | null
  manual: boolean
  status: Status
  startedAt?: string | null
  durationMs?: number | null
  actions: string[]
  command?: string | null
  exitCode?: number | null
  timedOut: boolean
  checks: CheckResult[]
  sandboxRequests: SandboxRequestRecord[]
  files: string[]
  error?: string | null
  note?: string | null
  attachments: string[]
}

export interface RunRecord {
  id: string
  playbookName: string
  playbookHash: string
  startedAt: string
  finishedAt?: string | null
  status: Status
  error?: string | null
  machine: string
  user: string
  cli: string
  cliVersion?: string | null
  sandbox?: { url: string; name: string; version: string; rootSubject: string; rootThumbprint: string } | null
  selection?: string[] | null
  steps: StepRecord[]
  summary: RunSummary
}

export interface RunEvent {
  type: "run" | "step" | "line"
  run?: RunRecord
  step?: StepRecord
  stepId?: string
  stream?: "stdout" | "stderr"
  text?: string
}

export interface WorkspaceView {
  path: string
  playbookText: string
  playbook?: PlaybookDefinition | null
  issues: PlaybookIssue[]
  assets: AssetView[]
  secretKeys: string[]
  runs: RunListItem[]
  activeRunId?: string | null
}

export interface SampleView {
  id: string
  name: string
  description?: string | null
}

export interface WorkspacesView {
  current?: string | null
  recent: string[]
  samples: SampleView[]
  defaultFolder: string
}

export interface SettingsView {
  cliCommand?: string | null
  cliPrefix: string[]
  resolvedProgram: string
  resolvedPrefix: string[]
}

export interface CliCheck {
  ok: boolean
  commandLine: string
  output: string
}

export interface SandboxCertificate {
  id: string
  title: string
  description: string
  subject: string
  problem?: string | null
  revokedAt?: string | null
}

export interface SandboxStatus {
  ok: boolean
  url: string
  info?: { name: string; version: string; baseUrl: string; rootSubject: string; rootThumbprint: string; loopbackOrigins: string[] } | null
  certificates: SandboxCertificate[]
  error?: string | null
}
