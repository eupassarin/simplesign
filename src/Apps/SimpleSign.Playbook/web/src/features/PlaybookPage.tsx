import { useEffect, useMemo, useState } from "react"
import { ArrowDown, ArrowUp, ChevronRight, CircleAlert, ExternalLink, Plus, Save, Trash2, TriangleAlert } from "lucide-react"
import { toast } from "sonner"
import { Pill, Section } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Switch } from "@/components/ui/switch"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useI18n, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import type {
  Expectation, PlaybookDefinition, PlaybookIssue, SandboxAction, SandboxStatus, SectionDefinition, StepDefinition, WorkspaceView,
} from "@/lib/types"

const lines = (text: string) => text.split("\n").map((l) => l.trim()).filter(Boolean)
const pairs = (text: string) => Object.fromEntries(lines(text).map((l) => {
  const at = l.indexOf("=")
  return at < 0 ? [l, ""] : [l.slice(0, at).trim(), l.slice(at + 1).trim()]
}))
const unpairs = (record: Record<string, unknown> | undefined, json = false) =>
  Object.entries(record ?? {}).map(([k, v]) => `${k} = ${json ? JSON.stringify(v) : String(v)}`).join("\n")

/** The playbook: a form and the raw JSON, both editing the same text, checked by the server as you type. */
export function PlaybookPage({ workspace, onChanged }: { workspace: WorkspaceView; onChanged: (w: WorkspaceView) => void }) {
  const { t } = useI18n()
  const [text, setText] = useState(workspace.playbookText)
  const [issues, setIssues] = useState<PlaybookIssue[]>(workspace.issues)
  const [tab, setTab] = useState("form")
  const dirty = text !== workspace.playbookText
  const parsed = useMemo<PlaybookDefinition | null>(() => {
    try {
      return JSON.parse(text) as PlaybookDefinition
    } catch {
      return null
    }
  }, [text])

  useEffect(() => setText(workspace.playbookText), [workspace.playbookText])
  useEffect(() => {
    const timer = setTimeout(() => {
      api.checkPlaybook(text).then((r) => setIssues(r.issues)).catch(() => { /* keep the last result */ })
    }, 400)
    return () => clearTimeout(timer)
  }, [text])

  const update = (next: PlaybookDefinition) => setText(JSON.stringify(next, null, 2))
  const save = async () => {
    try {
      onChanged(await api.savePlaybook(text))
      toast.success(t("common.saved"))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const errors = issues.filter((i) => i.isError)
  return (
    <div className="grid gap-6 xl:grid-cols-[1fr_320px]">
      <Tabs value={tab} onValueChange={setTab} className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <TabsList>
            <TabsTrigger value="form">{t("playbook.form")}</TabsTrigger>
            <TabsTrigger value="json">{t("playbook.json")}</TabsTrigger>
          </TabsList>
          {dirty && <Pill tone="warning">{t("playbook.unsaved")}</Pill>}
          <Button size="sm" className="ml-auto" disabled={!dirty} onClick={save}><Save /> {t("common.save")}</Button>
        </div>
        <TabsContent value="form" className="pt-4">
          {parsed ? <PlaybookForm playbook={parsed} onChange={update} /> : <p className="text-destructive text-sm">{t("playbook.invalidJson")}</p>}
        </TabsContent>
        <TabsContent value="json" className="pt-4">
          <Textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false}
            onKeyDown={(e) => { if ((e.metaKey || e.ctrlKey) && e.key === "s") { e.preventDefault(); void save() } }}
            className="min-h-[70vh] font-mono text-xs leading-relaxed" />
        </TabsContent>
      </Tabs>
      <aside className="space-y-3">
        <h3 className="text-sm font-semibold">{t("playbook.issues")}</h3>
        {issues.length === 0 ? <p className="text-muted-foreground text-sm">{t("playbook.noIssues")}</p> : (
          <ul className="space-y-2">
            {issues.map((i, n) => (
              <li key={n} className="flex gap-2 text-xs">
                {i.isError ? <CircleAlert className="text-destructive mt-0.5 size-3.5 shrink-0" /> : <TriangleAlert className="text-warning mt-0.5 size-3.5 shrink-0" />}
                <span><span className="font-mono">{i.path || "/"}</span> — {i.message}</span>
              </li>
            ))}
          </ul>
        )}
        {errors.length > 0 && <p className="text-muted-foreground text-xs">{t("playbook.errorsStopRun")}</p>}
        <p className="text-muted-foreground text-xs">{t("playbook.variablesAvailable")}</p>
      </aside>
    </div>
  )
}

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div className="space-y-1">
      <Label className="text-xs">{label}</Label>
      {children}
      {hint && <p className="text-muted-foreground text-xs">{hint}</p>}
    </div>
  )
}

function PlaybookForm({ playbook, onChange }: { playbook: PlaybookDefinition; onChange: (p: PlaybookDefinition) => void }) {
  const { t } = useI18n()
  const sections = playbook.sections ?? []
  const set = (patch: Partial<PlaybookDefinition>) => onChange({ ...playbook, ...patch })
  const setSection = (index: number, section: SectionDefinition | null) =>
    set({ sections: section ? sections.map((s, i) => (i === index ? section : s)) : sections.filter((_, i) => i !== index) })
  const move = (index: number, by: number) => {
    const next = [...sections]
    const [item] = next.splice(index, 1)
    next.splice(index + by, 0, item)
    set({ sections: next })
  }
  return (
    <div className="space-y-8">
      <Section title={t("playbook.general")}>
        <div className="grid gap-3">
          <Field label={t("playbook.name")}><Input value={playbook.name ?? ""} onChange={(e) => set({ name: e.target.value })} /></Field>
          <Field label={t("playbook.description")}><Textarea rows={2} value={playbook.description ?? ""} onChange={(e) => set({ description: e.target.value || null })} /></Field>
        </div>
      </Section>
      <SandboxForm playbook={playbook} onChange={onChange} />
      <Section title={t("playbook.variables")} description={t("playbook.variablesHint")}>
        <LinesArea value={unpairs(playbook.variables)} onChange={(v) => set({ variables: pairs(v) as Record<string, string> })} rows={3} />
      </Section>
      <Section title={t("playbook.assets")} description={t("playbook.assetsHint")}>
        <LinesArea rows={3}
          value={(playbook.assets ?? []).map((a) => `${a.id} = ${a.file}${a.secret ? ` = ${a.secret}` : ""}`).join("\n")}
          onChange={(v) => set({
            assets: lines(v).map((l) => {
              const [id, file, secret] = l.split("=").map((p) => p.trim())
              return { id, file: file ?? "", secret: secret || null }
            }),
          })} />
      </Section>
      <Section title={t("playbook.sections")}
        aside={<Button size="sm" variant="outline" onClick={() => set({ sections: [...sections, { id: `section-${sections.length + 1}`, title: "", steps: [] }] })}><Plus /> {t("playbook.addSection")}</Button>}>
        <div className="space-y-4">
          {sections.map((section, index) => (
            <div key={index} className="space-y-3 rounded-lg border p-4">
              <div className="flex flex-wrap items-end gap-2">
                <div className="w-40"><Field label={t("playbook.sectionId")}><Input className="font-mono" value={section.id} onChange={(e) => setSection(index, { ...section, id: e.target.value })} /></Field></div>
                <div className="min-w-48 flex-1"><Field label={t("playbook.sectionTitle")}><Input value={section.title} onChange={(e) => setSection(index, { ...section, title: e.target.value })} /></Field></div>
                <Button variant="ghost" size="icon" disabled={index === 0} onClick={() => move(index, -1)} aria-label={t("common.up")}><ArrowUp /></Button>
                <Button variant="ghost" size="icon" disabled={index === sections.length - 1} onClick={() => move(index, 1)} aria-label={t("common.down")}><ArrowDown /></Button>
                <Button variant="ghost" size="icon" onClick={() => setSection(index, null)} aria-label={t("common.remove")}><Trash2 /></Button>
              </div>
              <StepsForm steps={section.steps ?? []} hasSandbox={!!playbook.sandbox} onChange={(steps) => setSection(index, { ...section, steps })} />
            </div>
          ))}
        </div>
      </Section>
    </div>
  )
}

function LinesArea({ value, onChange, rows = 3, placeholder }: { value: string; onChange: (v: string) => void; rows?: number; placeholder?: string }) {
  // Keeps its own text while typing (blank lines, half-written pairs) and reports every change.
  const [draft, setDraft] = useState(value)
  useEffect(() => setDraft((d) => (lines(d).join("\n") === lines(value).join("\n") ? d : value)), [value])
  return <Textarea rows={rows} value={draft} placeholder={placeholder} className="font-mono text-xs" spellCheck={false}
    onChange={(e) => { setDraft(e.target.value); onChange(e.target.value) }} />
}

function SandboxForm({ playbook, onChange }: { playbook: PlaybookDefinition; onChange: (p: PlaybookDefinition) => void }) {
  const { t } = useI18n()
  const [status, setStatus] = useState<SandboxStatus | null>(null)
  const sandbox = playbook.sandbox
  return (
    <Section title={t("playbook.sandbox")} description={t("playbook.sandboxHint")}>
      <label className="flex items-center gap-2 text-sm">
        <Switch checked={!!sandbox} onCheckedChange={(on) => onChange({ ...playbook, sandbox: on ? { url: "http://localhost:5300/", resetBeforeRun: true } : null })} />
        {t("playbook.useSandbox")}
      </label>
      {sandbox && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-64 flex-1"><Field label={t("playbook.sandboxUrl")}><Input className="font-mono" value={sandbox.url} onChange={(e) => onChange({ ...playbook, sandbox: { ...sandbox, url: e.target.value } })} /></Field></div>
            <Button variant="outline" onClick={() => api.sandbox(sandbox.url).then(setStatus).catch((e: Error) => toast.error(e.message))}>{t("sandbox.check")}</Button>
            <Button variant="ghost" asChild><a href={sandbox.url} target="_blank" rel="noreferrer"><ExternalLink /> {t("sandbox.open")}</a></Button>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={sandbox.resetBeforeRun} onCheckedChange={(on) => onChange({ ...playbook, sandbox: { ...sandbox, resetBeforeRun: on } })} />
            {t("playbook.resetBeforeRun")}
          </label>
          {status && (status.ok && status.info ? (
            <div className="space-y-1 text-sm">
              <Pill tone="success">{t("sandbox.ok", { name: status.info.name, version: status.info.version })}</Pill>
              <p className="text-muted-foreground text-xs">{t("sandbox.root")}: {status.info.rootSubject}</p>
              <p className="text-muted-foreground text-xs">{t("sandbox.certificates")}: <span className="font-mono">{status.certificates.map((c) => c.id).join(", ")}</span></p>
            </div>
          ) : <Pill tone="danger">{t("sandbox.unreachable")}: {status.error}</Pill>)}
        </div>
      )}
    </Section>
  )
}

function StepsForm({ steps, hasSandbox, onChange }: { steps: StepDefinition[]; hasSandbox: boolean; onChange: (s: StepDefinition[]) => void }) {
  const { t } = useI18n()
  const setStep = (index: number, step: StepDefinition | null) =>
    onChange(step ? steps.map((s, i) => (i === index ? step : s)) : steps.filter((_, i) => i !== index))
  const move = (index: number, by: number) => {
    const next = [...steps]
    const [item] = next.splice(index, 1)
    next.splice(index + by, 0, item)
    onChange(next)
  }
  return (
    <div className="space-y-2">
      {steps.length === 0 && <p className="text-muted-foreground text-sm">{t("playbook.noSteps")}</p>}
      {steps.map((step, index) => (
        <Collapsible key={index} className="rounded-md border">
          <div className="flex items-center gap-1 px-2 py-1">
            <CollapsibleTrigger className="group flex min-w-0 flex-1 items-center gap-2 py-1 text-left text-sm">
              <ChevronRight className="size-4 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
              <span className="font-mono text-xs">{step.id}</span>
              <span className="truncate">{step.title}</span>
              {step.manual && <Pill>{t("playbook.manual").split(" (")[0]}</Pill>}
            </CollapsibleTrigger>
            <Button variant="ghost" size="icon" className="size-7" disabled={index === 0} onClick={() => move(index, -1)} aria-label={t("common.up")}><ArrowUp className="size-3.5" /></Button>
            <Button variant="ghost" size="icon" className="size-7" disabled={index === steps.length - 1} onClick={() => move(index, 1)} aria-label={t("common.down")}><ArrowDown className="size-3.5" /></Button>
            <Button variant="ghost" size="icon" className="size-7" onClick={() => setStep(index, null)} aria-label={t("common.remove")}><Trash2 className="size-3.5" /></Button>
          </div>
          <CollapsibleContent className="border-t p-3">
            <StepForm step={step} hasSandbox={hasSandbox} onChange={(s) => setStep(index, s)} />
          </CollapsibleContent>
        </Collapsible>
      ))}
      <Button size="sm" variant="ghost" onClick={() => onChange([...steps, { id: `step-${Date.now() % 100000}`, title: "", run: { args: ["version"] }, expect: { exitCode: 0 } }])}>
        <Plus /> {t("playbook.addStep")}
      </Button>
    </div>
  )
}

function StepForm({ step, hasSandbox, onChange }: { step: StepDefinition; hasSandbox: boolean; onChange: (s: StepDefinition) => void }) {
  const { t } = useI18n()
  const set = (patch: Partial<StepDefinition>) => onChange({ ...step, ...patch })
  const run = step.run ?? { args: [] }
  const expect: Expectation = step.expect ?? {}
  const setExpect = (patch: Partial<Expectation>) => set({ expect: { ...expect, ...patch } })
  return (
    <div className="space-y-4">
      <div className="grid gap-3 sm:grid-cols-[160px_1fr]">
        <Field label={t("playbook.stepId")}><Input className="font-mono" value={step.id} onChange={(e) => set({ id: e.target.value })} /></Field>
        <Field label={t("playbook.stepTitle")}><Input value={step.title} onChange={(e) => set({ title: e.target.value })} /></Field>
      </div>
      <Field label={t("playbook.stepDescription")}><Textarea rows={2} value={step.description ?? ""} onChange={(e) => set({ description: e.target.value || null })} /></Field>
      <label className="flex items-center gap-2 text-sm">
        <Switch checked={!!step.manual} onCheckedChange={(on) => set({ manual: on, run: on ? null : (step.run ?? { args: [] }) })} />
        {t("playbook.manual")}
      </label>
      {hasSandbox && !step.manual && <ActionsForm title={t("playbook.setup")} actions={step.setup ?? []} onChange={(setup) => set({ setup })} />}
      {!step.manual && (
        <div className="space-y-3">
          <h4 className="text-sm font-medium">{t("playbook.run")}</h4>
          <Field label={t("playbook.args")}>
            <LinesArea rows={4} value={run.args.join("\n")} onChange={(v) => set({ run: { ...run, args: lines(v) } })} placeholder={"sign\n${asset.contract}\n--json"} />
          </Field>
          <div className="flex flex-wrap gap-3">
            <div className="w-32"><Field label={t("playbook.timeout")}>
              <Input type="number" min={1} max={3600} value={run.timeoutSeconds ?? 120} onChange={(e) => set({ run: { ...run, timeoutSeconds: Number(e.target.value) || 120 } })} />
            </Field></div>
            {hasSandbox && (
              <div className="w-56"><Field label={t("playbook.network")}>
                <Select value={run.network ?? "sandbox"} onValueChange={(v) => set({ run: { ...run, network: v === "sandbox" ? null : v } })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sandbox">{t("playbook.networkSandbox")}</SelectItem>
                    <SelectItem value="none">{t("playbook.networkNone")}</SelectItem>
                  </SelectContent>
                </Select>
              </Field></div>
            )}
          </div>
          <h4 className="pt-2 text-sm font-medium">{t("playbook.expect")}</h4>
          <div className="w-32"><Field label={t("playbook.exitCode")}>
            <Input type="number" value={expect.exitCode ?? ""} onChange={(e) => setExpect({ exitCode: e.target.value === "" ? null : Number(e.target.value) })} />
          </Field></div>
          <p className="text-muted-foreground -mt-2 text-xs">{t("playbook.exitCodeHint")}</p>
          <Field label={t("playbook.jsonChecks")} hint={t("playbook.jsonHint")}>
            <LinesArea value={unpairs(expect.json, true)} onChange={(v) => setExpect({
              json: Object.fromEntries(Object.entries(pairs(v)).map(([k, raw]) => {
                try {
                  return [k, JSON.parse(raw)]
                } catch {
                  return [k, raw]
                }
              })),
            })} />
          </Field>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label={t("playbook.stdoutContains")}><LinesArea rows={2} value={(expect.stdoutContains ?? []).join("\n")} onChange={(v) => setExpect({ stdoutContains: lines(v) })} /></Field>
            <Field label={t("playbook.stdoutMatches")}><LinesArea rows={2} value={(expect.stdoutMatches ?? []).join("\n")} onChange={(v) => setExpect({ stdoutMatches: lines(v) })} /></Field>
          </div>
          <Field label={t("playbook.files")}><LinesArea rows={2} value={(expect.files ?? []).join("\n")} onChange={(v) => setExpect({ files: lines(v) })} /></Field>
          {hasSandbox && (
            <div className="space-y-2">
              <Label className="text-xs">{t("playbook.sandboxRequests")}</Label>
              {(expect.sandboxRequests ?? []).map((r, i) => {
                const list = expect.sandboxRequests ?? []
                const setRequest = (patch: object | null) => setExpect({
                  sandboxRequests: patch ? list.map((x, j) => (j === i ? { ...x, ...patch } : x)) : list.filter((_, j) => j !== i),
                })
                return (
                  <div key={i} className="flex flex-wrap items-center gap-2">
                    <Select value={r.service ?? "any"} onValueChange={(v) => setRequest({ service: v === "any" ? null : v })}>
                      <SelectTrigger className="w-28" aria-label={t("playbook.service")}><SelectValue /></SelectTrigger>
                      <SelectContent>{["any", "CRL", "OCSP", "TSA", "AIA", "CSC"].map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}</SelectContent>
                    </Select>
                    <Input className="w-44 font-mono text-xs" placeholder={t("playbook.pathContains")} value={r.pathContains ?? ""} onChange={(e) => setRequest({ pathContains: e.target.value || null })} />
                    <Input className="w-20" type="number" min={0} aria-label={t("playbook.min")} title={t("playbook.min")} value={r.min ?? 1} onChange={(e) => setRequest({ min: Number(e.target.value) })} />
                    <Input className="w-20" type="number" min={0} aria-label={t("playbook.max")} title={t("playbook.max")} placeholder="∞" value={r.max ?? ""} onChange={(e) => setRequest({ max: e.target.value === "" ? null : Number(e.target.value) })} />
                    <Button variant="ghost" size="icon" className="size-7" onClick={() => setRequest(null)} aria-label={t("common.remove")}><Trash2 className="size-3.5" /></Button>
                  </div>
                )
              })}
              <Button size="sm" variant="ghost" onClick={() => setExpect({ sandboxRequests: [...(expect.sandboxRequests ?? []), { service: "OCSP", min: 1 }] })}><Plus /> {t("playbook.addRequest")}</Button>
            </div>
          )}
        </div>
      )}
      {hasSandbox && !step.manual && <ActionsForm title={t("playbook.teardown")} actions={step.teardown ?? []} onChange={(teardown) => set({ teardown })} />}
    </div>
  )
}

const actionKinds = ["faults", "revoke", "unrevoke", "reset", "certificate", "shortLived"] as const
const faultValues: Record<string, string[]> = {
  crl: ["None", "Down", "Slow", "Expired", "WrongKey", "Stale"],
  ocsp: ["None", "Down", "Slow", "TryLater", "Expired", "Unauthorized", "Unknown"],
  tsa: ["None", "Down", "Slow", "InvalidToken"],
  ocspSigner: ["Issuer", "Delegated"],
  trustedList: ["None", "Expired", "WrongSigner", "Tampered"],
}

function ActionsForm({ title, actions, onChange }: { title: string; actions: SandboxAction[]; onChange: (a: SandboxAction[]) => void }) {
  const { t } = useI18n()
  const setAction = (index: number, action: SandboxAction | null) =>
    onChange(action ? actions.map((a, i) => (i === index ? action : a)) : actions.filter((_, i) => i !== index))
  return (
    <div className="space-y-2">
      <h4 className="text-sm font-medium">{title}</h4>
      {actions.map((action, index) => (
        <div key={index} className="bg-muted/30 flex flex-wrap items-center gap-2 rounded-md border p-2">
          <Select value={action.sandbox} onValueChange={(v) => setAction(index, { sandbox: v })}>
            <SelectTrigger className="w-60"><SelectValue /></SelectTrigger>
            <SelectContent>{actionKinds.map((k) => <SelectItem key={k} value={k}>{t(`actions.${k}` as MessageKey)}</SelectItem>)}</SelectContent>
          </Select>
          {(action.sandbox === "revoke" || action.sandbox === "unrevoke") && (
            <Input className="w-44 font-mono text-xs" placeholder={t("actions.certificateId")} value={action.certificate ?? ""} onChange={(e) => setAction(index, { ...action, certificate: e.target.value })} />
          )}
          {action.sandbox === "revoke" && (
            <Select value={action.publication ?? "Both"} onValueChange={(v) => setAction(index, { ...action, publication: v === "Both" ? null : v })}>
              <SelectTrigger className="w-32" aria-label={t("actions.publication")}><SelectValue /></SelectTrigger>
              <SelectContent>{["Both", "CrlOnly", "OcspOnly"].map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}</SelectContent>
            </Select>
          )}
          {action.sandbox === "certificate" && (
            <Input className="w-44 font-mono text-xs" placeholder={t("actions.certificateId")} value={action.id ?? ""} onChange={(e) => setAction(index, { ...action, id: e.target.value })} />
          )}
          {action.sandbox === "shortLived" && (
            <Input className="w-24" type="number" min={1} max={3600} placeholder={t("actions.seconds")} value={action.seconds ?? ""} onChange={(e) => setAction(index, { ...action, seconds: e.target.value === "" ? null : Number(e.target.value) })} />
          )}
          {(action.sandbox === "certificate" || action.sandbox === "shortLived") && (
            <Input className="w-28 font-mono text-xs" placeholder={`${t("actions.as")}: cert`} value={action.as ?? ""} onChange={(e) => setAction(index, { ...action, as: e.target.value || null })} />
          )}
          {action.sandbox === "faults" && (Object.keys(faultValues) as (keyof typeof faultValues)[]).map((kind) => (
            <Select key={kind} value={(action[kind as "crl" | "ocsp" | "tsa" | "ocspSigner" | "trustedList"]) ?? "-"} onValueChange={(v) => setAction(index, { ...action, [kind]: v === "-" ? null : v })}>
              <SelectTrigger className="w-40" aria-label={t(`actions.${kind}` as MessageKey)}><span className="text-muted-foreground text-xs">{t(`actions.${kind}` as MessageKey)}:</span> <SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="-">{t("actions.unchanged")}</SelectItem>
                {faultValues[kind].map((v) => <SelectItem key={v} value={v}>{v}</SelectItem>)}
              </SelectContent>
            </Select>
          ))}
          <Button variant="ghost" size="icon" className="ml-auto size-7" onClick={() => setAction(index, null)} aria-label={t("common.remove")}><Trash2 className="size-3.5" /></Button>
        </div>
      ))}
      <Button size="sm" variant="ghost" onClick={() => onChange([...actions, { sandbox: "certificate", id: "rsa-2048" }])}><Plus /> {t("playbook.addAction")}</Button>
    </div>
  )
}
