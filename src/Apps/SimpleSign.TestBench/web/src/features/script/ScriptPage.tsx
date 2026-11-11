import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { CheckCircle2, Circle, ClipboardCheck, Download, ExternalLink, FileJson, FolderOpen, Hand, Loader2, MinusCircle, Play, Square, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Progress } from "@/components/ui/progress"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { Textarea } from "@/components/ui/textarea"
import { useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { ReportButtons } from "../shared/ReportViewer"
import { Pill } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { LogView } from "../workbench/LogView"
import type { Format, RunView } from "../workbench/schema"
import { scriptApi } from "./api"
import type { ScriptEngineRun, ScriptLoaded, ScriptRequirementView, ScriptRunView, ScriptSample, ScriptStatus, ScriptStep, ScriptStepView } from "./types"

type Selection = { kind: "step" | "requirement"; id: string } | null

/**
 * The certification script runner: load a script written beforehand (the requirements of an accreditation guide and the
 * steps that show each one), run it against the Sandbox through the library, the CLI or both, decide the manual steps,
 * and take the evidence to the auditor.
 */
export function ScriptPage() {
  const t = useT()
  const [loaded, setLoaded] = useState<ScriptLoaded | null>(null)
  const [samples, setSamples] = useState<ScriptSample[]>([])
  const [run, setRun] = useState<ScriptRunView | null>(null)
  const [engine, setEngine] = useState<string>("script")
  const [selection, setSelection] = useState<Selection>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const script = loaded?.script ?? null

  useEffect(() => {
    scriptApi.samples().then(setSamples).catch(() => undefined)
    scriptApi.loaded().then((l) => l && setLoaded(l)).catch(() => undefined)
    scriptApi.history().then((h) => h[0] && setRun(h[0])).catch(() => undefined)
  }, [])

  // Follow the run while it goes.
  const active = run?.status === "running" || run?.status === "waiting"
  useEffect(() => {
    if (!run || !active) return
    const timer = window.setInterval(() => {
      scriptApi.run(run.id).then(setRun).catch(() => undefined)
    }, 1000)
    return () => window.clearInterval(timer)
  }, [run, active])

  const onLoaded = useCallback((result: ScriptLoaded) => {
    setLoaded(result)
    setSelection(null)
    if (!result.canRun) toast.error(t("script.errors", { count: result.issues.filter((i) => i.isError).length }))
  }, [t])

  const openFile = async (file: File) => {
    try {
      onLoaded(await scriptApi.load(await file.text()))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const start = async (scope: { sectionId?: string; stepId?: string } = {}) => {
    try {
      const view = await scriptApi.start({ engine: engine === "script" ? null : engine, ...scope })
      setRun(view)
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const stepViews = useMemo(() => new Map((run?.scriptId === script?.id ? run?.steps ?? [] : []).map((s) => [s.stepId, s])), [run, script])
  const requirementViews = useMemo(() => new Map((run?.scriptId === script?.id ? run?.requirements ?? [] : []).map((r) => [r.id, r])), [run, script])
  const shown = script ? script.requirements.filter((r) => r.applies && requirementViews.get(r.id)?.status === "passed").length : 0
  const applicable = script ? script.requirements.filter((r) => r.applies).length : 0
  const errors = loaded?.issues.filter((i) => i.isError) ?? []
  const warnings = loaded?.issues.filter((i) => !i.isError) ?? []

  return (
    <div className="flex h-full min-h-0 flex-col">
      <header className="flex flex-wrap items-center gap-2 border-b px-4 py-3">
        <ClipboardCheck className="text-primary size-5" />
        <div className="mr-2 min-w-0 leading-tight">
          <p className="font-semibold">{t("script.title")}</p>
          <p className="text-muted-foreground truncate text-xs">{script ? [script.title, script.authority, script.standard].filter(Boolean).join(" · ") : t("script.noScript")}</p>
        </div>
        <input ref={fileInput} type="file" accept=".json,application/json" className="hidden"
          onChange={(e) => { const f = e.target.files?.[0]; if (f) void openFile(f); e.target.value = "" }} />
        <Button variant="outline" size="sm" onClick={() => fileInput.current?.click()}><FolderOpen /> {t("script.load")}</Button>
        {samples.length > 0 && (
          <Select value="" onValueChange={(id) => scriptApi.loadSample(id).then(onLoaded).catch((e) => toast.error((e as Error).message))}>
            <SelectTrigger size="sm" className="w-auto"><SelectValue placeholder={t("script.samples")} /></SelectTrigger>
            <SelectContent>{samples.map((s) => <SelectItem key={s.id} value={s.id}>{s.title}</SelectItem>)}</SelectContent>
          </Select>
        )}
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Select value={engine} onValueChange={setEngine}>
            <SelectTrigger size="sm" className="w-auto" aria-label={t("script.engine")}><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="script">{t("script.engineScript")}</SelectItem>
              <SelectItem value="library">{t("script.engineLibrary")}</SelectItem>
              <SelectItem value="cli">{t("script.engineCli")}</SelectItem>
              <SelectItem value="both">{t("script.engineBoth")}</SelectItem>
            </SelectContent>
          </Select>
          {active
            ? <Button size="sm" variant="destructive" onClick={() => run && scriptApi.cancel(run.id)}><Square /> {t("script.cancel")}</Button>
            : <Button size="sm" disabled={!loaded?.canRun} onClick={() => start()}><Play /> {t("script.runAll")}</Button>}
          {run && (
            <>
              <Button variant="outline" size="sm" asChild><a href={scriptApi.evidenceHtmlUrl(run.id)} target="_blank" rel="noreferrer"><ExternalLink /> {t("script.evidenceHtml")}</a></Button>
              <Button variant="outline" size="sm" asChild><a href={scriptApi.evidenceZipUrl(run.id)} download><Download /> {t("script.evidenceZip")}</a></Button>
            </>
          )}
          <Button variant="ghost" size="sm" asChild><a href={scriptApi.schemaUrl} target="_blank" rel="noreferrer"><FileJson /> {t("script.schema")}</a></Button>
          <Button variant="ghost" size="sm" asChild><a href={scriptApi.optionsUrl} target="_blank" rel="noreferrer">{t("script.options")}</a></Button>
        </div>
      </header>

      {(errors.length > 0 || warnings.length > 0) && (
        <div className={cn("max-h-40 overflow-auto border-b px-4 py-2 text-xs", errors.length > 0 ? "bg-destructive/5" : "bg-warning/5")}>
          <p className="mb-1 font-medium">{t("script.issues")} · {errors.length > 0 && t("script.errors", { count: errors.length })} {warnings.length > 0 && t("script.warnings", { count: warnings.length })}</p>
          <ul className="space-y-0.5">
            {loaded!.issues.map((i, n) => (
              <li key={n} className={i.isError ? "text-destructive" : "text-muted-foreground"}><code className="mr-2">{i.path}</code>{i.message}</li>
            ))}
          </ul>
        </div>
      )}

      {!script ? (
        <div className="text-muted-foreground flex flex-1 items-center justify-center p-8 text-sm">{t("script.noScript")}</div>
      ) : (
        <div className="flex min-h-0 flex-1">
          <aside className="flex w-[400px] shrink-0 flex-col border-r">
            <div className="space-y-1 border-b p-3">
              <p className="text-muted-foreground text-xs">{t("script.progress", { done: shown, total: applicable })}</p>
              <Progress value={applicable === 0 ? 0 : (shown * 100) / applicable} />
              {run && run.scriptId === script.id && <p className="text-muted-foreground text-xs">{t("script.history")}: {run.id} · <StatusText status={run.status} /></p>}
            </div>
            <Tabs defaultValue="requirements" className="flex min-h-0 flex-1 flex-col gap-0">
              <TabsList className="mx-3 mt-2">
                <TabsTrigger value="requirements">{t("script.requirements")}</TabsTrigger>
                <TabsTrigger value="steps">{t("script.steps")}</TabsTrigger>
              </TabsList>
              <TabsContent value="requirements" className="min-h-0 flex-1">
                <ScrollArea className="h-full">
                  <ul className="p-2">
                    {script.requirements.map((r) => {
                      const status: ScriptStatus = !r.applies ? "notApplicable" : requirementViews.get(r.id)?.status ?? "pending"
                      return (
                        <li key={r.id}>
                          <button onClick={() => setSelection({ kind: "requirement", id: r.id })}
                            className={cn("hover:bg-muted flex w-full items-start gap-2 rounded-md px-2 py-1.5 text-left text-sm",
                              selection?.kind === "requirement" && selection.id === r.id && "bg-muted")}>
                            <StatusIcon status={status} />
                            <span className="min-w-0"><span className="font-mono text-xs">{r.id}</span>{r.group && <span className="text-muted-foreground text-xs"> · {r.group}</span>}
                              <span className="line-clamp-2 block">{r.text}</span></span>
                          </button>
                        </li>
                      )
                    })}
                  </ul>
                </ScrollArea>
              </TabsContent>
              <TabsContent value="steps" className="min-h-0 flex-1">
                <ScrollArea className="h-full">
                  <div className="p-2">
                    {script.sections.map((section) => (
                      <div key={section.id} className="mb-3">
                        <div className="flex items-center gap-1 px-2 py-1">
                          <p className="text-muted-foreground flex-1 text-xs font-semibold uppercase">{section.title}</p>
                          <Button variant="ghost" size="icon" className="size-6" disabled={!loaded?.canRun || active} aria-label={t("script.runSection")}
                            title={t("script.runSection")} onClick={() => start({ sectionId: section.id })}><Play className="size-3" /></Button>
                        </div>
                        {section.steps.map((step) => (
                          <button key={step.id} onClick={() => setSelection({ kind: "step", id: step.id })}
                            className={cn("hover:bg-muted flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm",
                              selection?.kind === "step" && selection.id === step.id && "bg-muted")}>
                            <StatusIcon status={stepViews.get(step.id)?.status ?? "pending"} />
                            <span className="min-w-0 flex-1 truncate">{step.title}</span>
                            {step.format && <span className="text-muted-foreground font-mono text-[10px] uppercase">{step.format}</span>}
                          </button>
                        ))}
                      </div>
                    ))}
                  </div>
                </ScrollArea>
              </TabsContent>
            </Tabs>
          </aside>

          <section className="min-w-0 flex-1 overflow-auto p-6">
            {selection?.kind === "step" ? (
              <StepDetail step={script.sections.flatMap((s) => s.steps).find((s) => s.id === selection.id)!}
                view={stepViews.get(selection.id)} run={run} defaultFormat={script.defaults.format as Format}
                canRun={!!loaded?.canRun && !active} onRun={() => start({ stepId: selection.id })} onDecided={() => run && scriptApi.run(run.id).then(setRun)} />
            ) : selection?.kind === "requirement" ? (
              <RequirementDetail requirement={script.requirements.find((r) => r.id === selection.id)!} view={requirementViews.get(selection.id)}
                steps={script.sections.flatMap((s) => s.steps).filter((s) => s.requirements.includes(selection.id))}
                stepViews={stepViews} onSelect={(id) => setSelection({ kind: "step", id })} />
            ) : (
              <div className="text-muted-foreground space-y-2 text-sm">
                {script.description && <p className="text-foreground">{script.description}</p>}
                <p>{t("script.noStep")}</p>
              </div>
            )}
          </section>
        </div>
      )}
    </div>
  )
}

function RequirementDetail({ requirement, view, steps, stepViews, onSelect }: {
  requirement: { id: string; group?: string | null; text: string; reference?: string | null; applies: boolean; justification?: string | null }
  view?: ScriptRequirementView
  steps: ScriptStep[]
  stepViews: Map<string, ScriptStepView>
  onSelect: (id: string) => void
}) {
  const t = useT()
  const status: ScriptStatus = !requirement.applies ? "notApplicable" : view?.status ?? "pending"
  return (
    <div className="max-w-3xl space-y-4">
      <div className="flex items-center gap-2"><StatusIcon status={status} /><h2 className="font-mono text-lg font-semibold">{requirement.id}</h2><StatusText status={status} /></div>
      {requirement.group && <p className="text-muted-foreground text-sm">{requirement.group}{requirement.reference && ` · ${requirement.reference}`}</p>}
      <p className="text-sm whitespace-pre-line">{requirement.text}</p>
      {!requirement.applies && <p className="bg-muted rounded-md p-3 text-sm">{t("script.notApplicable", { why: requirement.justification ?? "" })}</p>}
      {steps.length > 0 && (
        <div>
          <p className="mb-1 text-sm font-medium">{t("script.steps")}</p>
          <ul className="space-y-1">
            {steps.map((s) => (
              <li key={s.id}>
                <button className="hover:bg-muted flex items-center gap-2 rounded-md px-2 py-1 text-sm" onClick={() => onSelect(s.id)}>
                  <StatusIcon status={stepViews.get(s.id)?.status ?? "pending"} /> {s.title}
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  )
}

function StepDetail({ step, view, run, defaultFormat, canRun, onRun, onDecided }: {
  step: ScriptStep
  view?: ScriptStepView
  run: ScriptRunView | null
  defaultFormat: Format
  canRun: boolean
  onRun: () => void
  onDecided: () => void
}) {
  const t = useT()
  const status: ScriptStatus = view?.status ?? "pending"
  const expected = step.expect
    ? Object.entries(step.expect).filter(([k, v]) => v !== null && v !== undefined && !(k === "logContains" && (v as string[]).length === 0))
    : []
  return (
    <div className="max-w-4xl space-y-5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusIcon status={status} />
        <h2 className="text-lg font-semibold">{step.title}</h2>
        <StatusText status={status} />
        <span className="text-muted-foreground font-mono text-xs">{step.id} · {step.kind}{step.kind !== "manual" && ` · ${step.format ?? defaultFormat}`}</span>
        {step.kind !== "manual" && <Button size="sm" variant="outline" className="ml-auto" disabled={!canRun} onClick={onRun}><Play /> {t("script.runStep")}</Button>}
      </div>
      {step.description && <p className="text-sm whitespace-pre-line">{step.description}</p>}
      <div className="flex flex-wrap items-center gap-1 text-xs">
        <span className="text-muted-foreground">{t("script.shows")}:</span>
        {step.requirements.map((r) => <Pill key={r}>{r}</Pill>)}
      </div>
      {step.sandbox && (
        <p className="text-muted-foreground text-xs">
          {t("script.sandbox")}: {[step.sandbox.crl && `CRL ${step.sandbox.crl}`, step.sandbox.ocsp && `OCSP ${step.sandbox.ocsp}`, step.sandbox.tsa && `TSA ${step.sandbox.tsa}`,
            step.sandbox.trustedList && `TL ${step.sandbox.trustedList}`, step.sandbox.revoke.length > 0 && `revoke ${step.sandbox.revoke.join(", ")}`].filter(Boolean).join(" · ")}
        </p>
      )}
      {expected.length > 0 && (
        <div className="text-sm">
          <p className="font-medium">{t("script.expected")}</p>
          <p className="text-muted-foreground font-mono text-xs">{expected.map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(", ") : String(v)}`).join(" · ")}</p>
        </div>
      )}
      {view?.message && <p className="text-destructive text-sm">{view.message}</p>}
      {step.kind === "manual" && run && <ManualStep step={step} view={view} run={run} onDecided={onDecided} />}
      {view?.runs.map((r) => <EngineRun key={r.engine + r.runId} result={r} format={(step.format as Format) ?? defaultFormat} />)}
    </div>
  )
}

function EngineRun({ result, format }: { result: ScriptEngineRun; format: Format }) {
  const t = useT()
  const [log, setLog] = useState<RunView | null>(null)
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {result.passed ? <CheckCircle2 className="text-success size-4" /> : <XCircle className="text-destructive size-4" />}
        <span className="font-medium uppercase">{result.engine}</span>
        <span className="text-muted-foreground text-xs">{t("script.run", { id: result.runId, ms: result.ms })}</span>
        {result.dssAgrees !== null && result.dssAgrees !== undefined && <Pill tone={result.dssAgrees ? "success" : "warning"}>{t(result.dssAgrees ? "script.dssAgrees" : "script.dssDiffers")}</Pill>}
      </div>
      <Table>
        <TableHeader><TableRow><TableHead>{t("script.check")}</TableHead><TableHead>{t("script.expected")}</TableHead><TableHead>{t("script.found")}</TableHead></TableRow></TableHeader>
        <TableBody>
          {result.checks.map((c, i) => (
            <TableRow key={i}>
              <TableCell className="font-mono text-xs">{c.what}</TableCell>
              <TableCell className="text-xs">{c.expected}</TableCell>
              <TableCell className={cn("text-xs", c.passed ? "text-success" : "text-destructive font-medium")}>{c.found}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {result.error && <p className="text-muted-foreground text-xs">{result.errorType}: {result.error}</p>}
      <div className="flex flex-wrap items-center gap-2">
        {result.outputId && <Button variant="outline" size="sm" asChild><a href={api.fileUrl(result.outputId, true)}><Download /> {t("script.output")}</a></Button>}
        {result.reportId && <ReportButtons source="simplesign" reportId={result.reportId} />}
        <Button variant="ghost" size="sm" onClick={() => (log ? setLog(null) : api.workbench.run(result.runId).then((r) => r && setLog(r)))}>
          {log ? t("script.hideLog") : t("script.log")}
        </Button>
      </div>
      {log && <LogView logs={log.logs} format={format} running={false} />}
    </div>
  )
}

function ManualStep({ step, view, run, onDecided }: { step: ScriptStep; view?: ScriptStepView; run: ScriptRunView; onDecided: () => void }) {
  const t = useT()
  const [note, setNote] = useState("")
  const [attachments, setAttachments] = useState<{ id: string; fileName: string }[]>([])
  const waiting = run.waitingFor === step.id
  const decide = async (passed: boolean) => {
    try {
      await scriptApi.decide(run.id, step.id, { passed, note: note || null, attachmentIds: attachments.map((a) => a.id) })
      onDecided()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  return (
    <div className={cn("space-y-3 rounded-lg border p-4", waiting && "border-info/60 bg-info/5")}>
      <p className="flex items-center gap-2 text-sm font-medium"><Hand className="size-4" /> {t("script.manual")}</p>
      <p className="text-sm whitespace-pre-line">{step.manual?.instructions}</p>
      {waiting ? (
        <>
          <p className="text-info text-xs">{t("script.waiting")}</p>
          <Textarea rows={3} placeholder={t("script.note")} value={note} onChange={(e) => setNote(e.target.value)} />
          <div className="flex flex-wrap items-center gap-2">
            <UploadButton label={t("script.attach")} accept="*/*" onUploaded={(f) => setAttachments((a) => [...a, f])} />
            {attachments.map((a) => <Pill key={a.id}>{a.fileName}</Pill>)}
          </div>
          <div className="flex gap-2">
            <Button size="sm" onClick={() => decide(true)}><CheckCircle2 /> {t("script.approve")}</Button>
            <Button size="sm" variant="destructive" onClick={() => decide(false)}><XCircle /> {t("script.reject")}</Button>
          </div>
        </>
      ) : (
        <>
          {view?.note && <p className="text-sm"><span className="text-muted-foreground">{t("script.note")}:</span> {view.note}</p>}
          {view && view.attachments.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {view.attachments.map((a) => <Button key={a.id} variant="outline" size="sm" asChild><a href={api.fileUrl(a.id, true)}><Download /> {a.fileName}</a></Button>)}
            </div>
          )}
        </>
      )}
    </div>
  )
}

function StatusIcon({ status }: { status: ScriptStatus }) {
  switch (status) {
    case "passed":
      return <CheckCircle2 className="text-success mt-0.5 size-4 shrink-0" />
    case "failed":
      return <XCircle className="text-destructive mt-0.5 size-4 shrink-0" />
    case "running":
      return <Loader2 className="text-info mt-0.5 size-4 shrink-0 animate-spin" />
    case "waiting":
      return <Hand className="text-info mt-0.5 size-4 shrink-0" />
    case "notApplicable":
    case "skipped":
      return <MinusCircle className="text-muted-foreground mt-0.5 size-4 shrink-0" />
    default:
      return <Circle className="text-muted-foreground mt-0.5 size-4 shrink-0" />
  }
}

function StatusText({ status }: { status: ScriptStatus }) {
  const t = useT()
  return <span className="text-muted-foreground text-xs">{t(`script.status.${status}` as MessageKey)}</span>
}
