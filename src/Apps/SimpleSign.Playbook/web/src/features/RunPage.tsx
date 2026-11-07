import { useCallback, useEffect, useRef, useState } from "react"
import { ChevronRight, FileArchive, FileText, Loader2, Paperclip, Play, Square } from "lucide-react"
import { toast } from "sonner"
import { KeyValue } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Textarea } from "@/components/ui/textarea"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { RunEvent, RunRecord, StepRecord, WorkspaceView } from "@/lib/types"
import { StatusPill, StepDetails } from "./shared"

type Output = Record<string, { stream: string; text: string }[]>

/** Starts a run (all steps or the ticked ones), follows it live, and takes the decisions of manual steps. */
export function RunPage({ workspace, onFinished }: { workspace: WorkspaceView; onFinished: () => void }) {
  const { t } = useI18n()
  const [run, setRun] = useState<RunRecord | null>(null)
  const [output, setOutput] = useState<Output>({})
  const [selection, setSelection] = useState<Set<string>>(new Set())
  const [open, setOpen] = useState<Set<string>>(new Set())
  const source = useRef<EventSource | null>(null)
  const live = !!run && !run.finishedAt

  const follow = useCallback(() => {
    source.current?.close()
    setOutput({})
    const events = new EventSource(api.eventsUrl)
    source.current = events
    events.onmessage = (message) => {
      const event = JSON.parse(message.data) as RunEvent
      if (event.type === "run" && event.run) {
        setRun(event.run)
        if (event.run.finishedAt) {
          events.close()
          onFinished()
        }
      } else if (event.type === "step" && event.step) {
        const step = event.step
        setRun((r) => (r ? { ...r, steps: r.steps.map((s) => (s.stepId === step.stepId ? step : s)) } : r))
        if (step.status === "running" || step.status === "waiting") setOpen((o) => new Set(o).add(step.stepId))
      } else if (event.type === "line" && event.stepId) {
        const id = event.stepId
        setOutput((o) => ({ ...o, [id]: [...(o[id] ?? []), { stream: event.stream ?? "stdout", text: event.text ?? "" }] }))
      }
    }
    events.onerror = () => events.close()
  }, [onFinished])

  // A run in progress is followed; otherwise the last run is shown.
  useEffect(() => {
    if (workspace.activeRunId) {
      follow()
    } else if (!run && workspace.runs[0]) {
      api.run(workspace.runs[0].id).then(setRun).catch(() => { /* none to show */ })
    }
    return () => source.current?.close()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [workspace.activeRunId])

  const start = async () => {
    try {
      await api.start(selection.size ? [...selection] : null)
      setOpen(new Set())
      follow()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const sections = workspace.playbook?.sections ?? []
  const record = (id: string) => run?.steps.find((s) => s.stepId === id)
  const toggle = (set: Set<string>, id: string) => {
    const next = new Set(set)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    return next
  }
  const hasErrors = workspace.issues.some((i) => i.isError)

  return (
    <div className="max-w-5xl space-y-6">
      <div className="flex flex-wrap items-center gap-2">
        {live ? (
          <Button variant="destructive" onClick={() => api.cancel().catch((e: Error) => toast.error(e.message))}><Square /> {t("run.stop")}</Button>
        ) : (
          <Button disabled={hasErrors || sections.length === 0} onClick={start}>
            <Play /> {selection.size ? t("run.startSelected", { count: selection.size }) : t("run.start")}
          </Button>
        )}
        {live && <Loader2 className="text-muted-foreground size-4 animate-spin" />}
        {!live && <span className="text-muted-foreground text-xs">{t("run.selectHint")}</span>}
        {run?.finishedAt && (
          <div className="ml-auto flex gap-2">
            <Button variant="outline" size="sm" asChild><a href={api.fileUrl(run.id, "report.html")} target="_blank" rel="noreferrer"><FileText /> {t("run.report")}</a></Button>
            <Button variant="outline" size="sm" asChild><a href={api.zipUrl(run.id)}><FileArchive /> {t("run.zip")}</a></Button>
          </div>
        )}
      </div>
      {hasErrors && <p className="text-destructive text-sm">{t("run.playbookHasErrors")}</p>}
      {run ? <RunHeader run={run} /> : <p className="text-muted-foreground text-sm">{t("run.idle")}</p>}

      <div className="space-y-6">
        {sections.map((section) => (
          <div key={section.id} className="space-y-2">
            <h3 className="text-sm font-semibold">{section.title || section.id}</h3>
            <ul className="divide-y rounded-md border">
              {section.steps.map((step) => {
                const r = record(step.id)
                return (
                  <li key={step.id}>
                    <Collapsible open={open.has(step.id)} onOpenChange={() => setOpen((o) => toggle(o, step.id))}>
                      <div className="flex items-center gap-2 px-3 py-2">
                        <Checkbox disabled={live} checked={selection.has(step.id)} onCheckedChange={() => setSelection((s) => toggle(s, step.id))} aria-label={step.title} />
                        <CollapsibleTrigger className="group flex min-w-0 flex-1 items-center gap-2 text-left text-sm" disabled={!r}>
                          <ChevronRight className="size-4 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
                          <span className="truncate">{step.title || step.id}</span>
                          <span className="text-muted-foreground font-mono text-xs">{step.id}</span>
                        </CollapsibleTrigger>
                        {r?.durationMs != null && <span className="text-muted-foreground text-xs tabular-nums">{r.durationMs} ms</span>}
                        {r && <StatusPill status={r.status} />}
                      </div>
                      {r && run && (
                        <CollapsibleContent className="border-t px-4 py-3">
                          <StepDetails runId={run.id} step={r} lines={output[step.id]}>
                            {r.status === "waiting" && <Decision runId={run.id} step={r} />}
                          </StepDetails>
                        </CollapsibleContent>
                      )}
                    </Collapsible>
                  </li>
                )
              })}
            </ul>
          </div>
        ))}
      </div>
    </div>
  )
}

/** When, on what, and how the run went. */
export function RunHeader({ run }: { run: RunRecord }) {
  const { t, dateTime } = useI18n()
  // Counted from the steps: step events update them before the run's own summary is sent again.
  const count = (...states: string[]) => run.steps.filter((x) => states.includes(x.status)).length
  const s = { passed: count("passed"), failed: count("failed"), errors: count("error"), skipped: count("skipped", "cancelled") }
  return (
    <div className="space-y-2 rounded-lg border p-4">
      <div className="flex flex-wrap items-center gap-3">
        <StatusPill status={run.status} />
        <span className="font-mono text-xs">{run.id}</span>
        <span className="text-sm">{t("run.summary", { passed: s.passed, failed: s.failed, errors: s.errors, skipped: s.skipped })}</span>
      </div>
      {run.error && <p className="text-destructive text-sm">{t("run.stoppedBecause", { reason: run.error })}</p>}
      <div className="grid gap-x-8 sm:grid-cols-2">
        <KeyValue label={t("run.started")}>{dateTime(run.startedAt)}</KeyValue>
        <KeyValue label={t("run.finished")}>{run.finishedAt ? dateTime(run.finishedAt) : "—"}</KeyValue>
        <KeyValue label={t("run.cli")} mono>{run.cli}</KeyValue>
        <KeyValue label={t("run.version")}>{run.cliVersion ?? "—"}</KeyValue>
        <KeyValue label={t("run.machine")}>{`${run.machine} (${run.user})`}</KeyValue>
        {run.sandbox && <KeyValue label="Sandbox" mono>{`${run.sandbox.name} · ${run.sandbox.url}`}</KeyValue>}
      </div>
    </div>
  )
}

/** The operator's result for a manual step: a note, files, and passed / failed / skip. */
function Decision({ runId, step }: { runId: string; step: StepRecord }) {
  const { t } = useI18n()
  const [note, setNote] = useState("")
  const input = useRef<HTMLInputElement>(null)
  const decide = (status: string) => api.decide(runId, step.stepId, status, note.trim() || null).catch((e: Error) => toast.error(e.message))
  return (
    <div className="border-warning/50 bg-warning/5 space-y-3 rounded-md border p-3">
      <p className="text-sm">{t("run.waiting")}</p>
      <Textarea rows={3} placeholder={t("run.note")} value={note} onChange={(e) => setNote(e.target.value)} />
      <div className="flex flex-wrap gap-2">
        <input ref={input} type="file" multiple className="hidden" onChange={(e) => {
          if (e.target.files?.length) {
            api.attach(runId, step.stepId, e.target.files).then(() => toast.success(t("run.attached"))).catch((err: Error) => toast.error(err.message))
          }
          e.target.value = ""
        }} />
        <Button variant="outline" size="sm" onClick={() => input.current?.click()}><Paperclip /> {t("run.attach")}</Button>
        <Button size="sm" className="ml-auto" onClick={() => decide("passed")}>{t("run.passed")}</Button>
        <Button size="sm" variant="destructive" onClick={() => decide("failed")}>{t("run.failed")}</Button>
        <Button size="sm" variant="ghost" onClick={() => decide("skipped")}>{t("run.skip")}</Button>
      </div>
    </div>
  )
}
