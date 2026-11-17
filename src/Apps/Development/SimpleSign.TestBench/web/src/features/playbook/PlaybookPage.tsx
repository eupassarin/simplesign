import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { AlertTriangle, CheckCircle2, ChevronRight, ChevronsDownUp, ChevronsUpDown, Circle, Clock, Download, Eraser, ExternalLink, FileJson, GitCompareArrows, ListTree, Loader2, Paperclip, Play, RotateCcw, Search, SkipForward, Square, Tag, Upload, X, XCircle } from "lucide-react"
import { toast } from "sonner"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { useI18n, useT, type MessageKey } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { HighlightedCode } from "../shared/CodeHighlight"
import { ReportButtons } from "../shared/ReportViewer"
import { Pill } from "../shared/ui"
import { LogView } from "../workbench/LogView"
import { CliSteps } from "../workbench/ResultPanel"
import type { Format, RunView } from "../workbench/schema"
import { playbookApi } from "./api"
import { OptionsReferenceDialog } from "./OptionsReference"
import { PlaybookFileMenu } from "./PlaybookFileMenu"
import { PlaybookPicker } from "./PlaybookPicker"
import type { PlaybookEngineDifference, PlaybookEngineRun, PlaybookInputView, PlaybookLoaded, PlaybookSample, PlaybookStateView, PlaybookStatus, PlaybookStep, PlaybookStepPreview, PlaybookStepView, PreviewItem } from "./types"

const emptyState: PlaybookStateView = { running: false, version: 0, steps: [] }

function remembered(key: string): string | null {
  try { return localStorage.getItem(key) } catch { return null }
}

function remember(key: string, value: string | null) {
  try {
    if (value === null) localStorage.removeItem(key)
    else localStorage.setItem(key, value)
  } catch { /* private window: not remembered */ }
}

/** The results the step list filters by: not run covers pending, queued and running. */
type StatusFilter = "all" | "passed" | "failed" | "notRun"

function statusOf(view?: PlaybookStepView): Exclude<StatusFilter, "all"> {
  return view?.status === "passed" ? "passed" : view?.status === "failed" ? "failed" : "notRun"
}

/** Whether DSS reached another verdict than SimpleSign in the step's latest run (any engine). */
function dssDiffers(view?: PlaybookStepView): boolean {
  return !!view?.result?.runs.some((r) => r.dssAgrees === false)
}

/** Whether the library and CLI runs of the step's latest run reached different verdicts. */
function enginesDiffer(view?: PlaybookStepView): boolean {
  return (view?.result?.engineDifferences?.length ?? 0) > 0
}

/** Lower case without accents, so "assinatura" finds "Assinatura" and "validacao" finds "validação". */
function fold(text: string): string {
  return text.normalize("NFD").replace(/\p{M}/gu, "").toLowerCase()
}

/**
 * The Playbook tab: load a playbook written beforehand (sections of steps, each with free tags), see everything a step
 * will do before running it, run it alone, a section or everything against the Sandbox, and read every detail of the
 * latest run of each step. Three columns: the steps, what the selected step does, and its latest result.
 */
export function PlaybookPage() {
  const t = useT()
  const [loaded, setLoaded] = useState<PlaybookLoaded | null>(null)
  const [samples, setSamples] = useState<PlaybookSample[]>([])
  const [state, setState] = useState<PlaybookStateView>(emptyState)
  const [engine, setEngine] = useState<string>(() => remembered("pb.engine") ?? "playbook")
  const [selected, setSelected] = useState<string | null>(() => remembered("pb.step"))
  const [chosenTags, setChosenTags] = useState<string[]>([])
  const [titleQuery, setTitleQuery] = useState("")
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all")
  const [dssOnly, setDssOnly] = useState(false)
  const [enginesOnly, setEnginesOnly] = useState(false)
  const [optionsOpen, setOptionsOpen] = useState(false)
  const [confirmRestart, setConfirmRestart] = useState(false)
  const [stepJson, setStepJson] = useState<Map<string, string>>(new Map())
  const [defaultsJson, setDefaultsJson] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const playbook = loaded?.playbook ?? null

  useEffect(() => {
    playbookApi.samples().then(setSamples).catch(() => undefined)
    playbookApi.loaded().then((l) => l && setLoaded(l)).catch(() => undefined)
    playbookApi.state().then(setState).catch(() => undefined)
  }, [])

  // Follow the run while it goes.
  useEffect(() => {
    if (!state.running) return
    const timer = window.setInterval(() => {
      playbookApi.state().then(setState).catch(() => undefined)
    }, 1000)
    return () => window.clearInterval(timer)
  }, [state.running])

  const select = useCallback((id: string | null) => {
    setSelected(id)
    remember("pb.step", id)
  }, [])

  const chooseEngine = (value: string) => {
    setEngine(value)
    remember("pb.engine", value)
  }

  const resetFilters = useCallback(() => {
    setChosenTags([])
    setTitleQuery("")
    setStatusFilter("all")
    setDssOnly(false)
    setEnginesOnly(false)
  }, [])

  const onLoaded = useCallback((result: PlaybookLoaded) => {
    setLoaded(result)
    resetFilters()
    playbookApi.state().then(setState).catch(() => undefined)
    const steps = result.playbook?.sections.flatMap((s) => s.steps) ?? []
    setSelected((current) => {
      const next = current && steps.some((s) => s.id === current) ? current : steps[0]?.id ?? null
      remember("pb.step", next)
      return next
    })
    if (!result.canRun) toast.error(t("playbook.errors", { count: result.issues.filter((i) => i.isError).length }))
  }, [t, resetFilters])

  const openFile = async (file: File) => {
    try {
      onLoaded(await playbookApi.load(await file.text()))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const start = async (scope: { sectionId?: string; stepId?: string } = {}) => {
    try {
      setState(await playbookApi.run({ engine: engine === "playbook" ? null : engine, ...scope }))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const clear = async (stepId?: string) => {
    try {
      setState(await playbookApi.clear(stepId))
      if (!stepId) resetFilters()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  const addTag = (x: string) => setChosenTags((current) => current.includes(x) ? current : [...current, x])

  // Each step as written in the file (the panel shows it before the step runs).
  useEffect(() => {
    if (!playbook) { setStepJson(new Map()); setDefaultsJson(null); return }
    let live = true
    playbookApi.loadedJson().then((text) => {
      if (!live || !text) return
      try {
        const file = JSON.parse(text) as { defaults?: unknown; sections?: { steps?: { id?: string }[] }[] }
        setStepJson(new Map((file.sections ?? []).flatMap((s) => s.steps ?? []).map((x) => [x.id ?? "", JSON.stringify(x, null, 2)])))
        setDefaultsJson(file.defaults === undefined ? null : JSON.stringify(file.defaults, null, 2))
      } catch { setStepJson(new Map()); setDefaultsJson(null) }
    }).catch(() => undefined)
    return () => { live = false }
  }, [playbook])

  const views = useMemo(() => new Map((state.playbookId === playbook?.id ? state.steps : []).map((s) => [s.stepId, s])), [state, playbook])
  const tags = useMemo(() => [...new Set(playbook?.sections.flatMap((s) => s.steps.flatMap((step) => step.tags)) ?? [])]
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true })), [playbook])
  const steps = useMemo(() => playbook?.sections.flatMap((s) => s.steps) ?? [], [playbook])
  // Tags (any of them) and the title or id narrow the list first; the result and DSS filters then apply on top.
  const narrowed = useMemo(() => {
    const query = fold(titleQuery.trim())
    return new Set(steps
      .filter((s) => (chosenTags.length === 0 || s.tags.some((x) => chosenTags.includes(x)))
        && (query === "" || fold(s.title).includes(query) || fold(s.id).includes(query)))
      .map((s) => s.id))
  }, [steps, chosenTags, titleQuery])
  const isShown = (s: PlaybookStep) => {
    const view = views.get(s.id)
    return narrowed.has(s.id) && (statusFilter === "all" || statusOf(view) === statusFilter) && (!dssOnly || dssDiffers(view))
      && (!enginesOnly || enginesDiffer(view))
  }
  const shownCount = steps.filter(isShown).length
  const filtering = chosenTags.length > 0 || titleQuery.trim() !== "" || statusFilter !== "all" || dssOnly || enginesOnly
  // Each count is what clicking it would show, given the other filters.
  const filterCounts = useMemo(() => {
    const c = { all: 0, passed: 0, failed: 0, notRun: 0, dss: 0, engines: 0 }
    for (const s of steps) {
      if (!narrowed.has(s.id)) continue
      const view = views.get(s.id)
      const dss = dssDiffers(view)
      const engines = enginesDiffer(view)
      const status = statusFilter === "all" || statusOf(view) === statusFilter
      if ((!dssOnly || dss) && (!enginesOnly || engines)) { c.all++; c[statusOf(view)]++ }
      if (dss && status && (!enginesOnly || engines)) c.dss++
      if (engines && status && (!dssOnly || dss)) c.engines++
    }
    return c
  }, [steps, narrowed, views, dssOnly, enginesOnly, statusFilter])
  const step = steps.find((s) => s.id === selected) ?? null
  const errors = loaded?.issues.filter((i) => i.isError) ?? []
  const warnings = loaded?.issues.filter((i) => !i.isError) ?? []
  const counts = useMemo(() => {
    const all = [...views.values()]
    return {
      passed: all.filter((s) => s.status === "passed").length,
      failed: all.filter((s) => s.status === "failed").length,
      dss: all.filter(dssDiffers).length,
      engines: all.filter(enginesDiffer).length,
      total: steps.length,
    }
  }, [views, steps])
  const canRun = !!loaded?.canRun && !state.running
  const hasResults = [...views.values()].some((s) => s.result)

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="space-y-2 border-b px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <PlaybookPicker current={playbook ? { id: playbook.id, title: playbook.title } : null} samples={samples} disabled={state.running}
            onSample={(id) => playbookApi.loadSample(id).then(onLoaded).catch((e) => toast.error((e as Error).message))}
            onOpenFile={() => fileInput.current?.click()} />
          <input ref={fileInput} type="file" accept=".json,application/json" className="hidden"
            onChange={(e) => { const f = e.target.files?.[0]; if (f) void openFile(f); e.target.value = "" }} />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={engine} onValueChange={chooseEngine}>
            <SelectTrigger size="sm" className="w-auto" aria-label={t("playbook.engine")}><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="playbook">{t("playbook.enginePlaybook")}</SelectItem>
              <SelectItem value="library">{t("playbook.engineLibrary")}</SelectItem>
              <SelectItem value="cli">{t("playbook.engineCli")}</SelectItem>
              <SelectItem value="both">{t("playbook.engineBoth")}</SelectItem>
            </SelectContent>
          </Select>
          {state.running
            ? <Button size="sm" variant="destructive" onClick={() => playbookApi.cancel()}><Square /> {t("playbook.cancel")}</Button>
            : <Button size="sm" disabled={!canRun} onClick={() => start()}><Play /> {t("playbook.runAll")}</Button>}
          <Button variant="outline" size="icon" className="size-8" disabled={!hasResults || state.running} onClick={() => setConfirmRestart(true)}
            title={t("playbook.restart")} aria-label={t("playbook.restart")}><RotateCcw /></Button>
          <EvidenceLink enabled={hasResults} href={playbookApi.evidenceHtmlUrl} newTab><ExternalLink /> {t("playbook.evidenceHtml")}</EvidenceLink>
          <EvidenceLink enabled={hasResults} href={playbookApi.evidenceZipUrl}><Download /> {t("playbook.evidenceZip")}</EvidenceLink>
          {playbook && (
            <span className="text-muted-foreground ml-1 flex items-center gap-2 text-xs tabular-nums">
              <span className="flex items-center gap-1"><CheckCircle2 className="text-success size-3.5" />{counts.passed}</span>
              <span className="flex items-center gap-1"><XCircle className="text-destructive size-3.5" />{counts.failed}</span>
              {counts.dss > 0 && (
                <button type="button" aria-pressed={dssOnly} title={t("playbook.filter.dssHint")} onClick={() => setDssOnly((on) => !on)}
                  className={cn("hover:text-foreground flex items-center gap-1 rounded px-1", dssOnly && "bg-warning/15 text-foreground")}>
                  <AlertTriangle className="text-warning size-3.5" />{t("playbook.filter.dssCount", { count: counts.dss })}
                </button>
              )}
              {counts.engines > 0 && (
                <button type="button" aria-pressed={enginesOnly} title={t("playbook.filter.enginesHint")} onClick={() => setEnginesOnly((on) => !on)}
                  className={cn("hover:text-foreground flex items-center gap-1 rounded px-1", enginesOnly && "bg-warning/15 text-foreground")}>
                  <GitCompareArrows className="text-warning size-3.5" />{t("playbook.filter.enginesCount", { count: counts.engines })}
                </button>
              )}
              <span>{t("playbook.countsOf", { total: counts.total })}</span>
            </span>
          )}
          <div className="ml-auto flex items-center gap-1">
            {playbook && <PlaybookFileMenu id={playbook.id} title={playbook.title} />}
            <Button variant="ghost" size="sm" asChild>
              <a href={playbookApi.schemaUrl} target="_blank" rel="noreferrer"><FileJson /> {t("playbook.schema")}</a>
            </Button>
            <Button variant="ghost" size="sm" title={t("playbook.optionsHint")} onClick={() => setOptionsOpen(true)}><ListTree /> {t("playbook.options")}</Button>
          </div>
        </div>
      </div>

      <OptionsReferenceDialog open={optionsOpen} onOpenChange={setOptionsOpen} />
      <Dialog open={confirmRestart} onOpenChange={setConfirmRestart}>
        <DialogContent className="sm:max-w-md">
          <DialogHeader>
            <DialogTitle>{t("playbook.restartTitle")}</DialogTitle>
            <DialogDescription>{t("playbook.restartConfirm")}</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <Button variant="outline" size="sm" onClick={() => setConfirmRestart(false)}>{t("playbook.restartCancel")}</Button>
            <Button size="sm" variant="destructive" onClick={() => { setConfirmRestart(false); void clear() }}><RotateCcw /> {t("playbook.restart")}</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {(errors.length > 0 || warnings.length > 0) && (
        <div className={cn("max-h-40 overflow-auto border-b px-4 py-2 text-xs", errors.length > 0 ? "bg-destructive/5" : "bg-warning/5")}>
          <p className="mb-1 font-medium">{t("playbook.issues")} · {errors.length > 0 && t("playbook.errors", { count: errors.length })} {warnings.length > 0 && t("playbook.warnings", { count: warnings.length })}</p>
          <ul className="space-y-0.5">
            {loaded!.issues.map((i, n) => (
              <li key={n} className={i.isError ? "text-destructive" : "text-muted-foreground"}><code className="mr-2">{i.path}</code>{i.message}</li>
            ))}
          </ul>
        </div>
      )}

      {playbook && (state.inputs?.length ?? 0) > 0 && (
        <InputsBar inputs={state.inputs!} disabled={state.running} onChange={setState} />
      )}

      {!playbook ? (
        <div className="text-muted-foreground flex flex-1 items-center justify-center p-8 text-sm">{t("playbook.noPlaybook")}</div>
      ) : (
        <div className="flex min-h-0 flex-1">
          <aside className="flex w-[460px] shrink-0 flex-col border-r">
            <div className="space-y-2 border-b p-2">
              <TitleFilter value={titleQuery} onChange={setTitleQuery} />
              {tags.length > 0 && <TagFilter tags={tags} chosen={chosenTags} onChange={setChosenTags} />}
              <div className="flex flex-wrap items-center gap-1">
                <StatusFilterControl value={statusFilter} counts={filterCounts} onChange={setStatusFilter} />
                <button type="button" aria-pressed={dssOnly} title={t("playbook.filter.dssHint")} onClick={() => setDssOnly((on) => !on)}
                  className={cn("flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-1 text-xs tabular-nums transition-colors",
                    dssOnly ? "border-warning/60 bg-warning/15 font-medium" : "text-muted-foreground hover:text-foreground")}>
                  <AlertTriangle className="text-warning size-3.5" />{t("playbook.filter.dss")} {filterCounts.dss}
                </button>
                <button type="button" aria-pressed={enginesOnly} title={t("playbook.filter.enginesHint")} onClick={() => setEnginesOnly((on) => !on)}
                  className={cn("flex shrink-0 items-center gap-1 whitespace-nowrap rounded-md border px-1.5 py-1 text-xs tabular-nums transition-colors",
                    enginesOnly ? "border-warning/60 bg-warning/15 font-medium" : "text-muted-foreground hover:text-foreground")}>
                  <GitCompareArrows className="text-warning size-3.5" />{t("playbook.filter.engines")} {filterCounts.engines}
                </button>
              </div>
              {filtering && (
                <p className="text-muted-foreground flex items-center gap-2 px-1 text-[11px]">
                  {t("playbook.filter.shown", { shown: shownCount, total: steps.length })}
                  <button type="button" className="hover:text-foreground underline underline-offset-2" onClick={resetFilters}>{t("playbook.filter.clear")}</button>
                </p>
              )}
            </div>
            <ScrollArea className="min-h-0 flex-1">
              <div className="p-2">
                {shownCount === 0 && <p className="text-muted-foreground p-4 text-center text-xs">{t("playbook.filter.none")}</p>}
                {playbook.sections.map((section) => {
                  const shown = section.steps.filter(isShown)
                  if (shown.length === 0) return null
                  return (
                    <div key={section.id} className="mb-3">
                      <div className="flex items-center gap-1 px-2 py-1">
                        <p className="text-muted-foreground flex-1 text-xs font-semibold uppercase" title={section.description ?? undefined}>{section.title}</p>
                        <Button variant="ghost" size="icon" className="size-6" disabled={!canRun} aria-label={t("playbook.runSection")}
                          title={t("playbook.runSection")} onClick={() => start({ sectionId: section.id })}><Play className="size-3" /></Button>
                      </div>
                      {shown.map((s) => (
                        <StepRow key={s.id} step={s} view={views.get(s.id)} active={selected === s.id} canRun={canRun} defaultFormat={playbook.defaults.format}
                          chosenTags={chosenTags} onSelect={() => select(s.id)} onRun={() => start({ stepId: s.id })} onTag={addTag} onDss={() => setDssOnly(true)} onEngines={() => setEnginesOnly(true)} />
                      ))}
                    </div>
                  )
                })}
              </div>
            </ScrollArea>
          </aside>

          <section className="flex min-w-0 flex-1 flex-col border-r">
            {step
              ? <StepPlan key={step.id} step={step} engine={engine === "playbook" ? null : engine} view={views.get(step.id)} canRun={canRun}
                  onRun={() => start({ stepId: step.id })} onTag={addTag} />
              : <p className="text-muted-foreground p-6 text-sm">{t("playbook.noStep")}</p>}
          </section>

          <section className="w-[560px] shrink-0 overflow-auto">
            {step && <StepResultPanel step={step} view={views.get(step.id)} defaultFormat={playbook.defaults.format as Format} json={stepJson.get(step.id)} defaultsJson={defaultsJson}
              canClear={!state.running} onClear={() => void clear(step.id)} />}
          </section>
        </div>
      )}
    </div>
  )
}

/** The playbook's inputs: what to upload for each, the file uploaded (name, size, SHA-256), and a button to upload or replace it. */
function InputsBar({ inputs, disabled, onChange }: { inputs: PlaybookInputView[]; disabled: boolean; onChange: (state: PlaybookStateView) => void }) {
  const t = useT()
  const [busy, setBusy] = useState<string | null>(null)
  const pick = useRef<Record<string, HTMLInputElement | null>>({})

  const upload = async (input: PlaybookInputView, file: File) => {
    setBusy(input.id)
    try {
      const uploaded = await api.uploadFile(file)
      onChange(await playbookApi.setInput(input.id, uploaded.id))
      toast.success(t("playbook.inputUploaded", { name: uploaded.fileName }))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  const remove = async (input: PlaybookInputView) => {
    setBusy(input.id)
    try {
      onChange(await playbookApi.removeInput(input.id))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="border-b px-4 py-2">
      <p className="mb-1.5 flex items-center gap-1.5 text-xs font-medium" title={t("playbook.inputsHint")}>
        <Paperclip className="size-3.5" />{t("playbook.inputs")}
        <span className="text-muted-foreground font-normal">· {t("playbook.inputsHint")}</span>
      </p>
      <div className="flex flex-wrap gap-2">
        {inputs.map((input) => (
          <div key={input.id} className={cn("flex min-w-0 max-w-full items-center gap-2 rounded-md border px-2 py-1.5 text-xs",
            input.file ? "border-success/40" : "border-warning/50 bg-warning/5")}>
            <div className="min-w-0">
              <p className="truncate font-medium" title={input.description ?? undefined}>{input.title}</p>
              <p className="text-muted-foreground truncate font-mono text-[10px]"
                title={input.file ? `SHA-256 ${input.file.sha256}` : undefined}>
                input:{input.id} · {input.file
                  ? <a className="hover:text-foreground underline underline-offset-2" href={api.fileUrl(input.file.fileId)} target="_blank" rel="noreferrer">
                      {input.file.fileName} ({input.file.size.toLocaleString()} B)</a>
                  : t("playbook.inputMissing")}
              </p>
            </div>
            <input ref={(el) => { pick.current[input.id] = el }} type="file" accept={input.accept ?? undefined} className="hidden"
              onChange={(e) => { const f = e.target.files?.[0]; if (f) void upload(input, f); e.target.value = "" }} />
            <Button size="sm" variant={input.file ? "outline" : "default"} className="h-7 shrink-0" disabled={disabled || busy === input.id}
              onClick={() => pick.current[input.id]?.click()}>
              {busy === input.id ? <Loader2 className="animate-spin" /> : <Upload />} {input.file ? t("playbook.inputReplace") : t("playbook.inputUpload")}
            </Button>
            {input.file && (
              <Button size="icon" variant="ghost" className="size-7 shrink-0" disabled={disabled || busy === input.id}
                aria-label={t("playbook.inputRemove")} title={t("playbook.inputRemove")} onClick={() => void remove(input)}><X /></Button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}

function EvidenceLink({ enabled, href, newTab, children }: { enabled: boolean; href: string; newTab?: boolean; children: React.ReactNode }) {
  const t = useT()
  if (!enabled) {
    return <Button variant="outline" size="sm" disabled title={t("playbook.evidenceEmpty")}>{children}</Button>
  }
  return (
    <Button variant="outline" size="sm" asChild>
      <a href={href} {...(newTab ? { target: "_blank", rel: "noreferrer" } : { download: true })}>{children}</a>
    </Button>
  )
}

/** Narrows the steps to those whose title or id contains the text (case and accents ignored). */
function TitleFilter({ value, onChange }: { value: string; onChange: (value: string) => void }) {
  const t = useT()
  return (
    <div className="border-input focus-within:ring-ring/50 focus-within:border-ring flex min-h-8 items-center gap-1.5 rounded-md border px-2 py-1 focus-within:ring-[3px]">
      <Search className="text-muted-foreground size-3.5 shrink-0" aria-hidden />
      <input value={value} aria-label={t("playbook.filter.title")} placeholder={t("playbook.filter.title")}
        className="placeholder:text-muted-foreground min-w-0 flex-1 bg-transparent text-xs outline-none"
        onChange={(e) => onChange(e.target.value)} onKeyDown={(e) => { if (e.key === "Escape") onChange("") }} />
      {value && (
        <button type="button" aria-label={t("playbook.filter.clearTitle")} title={t("playbook.filter.clearTitle")}
          className="text-muted-foreground hover:text-foreground" onClick={() => onChange("")}><X className="size-3.5" /></button>
      )}
    </div>
  )
}

/** All | passed | failed | not run, as buttons joined together, each with how many steps it would show. */
function StatusFilterControl({ value, counts, onChange }: {
  value: StatusFilter
  counts: Record<StatusFilter, number>
  onChange: (value: StatusFilter) => void
}) {
  const t = useT()
  const options: { id: StatusFilter; icon?: React.ReactNode }[] = [
    { id: "all" },
    { id: "passed", icon: <CheckCircle2 className="text-success size-3.5" /> },
    { id: "failed", icon: <XCircle className="text-destructive size-3.5" /> },
    { id: "notRun", icon: <Circle className="text-muted-foreground size-3.5" /> },
  ]
  return (
    <div className="bg-muted flex shrink-0 rounded-md p-0.5 text-xs" role="radiogroup" aria-label={t("playbook.filter.status")}>
      {options.map(({ id, icon }) => {
        const name = t(`playbook.filter.${id}` as MessageKey)
        return (
          <button key={id} type="button" role="radio" aria-checked={value === id} title={name} aria-label={`${name} (${counts[id]})`}
            onClick={() => onChange(id)}
            className={cn("flex items-center gap-1 rounded px-2 py-1 tabular-nums transition-all",
              value === id ? "bg-background font-medium shadow-sm" : "text-muted-foreground hover:text-foreground")}>
            {icon ?? name} {counts[id]}
          </button>
        )
      })}
    </div>
  )
}

/** Picks tags by typing: suggestions as you type, several at once; a step shows when it has any of them. */
function TagFilter({ tags, chosen, onChange }: { tags: string[]; chosen: string[]; onChange: (tags: string[]) => void }) {
  const t = useT()
  const [query, setQuery] = useState("")
  const [open, setOpen] = useState(false)
  const [active, setActive] = useState(0)
  const input = useRef<HTMLInputElement>(null)
  const options = tags.filter((x) => !chosen.includes(x) && x.toLowerCase().includes(query.trim().toLowerCase()))

  const add = (x: string) => {
    onChange([...chosen, x])
    setQuery("")
    setActive(0)
    input.current?.focus()
  }

  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowDown") { e.preventDefault(); setOpen(true); setActive((a) => Math.min(a + 1, options.length - 1)) }
    else if (e.key === "ArrowUp") { e.preventDefault(); setActive((a) => Math.max(a - 1, 0)) }
    else if (e.key === "Enter" && options[active]) { e.preventDefault(); add(options[active]) }
    else if (e.key === "Backspace" && query === "" && chosen.length > 0) onChange(chosen.slice(0, -1))
    else if (e.key === "Escape") { setOpen(false); input.current?.blur() }
  }

  return (
    <div className="relative">
      <div className="border-input focus-within:ring-ring/50 focus-within:border-ring flex min-h-8 flex-wrap items-center gap-1 rounded-md border px-2 py-1 focus-within:ring-[3px]"
        onClick={() => input.current?.focus()}>
        <Tag className="text-muted-foreground size-3.5 shrink-0" aria-hidden />
        {chosen.map((x) => (
          <span key={x} className="bg-primary/10 text-primary flex items-center gap-0.5 rounded px-1.5 py-0.5 font-mono text-[11px]">
            {x}
            <button aria-label={t("playbook.removeTag", { tag: x })} className="hover:text-foreground" onClick={(e) => { e.stopPropagation(); onChange(chosen.filter((c) => c !== x)) }}>
              <X className="size-3" />
            </button>
          </span>
        ))}
        <input ref={input} value={query} role="combobox" aria-expanded={open} aria-label={t("playbook.tags")}
          placeholder={chosen.length === 0 ? t("playbook.tagPlaceholder", { count: tags.length }) : ""}
          className="placeholder:text-muted-foreground min-w-16 flex-1 bg-transparent text-xs outline-none"
          onChange={(e) => { setQuery(e.target.value); setActive(0); setOpen(true) }}
          onFocus={() => setOpen(true)} onBlur={() => setOpen(false)} onKeyDown={onKeyDown} />
        {chosen.length > 0 && (
          <button aria-label={t("playbook.clearTag")} title={t("playbook.clearTag")} className="text-muted-foreground hover:text-foreground"
            onClick={(e) => { e.stopPropagation(); onChange([]) }}><X className="size-3.5" /></button>
        )}
      </div>
      {open && (
        <ul role="listbox" className="bg-popover text-popover-foreground absolute inset-x-0 z-30 mt-1 max-h-64 overflow-auto rounded-md border p-1 shadow-md">
          {options.length === 0
            ? <li className="text-muted-foreground px-2 py-1.5 text-xs">{t("playbook.noTag")}</li>
            : options.map((x, i) => (
              <li key={x} role="option" aria-selected={i === active}
                className={cn("cursor-pointer rounded px-2 py-1 font-mono text-xs", i === active && "bg-accent text-accent-foreground")}
                onMouseEnter={() => setActive(i)} onMouseDown={(e) => { e.preventDefault(); add(x) }}>{x}</li>
            ))}
        </ul>
      )}
    </div>
  )
}

function StepRow({ step, view, active, canRun, defaultFormat, chosenTags, onSelect, onRun, onTag, onDss, onEngines }: {
  step: PlaybookStep
  view?: PlaybookStepView
  active: boolean
  canRun: boolean
  defaultFormat: string
  chosenTags: string[]
  onSelect: () => void
  onRun: () => void
  onTag: (tag: string) => void
  onDss: () => void
  onEngines: () => void
}) {
  const t = useT()
  return (
    <div className={cn("group hover:bg-muted flex items-start gap-2 rounded-md px-2 py-1.5", active && "bg-muted")}>
      <button className="flex min-w-0 flex-1 items-start gap-2 text-left" onClick={onSelect}>
        <StatusIcon status={view?.status ?? "pending"} />
        <span className="min-w-0 flex-1">
          <span className="block text-sm leading-snug">{step.title}</span>
          <span className="mt-0.5 flex flex-wrap items-center gap-1">
            <span className="text-muted-foreground font-mono text-[10px] uppercase">{step.kind === "validate" ? t("playbook.kindValidate") : step.kind === "augment" ? t("playbook.kindAugment") : step.format ?? defaultFormat}</span>
            {dssDiffers(view) && (
              <span role="button" tabIndex={-1} title={t("playbook.filter.dssRow")} onClick={(e) => { e.stopPropagation(); onDss() }}
                className="border-warning/50 bg-warning/10 hover:bg-warning/20 flex items-center gap-0.5 rounded border px-1 font-mono text-[10px]">
                <AlertTriangle className="text-warning size-2.5" />DSS
              </span>
            )}
            {enginesDiffer(view) && (
              <span role="button" tabIndex={-1} title={t("playbook.filter.enginesRow")} onClick={(e) => { e.stopPropagation(); onEngines() }}
                className="border-warning/50 bg-warning/10 hover:bg-warning/20 flex items-center gap-0.5 whitespace-nowrap rounded border px-1 font-mono text-[10px]">
                <GitCompareArrows className="text-warning size-2.5" />LIB≠CLI
              </span>
            )}
            {step.tags.map((x) => (
              <span key={x} role="button" tabIndex={-1} title={t("playbook.filterByTag", { tag: x })} onClick={(e) => { e.stopPropagation(); onTag(x) }}
                className={cn("rounded px-1 font-mono text-[10px]", chosenTags.includes(x) ? "bg-primary/15 text-primary" : "bg-muted-foreground/10 hover:bg-muted-foreground/20")}>{x}</span>
            ))}
          </span>
        </span>
      </button>
      <Button variant="ghost" size="icon" className="size-6 opacity-0 group-hover:opacity-100 focus-visible:opacity-100" disabled={!canRun}
        aria-label={t("playbook.runStep")} title={t("playbook.runStep")} onClick={onRun}><Play className="size-3" /></Button>
    </div>
  )
}

const itemKeys = new Set([
  "engine", "crossValidate", "format", "document", "existingSignatures", "data", "file", "signer", "playbook", "subject", "issuer", "key", "valid", "nonRepudiation", "source",
  "crl", "ocsp", "tsa", "trustedList", "revoke",
  "outcome", "reason", "indication", "subIndication", "level", "dssAgrees", "etsiReport", "failedConstraints", "logContains",
])
const validationKeys = new Set(["trust", "policy", "level", "revocation"])

/** A preview card: one look for every block (what is signed, the signer, the Sandbox, the expectation, each group of settings). */
interface Card {
  id: string
  title: string
  badge?: string
  tone?: "info"
  rows: { label: string; value: string; mono?: boolean; fromPlaybook?: boolean; changed?: boolean }[]
  footer?: string
  defaultOpen: boolean
}

/** Column 2: everything the step will do, before it runs: an overview of cards, and the C# and CLI that do the same. */
function StepPlan({ step, engine, view, canRun, onRun, onTag }: {
  step: PlaybookStep
  engine: string | null
  view?: PlaybookStepView
  canRun: boolean
  onRun: () => void
  onTag: (tag: string) => void
}) {
  const t = useT()
  const [preview, setPreview] = useState<PlaybookStepPreview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [open, setOpen] = useState<Record<string, boolean>>({})
  const { locale } = useI18n()
  // A step that names step:ID shows that step's file once it ran: fetch again when a result arrives.
  const resultAt = view?.result?.at ?? null
  useEffect(() => {
    let live = true
    setLoading(true)
    setError(null)
    playbookApi.preview(step.id, engine)
      .then((p) => { if (live) setPreview(p) })
      .catch((e) => { if (live) { setPreview(null); setError((e as Error).message) } })
      .finally(() => { if (live) setLoading(false) })
    return () => { live = false }
  }, [step.id, engine, resultAt, locale])

  const value = useCallback((raw: string) => {
    switch (raw) {
      case "yes": return t("common.yes")
      case "no": return t("common.no")
      case "on": return t("playbook.on")
      case "off": return t("playbook.off")
      case "": return t("playbook.libraryDefault")
      default: return raw.startsWith("step:") ? t("playbook.fileOfStep", { step: raw.slice(5) })
        : raw.startsWith("input:") ? t("playbook.fileOfInput", { input: raw.slice(6) }) : raw
    }
  }, [t])
  const label = useCallback((i: PreviewItem) => itemKeys.has(i.key) ? t(`playbook.item.${i.key}` as MessageKey) : i.label, [t])

  const cards = useMemo<Card[]>(() => {
    if (!preview) return []
    const items = (list: PreviewItem[], mono?: boolean) => list.map((i) => ({ label: label(i), value: value(i.value), mono }))
    const list: Card[] = [
      {
        id: "run", title: t("playbook.runCard"), defaultOpen: true,
        rows: [
          { label: t("playbook.item.engine"), value: engineLabel(t, preview.engine) },
          {
            label: t("playbook.item.crossValidate"),
            value: `${t(preview.crossValidate ? "playbook.on" : "playbook.off")} (${t(preview.crossValidateFrom === "step" ? "playbook.fromStep" : "playbook.fromDefaults")})`,
            changed: preview.crossValidate,
          },
          ...(preview.crossValidate ? [{ label: "", value: t("playbook.crossValidateNote") }] : []),
        ],
      },
      { id: "target", title: t(preview.kind === "validate" ? "playbook.validated" : "playbook.signed"), rows: items(preview.target), defaultOpen: true },
    ]
    if (preview.kind !== "validate") list.push({ id: "signer", title: t("playbook.signer"), rows: items(preview.signer), defaultOpen: true })
    if (preview.sandbox.length > 0) {
      list.push({ id: "sandbox", title: t("playbook.sandbox"), tone: "info", rows: items(preview.sandbox, true), footer: t("playbook.sandboxBack"), defaultOpen: true })
    }
    list.push({ id: "expect", title: t("playbook.expect"), rows: items(preview.expect, true), defaultOpen: true })
    for (const g of preview.groups) {
      const fromPlaybook = g.settings.filter((s) => s.fromPlaybook).length
      const validation = g.id === "validation"
      list.push({
        id: `group:${g.id}`,
        title: validation ? t("playbook.validation.title") : g.title,
        badge: fromPlaybook > 0 ? t("playbook.fromPlaybookCount", { count: fromPlaybook }) : undefined,
        rows: g.settings.map((s) => ({
          label: validation && validationKeys.has(s.id) ? t(`playbook.validation.${s.id}` as MessageKey) : s.title,
          value: value(s.value), fromPlaybook: s.fromPlaybook, changed: s.changed,
        })),
        defaultOpen: fromPlaybook > 0,
      })
    }
    return list
  }, [preview, t, label, value])

  const isOpen = (c: Card) => open[c.id] ?? c.defaultOpen
  const allOpen = cards.length > 0 && cards.every(isOpen)
  const status = view?.status ?? "pending"
  const notes = preview ? [
    ...(preview.needsInputs ?? []).map((i) => ({ tone: "warning" as const, text: t("playbook.needsInput", { input: i }) })),
    ...preview.needsSteps.map((s) => ({ tone: "warning" as const, text: t("playbook.needsStep", { step: s }) })),
    ...(preview.codeError ? [{ tone: "warning" as const, text: t("playbook.codeError", { error: preview.codeError }) }] : []),
    ...preview.issues.map((i) => ({ tone: i.severity === "Error" ? "error" as const : "muted" as const, text: i.message })),
  ] : []

  return (
    <Tabs defaultValue="overview" className="flex min-h-0 flex-1 flex-col gap-0">
      <div className="space-y-2 border-b px-5 pt-4">
        <div className="flex flex-wrap items-start gap-2">
          <StatusIcon status={status} />
          <div className="min-w-0 flex-1">
            <h2 className="text-base font-semibold leading-snug">{step.title}</h2>
            <p className="text-muted-foreground font-mono text-xs">{step.id}{preview && ` · ${preview.kind === "validate" ? t("playbook.kindValidate") : preview.kind === "augment" ? `${t("playbook.kindAugment")} · ${preview.format}` : preview.format} · ${engineLabel(t, preview.engine)}${preview.crossValidate ? " · DSS" : ""}`}</p>
          </div>
          <Button size="sm" disabled={!canRun} onClick={onRun}>{status === "running" ? <Loader2 className="animate-spin" /> : <Play />} {t("playbook.runStep")}</Button>
        </div>
        {step.description && <p className="text-sm whitespace-pre-line">{step.description}</p>}
        {step.tags.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {step.tags.map((x) => (
              <button key={x} title={t("playbook.filterByTag", { tag: x })} onClick={() => onTag(x)}
                className="bg-muted hover:bg-muted-foreground/20 rounded px-1.5 py-0.5 font-mono text-[11px]">{x}</button>
            ))}
          </div>
        )}
        <div className="flex items-end gap-2">
          <TabsList variant="line" className="-mb-px">
            <TabsTrigger value="overview">{t("playbook.tabOverview")}</TabsTrigger>
            <TabsTrigger value="csharp" disabled={!preview?.code}>C#</TabsTrigger>
            <TabsTrigger value="cli" disabled={!preview?.code}>CLI</TabsTrigger>
          </TabsList>
          {cards.length > 0 && (
            <Button variant="ghost" size="sm" className="text-muted-foreground mb-1 ml-auto h-7 text-xs"
              onClick={() => setOpen(Object.fromEntries(cards.map((c) => [c.id, !allOpen])))}>
              {allOpen ? <ChevronsDownUp /> : <ChevronsUpDown />} {t(allOpen ? "playbook.collapseAll" : "playbook.expandAll")}
            </Button>
          )}
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {error && <p className="text-destructive p-5 text-sm">{error}</p>}
        {loading && !preview && <p className="text-muted-foreground flex items-center gap-2 p-5 text-sm"><Loader2 className="size-4 animate-spin" /> {t("playbook.preparing")}</p>}
        {preview && (
          <div className={cn(loading && "opacity-60")}>
            <TabsContent value="overview" className="space-y-2 p-5">
              {notes.map((n, i) => (
                <p key={i} className={cn("rounded-md border px-3 py-2 text-xs",
                  n.tone === "warning" && "bg-warning/10 border-warning/40", n.tone === "error" && "text-destructive border-destructive/40", n.tone === "muted" && "text-muted-foreground")}>{n.text}</p>
              ))}
              {cards.map((c) => <PlanCard key={c.id} card={c} open={isOpen(c)} onOpenChange={(o) => setOpen((s) => ({ ...s, [c.id]: o }))} />)}
              <p className="text-muted-foreground flex items-center gap-2 pt-1 text-[11px]">
                <span className="bg-primary inline-block size-1.5 rounded-full" /> {t("playbook.legendPlaybook")} · <span className="text-foreground font-medium">{t("playbook.legendBold")}</span> {t("playbook.legendChanged")}
              </p>
            </TabsContent>
            {preview.code && (
              <>
                <TabsContent value="csharp" className="p-5"><HighlightedCode code={preview.code.cSharp} language="csharp" /></TabsContent>
                <TabsContent value="cli" className="space-y-3 p-5">
                  <HighlightedCode code={preview.code.cli} language="shell" />
                  {preview.code.cliNotes.length > 0 && <ul className="text-muted-foreground space-y-1 text-xs">{preview.code.cliNotes.map((n, i) => <li key={i}>• {n}</li>)}</ul>}
                </TabsContent>
              </>
            )}
          </div>
        )}
      </div>
    </Tabs>
  )
}

function PlanCard({ card, open, onOpenChange }: { card: Card; open: boolean; onOpenChange: (open: boolean) => void }) {
  return (
    <Collapsible open={open} onOpenChange={onOpenChange} className={cn("rounded-md border", card.tone === "info" && "border-info/50 bg-info/5")}>
      <CollapsibleTrigger className="group hover:bg-muted/40 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left">
        <ChevronRight className="text-muted-foreground size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
        <span className="flex-1 text-xs font-semibold uppercase">{card.title}</span>
        {card.badge && <span className="text-primary flex items-center gap-1 text-[11px]"><span className="bg-primary size-1.5 rounded-full" />{card.badge}</span>}
      </CollapsibleTrigger>
      <CollapsibleContent className="px-3 pb-2">
        {card.rows.length === 0
          ? <p className="text-muted-foreground pl-5.5 text-xs">—</p>
          : (
            <dl className="grid grid-cols-[minmax(8rem,38%)_1fr] gap-x-3 gap-y-1 pl-5.5 text-xs">
              {card.rows.map((r, n) => (
                <div key={n} className="contents">
                  <dt className="text-muted-foreground flex items-start gap-1.5">
                    <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", r.fromPlaybook ? "bg-primary" : "bg-transparent")} />
                    {r.label}
                  </dt>
                  <dd className={cn("break-words", r.mono && "font-mono", r.changed && "font-medium", r.fromPlaybook && "text-primary")}>{r.value}</dd>
                </div>
              ))}
            </dl>
          )}
        {card.footer && <p className="text-muted-foreground mt-1.5 pl-5.5 text-xs">{card.footer}</p>}
      </CollapsibleContent>
    </Collapsible>
  )
}

/** Column 3: the latest result of the step, every engine with every detail. */
function StepResultPanel({ step, view, defaultFormat, json, defaultsJson, canClear, onClear }: {
  step: PlaybookStep
  view?: PlaybookStepView
  defaultFormat: Format
  json?: string
  defaultsJson?: string | null
  canClear: boolean
  onClear: () => void
}) {
  const t = useT()
  const { locale } = useI18n()
  const result = view?.result
  if (view?.status === "running" || view?.status === "queued") {
    return (
      <div className="space-y-3 p-5">
        <p className="text-muted-foreground flex items-center gap-2 text-sm">
          {view.status === "running" ? <Loader2 className="size-4 animate-spin" /> : <Clock className="size-4" />} {t(view.status === "running" ? "playbook.running" : "playbook.queued")}
        </p>
        {result && <p className="text-muted-foreground text-xs">{t("playbook.previous")}</p>}
      </div>
    )
  }
  if (!result) {
    return (
      <div className="space-y-3 p-5">
        <p className="text-muted-foreground text-sm">{t("playbook.notRun")}</p>
        {json && (
          <div className="space-y-1">
            <p className="flex items-center gap-1.5 text-xs font-semibold uppercase"><FileJson className="size-3.5" /> {t("playbook.stepJson")}</p>
            <p className="text-muted-foreground text-xs">{t("playbook.stepJsonHint")}</p>
            <HighlightedCode code={json} language="json" />
          </div>
        )}
        {defaultsJson && (
          <Collapsible className="rounded-md border">
            <CollapsibleTrigger className="group hover:bg-muted/40 flex w-full items-center gap-2 rounded-md px-3 py-2 text-left">
              <ChevronRight className="text-muted-foreground size-3.5 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
              <span className="flex-1 text-xs font-semibold uppercase">{t("playbook.defaultsJson")}</span>
            </CollapsibleTrigger>
            <CollapsibleContent className="space-y-1 px-3 pb-3">
              <p className="text-muted-foreground text-xs">{t("playbook.defaultsJsonHint")}</p>
              <HighlightedCode code={defaultsJson} language="json" />
            </CollapsibleContent>
          </Collapsible>
        )}
      </div>
    )
  }
  return (
    <div className="space-y-3 p-5">
      <div className="flex flex-wrap items-center gap-2">
        <StatusIcon status={result.status} />
        <span className="text-sm font-semibold">{t(`playbook.status.${result.status}` as MessageKey)}</span>
        <span className="text-muted-foreground ml-auto text-xs">{t("playbook.ranAt", { at: new Date(result.at).toLocaleString(locale), ms: result.ms })}</span>
        <Button variant="ghost" size="sm" className="h-7 text-xs" disabled={!canClear} onClick={onClear} title={t("playbook.clearResultHint")}><Eraser /> {t("playbook.clearResult")}</Button>
      </div>
      {result.message && <p className={cn("text-sm", result.status === "skipped" ? "text-warning" : "text-destructive")}>{result.message}</p>}
      {result.engineDifferences && result.engineDifferences.length > 0 && <EngineDifferences differences={result.engineDifferences} />}
      {result.runs.map((r) => <EngineRunCard key={r.engine + r.runId} result={r} format={(step.format as Format) ?? defaultFormat} />)}
    </div>
  )
}

/** Where the library and the CLI reached different verdicts on the same step. */
function EngineDifferences({ differences }: { differences: PlaybookEngineDifference[] }) {
  const t = useT()
  return (
    <div className="border-warning/50 bg-warning/10 space-y-2 rounded-lg border p-3">
      <p className="flex items-center gap-2 text-sm font-medium"><GitCompareArrows className="text-warning size-4" />{t("playbook.enginesDiffer")}</p>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>{t("playbook.enginesWhat")}</TableHead>
            <TableHead>{t("playbook.engineLibrary")}</TableHead>
            <TableHead>{t("playbook.engineCli")}</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {differences.map((d) => (
            <TableRow key={d.what}>
              <TableCell className="font-mono text-xs">{d.what}</TableCell>
              <TableCell className="font-mono text-xs break-all whitespace-normal">{d.library ?? "—"}</TableCell>
              <TableCell className="font-mono text-xs break-all whitespace-normal">{d.cli ?? "—"}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

function EngineRunCard({ result, format }: { result: PlaybookEngineRun; format: Format }) {
  const t = useT()
  const [run, setRun] = useState<RunView | null>(null)
  useEffect(() => {
    let live = true
    api.workbench.run(result.runId).then((r) => { if (live && r) setRun(r) }).catch(() => undefined)
    return () => { live = false }
  }, [result.runId])
  return (
    <div className="space-y-2 rounded-lg border p-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        {result.passed ? <CheckCircle2 className="text-success size-4" /> : <XCircle className="text-destructive size-4" />}
        <span className="font-medium uppercase">{result.engine}</span>
        <span className="text-muted-foreground text-xs">{t("playbook.run", { id: result.runId, ms: result.ms })}</span>
        {result.dssAgrees !== null && result.dssAgrees !== undefined && <Pill tone={result.dssAgrees ? "success" : "warning"}>{t(result.dssAgrees ? "playbook.dssAgrees" : "playbook.dssDiffers")}</Pill>}
        {result.crossValidated && (result.dssAgrees === null || result.dssAgrees === undefined) && (
          <span title={result.dssError ?? undefined}><Pill tone="warning">{t("playbook.dssUnavailable")}</Pill></span>
        )}
      </div>
      <Table>
        <TableHeader><TableRow><TableHead>{t("playbook.check")}</TableHead><TableHead>{t("playbook.expected")}</TableHead><TableHead>{t("playbook.found")}</TableHead></TableRow></TableHeader>
        <TableBody>
          {result.checks.map((c, i) => (
            <TableRow key={i}>
              <TableCell className="font-mono text-xs">{c.what}</TableCell>
              <TableCell className="text-xs whitespace-normal">{c.expected}</TableCell>
              <TableCell className={cn("text-xs whitespace-normal", c.passed ? "text-success" : "text-destructive font-medium")}>{c.found}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      {(result.achievedLevel || result.indication) && (
        <p className="text-muted-foreground text-xs">
          {result.achievedLevel && <>{t("playbook.level")}: <span className="text-foreground font-mono">{result.achievedLevel}</span> </>}
          {result.indication && <>· {result.indication}{result.subIndication && ` / ${result.subIndication}`}</>}
        </p>
      )}
      {result.error && <p className="text-muted-foreground text-xs break-words">{result.errorType}: {result.error}</p>}
      <div className="flex flex-wrap items-center gap-2">
        {result.reportId && <ReportButtons source="simplesign" reportId={result.reportId} />}
        {run?.crossValidation?.reportId && <ReportButtons source="dss" reportId={run.crossValidation.reportId} />}
        {result.outputId && <Button variant="outline" size="sm" asChild><a href={api.fileUrl(result.outputId, true)}><Download /> {result.fileName ?? t("playbook.output")}</a></Button>}
        {result.etsiReportId && <Button variant="outline" size="sm" asChild><a href={api.fileUrl(result.etsiReportId, true)}><Download /> {t("playbook.etsi")}</a></Button>}
        {result.reportId && <Button variant="ghost" size="sm" asChild><a href={api.fileUrl(result.reportId, true)}><Download /> JSON</a></Button>}
      </div>
      {run?.cli && run.cli.length > 0 && <CliSteps steps={run.cli} />}
      {run && (
        <Collapsible>
          <CollapsibleTrigger className="group flex items-center gap-1 text-sm font-medium">
            <ChevronRight className="size-3.5 transition-transform group-data-[state=open]:rotate-90" /> {t("playbook.log")}
          </CollapsibleTrigger>
          <CollapsibleContent className="pt-2"><LogView logs={run.logs} format={run.format ?? format} running={false} /></CollapsibleContent>
        </Collapsible>
      )}
    </div>
  )
}

function engineLabel(t: ReturnType<typeof useT>, engine: string) {
  return engine === "library" ? t("playbook.engineLibrary") : engine === "cli" ? t("playbook.engineCli") : engine === "both" ? t("playbook.engineBoth") : engine
}

function StatusIcon({ status }: { status: PlaybookStatus }) {
  switch (status) {
    case "passed":
      return <CheckCircle2 className="text-success mt-0.5 size-4 shrink-0" />
    case "failed":
      return <XCircle className="text-destructive mt-0.5 size-4 shrink-0" />
    case "running":
      return <Loader2 className="text-info mt-0.5 size-4 shrink-0 animate-spin" />
    case "queued":
      return <Clock className="text-info mt-0.5 size-4 shrink-0" />
    case "skipped":
      return <SkipForward className="text-warning mt-0.5 size-4 shrink-0" />
    default:
      return <Circle className="text-muted-foreground mt-0.5 size-4 shrink-0" />
  }
}
