import { useState } from "react"
import { CircleAlert, History, Loader2, PenTool, RotateCcw, ShieldCheck, Shuffle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { Switch } from "@/components/ui/switch"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useI18n, useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { IssueList, Pill } from "../shared/ui"
import { OptionForm } from "./OptionForm"
import { frameworkTone, StandardBadge } from "./parts"
import { ResultPanel } from "./ResultPanel"
import { asText } from "./schema"
import { useWorkbench } from "./state"

/**
 * The single screen: pick a format, set any option on the left, sign, and read the result, the
 * verdicts, the log and the code on the right. Every option names its clause of the standard.
 */
export function WorkbenchPage() {
  const { evaluation } = useWorkbench()
  return (
    <div className="flex h-full min-h-0 flex-col">
      <TopBar />
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(400px,5fr)_7fr]">
        <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
          {evaluation && <IssueList issues={evaluation.issues} />}
          <OptionForm />
        </div>
        <div className="min-h-0 overflow-y-auto p-4"><ResultPanel /></div>
      </div>
    </div>
  )
}

function TopBar() {
  const { schema, format, setFormat, frameworks, toggleFramework, applyPreset, options, evaluation, evaluating, running, sign, reset } = useWorkbench()
  const t = useT()
  const current = schema.formats.find((f) => f.id === format)!
  const errors = evaluation?.issues.filter((i) => i.severity === "Error").length ?? 0
  const level = asText(options.level)
  const baseline = asText(options.kind) !== "IcpBrasil" && asText(options.mode) !== "Fiscal"
  return (
    <div className="space-y-2.5 border-b px-4 py-3">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
        <div className="bg-muted flex rounded-lg p-0.5" role="radiogroup" aria-label={t("wb.format")}>
          {schema.formats.map((f) => (
            <button key={f.id} role="radio" aria-checked={format === f.id} onClick={() => setFormat(f.id)}
              className={cn("rounded-md px-4 py-1.5 text-sm font-semibold transition-all", format === f.id ? "bg-background shadow-sm" : "text-muted-foreground hover:text-foreground")}>
              {f.title}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1" role="group" aria-label={t("wb.presets")}>
          {schema.presets.filter((p) => p.formats.includes(format)).map((p) => (
            <Tooltip key={p.id}>
              <TooltipTrigger asChild>
                <Button variant={baseline && p.set.level === level ? "default" : "outline"} size="sm" className="h-8 px-2.5 font-mono text-xs" onClick={() => applyPreset(p)}>{p.title}</Button>
              </TooltipTrigger>
              <TooltipContent>{p.summary}</TooltipContent>
            </Tooltip>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <VaryControl />
          <DssControl />
          <HistoryDrawer />
          <Tooltip>
            <TooltipTrigger asChild><Button variant="ghost" size="icon" aria-label={t("wb.reset")} onClick={reset}><RotateCcw /></Button></TooltipTrigger>
            <TooltipContent>{t("wb.reset")}</TooltipContent>
          </Tooltip>
          <Button disabled={running || errors > 0 || !evaluation} onClick={() => sign()} className="min-w-36">
            {running ? <Loader2 className="animate-spin" /> : <PenTool />}
            {t("wb.sign")}{evaluation?.effectiveLevel ? ` · ${evaluation.effectiveLevel}` : ""}
          </Button>
        </div>
      </div>
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1.5 text-xs">
        <span className="text-muted-foreground">{current.summary}</span>
        <StandardBadge explanation={{ title: current.title, summary: current.summary, standards: current.standards, api: current.signerApi }} />
        <span className="text-muted-foreground ml-auto flex items-center gap-1.5">
          {t("wb.frameworks")}
          {schema.frameworks.map((f) => {
            const on = frameworks.has(f.id)
            const tone = frameworkTone[f.id]
            return (
              <Tooltip key={f.id}>
                <TooltipTrigger asChild>
                  <button type="button" role="switch" aria-checked={on} disabled={f.status !== "available"} onClick={() => toggleFramework(f.id)}
                    className={cn("rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors",
                      f.status !== "available" ? "cursor-not-allowed border-dashed opacity-50" : on ? tone?.chip : "hover:border-foreground/40 hover:text-foreground")}>
                    {on ? "✓ " : "+ "}{f.title}{f.status !== "available" && ` · ${t("wb.planned")}`}
                  </button>
                </TooltipTrigger>
                <TooltipContent className="max-w-72">{f.summary}</TooltipContent>
              </Tooltip>
            )
          })}
        </span>
        {errors > 0 && <span className="text-destructive flex items-center gap-1"><CircleAlert className="size-3.5" />{t("wb.errors", { n: errors })}</span>}
        {evaluating && <Loader2 className="text-muted-foreground size-3 animate-spin" />}
      </div>
    </div>
  )
}

/** Signs once per value of one option, keeping everything else: every level, every digest, every packaging… */
function VaryControl() {
  const { schema, isVisible, visibleValues, runVariants, variantsRunning, running, evaluation } = useWorkbench()
  const t = useT()
  const [open, setOpen] = useState(false)
  const [optionId, setOptionId] = useState<string>("")
  const candidates = schema.options.filter((o) => o.kind === "choice" && o.path && o.support === "supported" && isVisible(o)
    && visibleValues(o).filter((v) => v.support === "supported").length > 1)
  const chosen = candidates.find((o) => o.id === optionId) ?? candidates.find((o) => o.path === "level") ?? candidates[0]
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-8"><Shuffle /> {t("wb.variants.title")}</Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 space-y-3 text-sm">
        <div>
          <p className="font-medium">{t("wb.variants.title")}</p>
          <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.variants.about")}</p>
        </div>
        <Select value={chosen?.id ?? ""} onValueChange={setOptionId}>
          <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
          <SelectContent>
            {candidates.map((o) => <SelectItem key={o.id} value={o.id}>{schema.sections.find((s) => s.id === o.section)?.title} · {o.title} ({visibleValues(o).length})</SelectItem>)}
          </SelectContent>
        </Select>
        <Button className="w-full" disabled={!chosen || variantsRunning || running || !evaluation} onClick={() => { setOpen(false); void runVariants(chosen!) }}>
          {variantsRunning ? <Loader2 className="animate-spin" /> : <Shuffle />}
          {chosen ? t("wb.variants.run", { n: visibleValues(chosen).filter((v) => v.support === "supported").length }) : t("wb.variants.title")}
        </Button>
      </PopoverContent>
    </Popover>
  )
}

/** Cross-validation with the EU DSS: on or off, where it is, and whether it answers. */
function DssControl() {
  const { dss, dssStatus, saveDss, checkDss } = useWorkbench()
  const t = useT()
  const [url, setUrl] = useState<string | null>(null)
  return (
    <Popover onOpenChange={(open) => { if (open) { setUrl(null); void checkDss() } }}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className={cn("h-8", dss.enabled && "border-info/60 bg-info/10")}>
          <ShieldCheck /> DSS {dss.enabled ? t("wb.dss.on") : t("wb.dss.offShort")}
        </Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 space-y-3 text-sm">
        <div className="flex items-start justify-between gap-3">
          <div>
            <p className="font-medium">{t("wb.dss.title")}</p>
            <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.dss.about")}</p>
          </div>
          <Switch checked={dss.enabled} onCheckedChange={(enabled) => saveDss({ ...dss, enabled })} aria-label={t("wb.dss.title")} />
        </div>
        <div className="flex gap-2">
          <Input className="font-mono text-xs" value={url ?? dss.url} onChange={(e) => setUrl(e.target.value)} />
          <Button variant="outline" size="sm" className="h-9" onClick={() => saveDss({ ...dss, url: url ?? dss.url })}>{t("wb.dss.check")}</Button>
        </div>
        {dssStatus && (dssStatus.reachable
          ? <Pill tone="success">{t("wb.dss.reachable", { ms: dssStatus.ms })}</Pill>
          : <p className="text-muted-foreground text-xs leading-relaxed break-words">{dssStatus.error}</p>)}
        <pre className="bg-muted overflow-x-auto rounded-md p-2 font-mono text-[11px]">docker compose -f tools/dss/docker-compose.yml up</pre>
      </PopoverContent>
    </Popover>
  )
}

/** The runs of this session: open one again, or start from its options. */
function HistoryDrawer() {
  const { history, openRun, schema } = useWorkbench()
  const { t, time } = useI18n()
  const [open, setOpen] = useState(false)
  return (
    <Sheet open={open} onOpenChange={setOpen}>
      <SheetTrigger asChild>
        <Button variant="outline" size="sm" className="h-8"><History /> {t("wb.history.title")}<span className="text-muted-foreground tabular-nums">{history.length}</span></Button>
      </SheetTrigger>
      <SheetContent className="w-[30rem] sm:max-w-none">
        <SheetHeader>
          <SheetTitle>{t("wb.history.title")}</SheetTitle>
          <SheetDescription>{t("wb.history.hint")}</SheetDescription>
        </SheetHeader>
        <ul className="divide-y overflow-y-auto border-t">
          {history.length === 0 && <li className="text-muted-foreground p-4 text-sm">{t("wb.history.empty")}</li>}
          {history.map((h) => (
            <li key={h.id}>
              <button className="hover:bg-accent/50 flex w-full items-center gap-2 px-4 py-2.5 text-left" onClick={() => { void openRun(h.id); setOpen(false) }}>
                <span className={cn("size-2 shrink-0 rounded-full", h.status === "running" ? "bg-info" : h.success ? (h.overall === "Valid" || !h.overall ? "bg-success" : "bg-warning") : "bg-destructive")} />
                <span className="w-14 shrink-0 text-xs font-semibold">{schema.formats.find((f) => f.id === h.format)?.title}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm">{h.success ? `${h.achievedLevel ?? h.requestedLevel ?? ""} · ${h.fileName ?? ""}` : h.error ?? t("wb.history.running")}</span>
                  <span className="text-muted-foreground block text-xs">{time(h.startedAt)} · {h.totalMs} ms{h.overall ? ` · ${h.overall}` : ""}</span>
                </span>
              </button>
            </li>
          ))}
        </ul>
      </SheetContent>
    </Sheet>
  )
}
