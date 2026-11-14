import { useState } from "react"
import { CircleAlert, History, Loader2, PenTool, RotateCcw, Shuffle } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle, SheetTrigger } from "@/components/ui/sheet"
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip"
import { useI18n, useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { IssueList, Pill } from "../shared/ui"
import { activeProfile, ProfileMenu, ProfileStrip } from "./profile"
import { OptionForm } from "./OptionForm"
import { StandardBadge } from "./parts"
import { ResultPanel } from "./ResultPanel"
import { asText, type SchemaPreset } from "./schema"
import { pairwise } from "./combinations"
import { useWorkbench, type Strategy } from "./state"

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
  const { schema, format, setFormat, applyPreset, options, evaluation, evaluating, running, sign, reset, updateAll } = useWorkbench()
  const t = useT()
  const current = schema.formats.find((f) => f.id === format)!
  const errors = evaluation?.issues.filter((i) => i.severity === "Error").length ?? 0
  const level = asText(options.level)
  // With ICP-Brasil on, its policies (AD-RB…AD-RA) take the place of the baseline levels.
  const icp = activeProfile(options)?.profile === "IcpBrasil"
  const icpPolicy = asText(options.kind) === "IcpBrasil" ? asText(options.icpPolicy) : null
  const presets = schema.presets.filter((p) => p.formats.includes(format) && (icp ? p.framework === "IcpBrasil" : !p.framework))
  const pressed = (p: SchemaPreset) => (p.framework ? p.set.icpPolicy === icpPolicy : icpPolicy === null && p.set.level === level)
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
          {presets.map((p) => (
            <Tooltip key={p.id}>
              <TooltipTrigger asChild>
                <Button variant={pressed(p) ? "default" : "outline"} size="sm" className="h-8 px-2.5 font-mono text-xs" onClick={() => applyPreset(p)}>{p.title}</Button>
              </TooltipTrigger>
              <TooltipContent>{p.summary}</TooltipContent>
            </Tooltip>
          ))}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <ProfileMenu page="sign" options={options} update={(change) => updateAll((o) => change(o))} />
          <VaryControl />
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
        {errors > 0 && <span className="text-destructive ml-auto flex items-center gap-1"><CircleAlert className="size-3.5" />{t("wb.errors", { n: errors })}</span>}
        {evaluating && <Loader2 className="text-muted-foreground size-3 animate-spin" />}
      </div>
      <ProfileStrip page="sign" options={options} />
    </div>
  )
}

const maxCombinations = 400

/**
 * Combinations: signs once for every value of one option, or for the combinations of several
 * (all of them, or pairwise: every pair of values together at least once), keeping the rest.
 */
function VaryControl() {
  const { schema, isVisible, variantValues, runVariants, variantsRunning, running, evaluation } = useWorkbench()
  const t = useT()
  const [open, setOpen] = useState(false)
  const [picked, setPicked] = useState<string[] | null>(null)
  const [strategy, setStrategy] = useState<Strategy>("all")
  const candidates = schema.options.filter((o) => o.kind === "choice" && o.path && o.support === "supported" && isVisible(o) && variantValues(o).length > 1)
  const ids = (picked ?? [candidates.find((o) => o.path === "level")?.id ?? candidates[0]?.id]).filter((id): id is string => !!id && candidates.some((o) => o.id === id))
  const chosen = candidates.filter((o) => ids.includes(o.id))
  const lists = chosen.map((o) => variantValues(o).map((v) => v.value))
  const total = lists.reduce((n, l) => n * l.length, chosen.length > 0 ? 1 : 0)
  const pairs = chosen.length > 2 ? pairwise(lists).length : total
  const count = strategy === "pairs" ? pairs : total
  const toggle = (id: string) => setPicked(ids.includes(id) ? ids.filter((x) => x !== id) : [...ids, id])
  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" className="h-8"><Shuffle /> {t("wb.variants.title")}</Button>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-[26rem] space-y-3 text-sm">
        <div>
          <p className="font-medium">{t("wb.variants.title")}</p>
          <p className="text-muted-foreground text-xs leading-relaxed">{t("wb.variants.about")}</p>
        </div>
        <div className="max-h-72 space-y-3 overflow-y-auto rounded-md border p-2">
          {schema.sections.map((section) => {
            const inSection = candidates.filter((o) => o.section === section.id)
            return inSection.length === 0 ? null : (
              <div key={section.id} className="space-y-1">
                <p className="text-muted-foreground text-[10px] font-semibold tracking-wide uppercase">{section.title}</p>
                {inSection.map((o) => (
                  <label key={o.id} className="flex items-center gap-2 text-sm">
                    <Checkbox checked={ids.includes(o.id)} onCheckedChange={() => toggle(o.id)} />
                    <span className="flex-1">{o.title}</span>
                    <span className="text-muted-foreground text-xs tabular-nums">{variantValues(o).length}</span>
                  </label>
                ))}
              </div>
            )
          })}
        </div>
        <div className="flex items-center gap-2 text-xs">
          <button type="button" className="text-muted-foreground hover:text-foreground underline underline-offset-2" onClick={() => { setPicked(candidates.map((o) => o.id)); setStrategy("pairs") }}>{t("wb.variants.everything")}</button>
          <button type="button" className="text-muted-foreground hover:text-foreground underline underline-offset-2" onClick={() => setPicked([])}>{t("wb.clear")}</button>
        </div>
        {chosen.length > 1 && (
          <div className="bg-muted flex rounded-md p-0.5 text-xs" role="radiogroup">
            {(["all", "pairs"] as const).map((s) => (
              <button key={s} role="radio" aria-checked={strategy === s} onClick={() => setStrategy(s)}
                className={cn("flex-1 rounded px-2 py-1 font-medium", strategy === s ? "bg-background shadow-sm" : "text-muted-foreground")}>
                {t(s === "all" ? "wb.variants.all" : "wb.variants.pairs")} · {s === "all" ? total : pairs}
              </button>
            ))}
          </div>
        )}
        {count > maxCombinations && <p className="text-destructive text-xs">{t("wb.variants.tooMany", { n: count, max: maxCombinations })}</p>}
        <Button className="w-full" disabled={chosen.length === 0 || count > maxCombinations || variantsRunning || running || !evaluation}
          onClick={() => { setOpen(false); void runVariants(chosen, chosen.length > 1 ? strategy : "all") }}>
          {variantsRunning ? <Loader2 className="animate-spin" /> : <Shuffle />}
          {t("wb.variants.run", { n: count })}
        </Button>
      </PopoverContent>
    </Popover>
  )
}

/** The runs of this session: open one again, or start from its options. */
export function HistoryDrawer() {
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
                {h.kind === "validate" && <Pill>{t("app.mode.validate")}</Pill>}
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm">{h.success ? [h.achievedLevel ?? h.requestedLevel, h.fileName].filter(Boolean).join(" · ") : h.error ?? t("wb.history.running")}</span>
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
