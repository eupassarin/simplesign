import { useMemo, useState } from "react"
import { Globe, Loader2 } from "lucide-react"
import { Input } from "@/components/ui/input"
import { useT } from "@/i18n"
import { cn } from "@/lib/utils"
import { StandardBadge } from "./parts"
import type { Format, RunLogEntry, SchemaStage } from "./schema"
import { useWorkbench } from "./state"

const levelTone: Record<string, string> = {
  Trace: "bg-muted-foreground/30",
  Debug: "bg-muted-foreground/50",
  Information: "bg-info",
  Warning: "bg-warning",
  Error: "bg-destructive",
  Critical: "bg-destructive",
}

/**
 * The log of a run: every library event and network request, grouped by the stage of the
 * signature it belongs to (each stage names the clause of the standard it implements), or in
 * the order they happened.
 */
export function LogView({ logs, format, running }: { logs: RunLogEntry[]; format: Format; running: boolean }) {
  const { schema } = useWorkbench()
  const t = useT()
  const [view, setView] = useState<"stages" | "timeline">("stages")
  const [details, setDetails] = useState(true)
  const [filter, setFilter] = useState("")
  const shown = useMemo(() => logs.filter((l) =>
    (details || (l.level !== "Debug" && l.level !== "Trace")) && (filter === "" || l.message.toLowerCase().includes(filter.toLowerCase()) || String(l.eventId) === filter)),
  [logs, details, filter])
  const stages = useMemo(() => {
    const byStage = new Map<string, RunLogEntry[]>()
    for (const entry of shown) byStage.set(entry.stage, [...(byStage.get(entry.stage) ?? []), entry])
    // Stages in the order the run reached them.
    return [...byStage.entries()].sort((a, b) => a[1][0].seq - b[1][0].seq)
      .map(([id, entries]) => ({ stage: schema.stages.find((s) => s.id === id), id, entries }))
  }, [shown, schema.stages])

  if (logs.length === 0) {
    return <p className="text-muted-foreground py-8 text-center text-sm">{running ? <Loader2 className="mx-auto size-4 animate-spin" /> : t("wb.log.empty")}</p>
  }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="bg-muted flex rounded-md p-0.5 text-xs">
          {(["stages", "timeline"] as const).map((v) => (
            <button key={v} onClick={() => setView(v)} className={cn("rounded px-2.5 py-1 font-medium", view === v ? "bg-background shadow-sm" : "text-muted-foreground")}>
              {t(v === "stages" ? "wb.log.byStage" : "wb.log.timeline")}
            </button>
          ))}
        </div>
        <label className="text-muted-foreground flex items-center gap-1.5 text-xs">
          <input type="checkbox" checked={details} onChange={(e) => setDetails(e.target.checked)} /> {t("wb.log.debug")}
        </label>
        <Input className="h-7 max-w-48 text-xs" placeholder={t("wb.log.filter")} value={filter} onChange={(e) => setFilter(e.target.value)} />
        <span className="text-muted-foreground ml-auto text-xs tabular-nums">
          {t("wb.log.count", { n: shown.length, total: logs.length })} {running && <Loader2 className="ml-1 inline size-3 animate-spin" />}
        </span>
      </div>
      {view === "timeline" ? (
        <div className="rounded-lg border"><Rows entries={shown} stages={schema.stages} showStage /></div>
      ) : (
        <ol className="space-y-2">
          {stages.map(({ stage, id, entries }, index) => (
            <li key={id} className="rounded-lg border">
              <StageHeader index={index + 1} stage={stage} id={id} entries={entries} format={format} />
              <Rows entries={entries} stages={schema.stages} />
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}

function StageHeader({ index, stage, id, entries, format }: { index: number; stage?: SchemaStage; id: string; entries: RunLogEntry[]; format: Format }) {
  const t = useT()
  const worst = entries.some((e) => e.level === "Error" || e.level === "Critical") ? "Error" : entries.some((e) => e.level === "Warning") ? "Warning" : "Information"
  const span = entries[entries.length - 1].ms - entries[0].ms
  const standards = stage?.standards[format] ?? []
  return (
    <div className="bg-muted/40 flex flex-wrap items-center gap-x-2 gap-y-1 border-b px-3 py-2">
      <span className={cn("flex size-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold", worst === "Error" ? "bg-destructive text-white" : worst === "Warning" ? "bg-warning text-black" : "bg-primary text-primary-foreground")}>{index}</span>
      <span className="text-sm font-semibold">{stage?.title ?? id}</span>
      {standards.length > 0 && <StandardBadge explanation={{ title: stage!.title, summary: stage!.summary, standards }} />}
      <span className="text-muted-foreground min-w-0 flex-1 truncate text-xs">{stage?.summary}</span>
      <span className="text-muted-foreground shrink-0 text-xs tabular-nums">{t("wb.log.stageSpan", { n: entries.length, at: entries[0].ms, ms: span })}</span>
    </div>
  )
}

function Rows({ entries, stages, showStage }: { entries: RunLogEntry[]; stages: SchemaStage[]; showStage?: boolean }) {
  return (
    <ul className="divide-y font-mono text-[11px] leading-relaxed">
      {entries.map((e) => (
        <li key={e.seq} className={cn("flex items-start gap-2 px-3 py-1", e.level === "Warning" && "bg-warning/5", (e.level === "Error" || e.level === "Critical") && "bg-destructive/5")}>
          <span className="text-muted-foreground w-12 shrink-0 text-right tabular-nums">{e.ms} ms</span>
          <span className={cn("mt-1.5 size-1.5 shrink-0 rounded-full", levelTone[e.level])} title={e.level} />
          {e.source === "network"
            ? <Globe className="text-muted-foreground mt-0.5 size-3 shrink-0" />
            : <span className="text-muted-foreground w-9 shrink-0 tabular-nums" title="EventId">{e.eventId || ""}</span>}
          {showStage && <span className="bg-muted text-muted-foreground shrink-0 rounded px-1 font-sans text-[10px]">{stages.find((s) => s.id === e.stage)?.title ?? e.stage}</span>}
          <span className={cn("min-w-0 flex-1 break-words", (e.level === "Debug" || e.level === "Trace") && "text-muted-foreground")}>{e.message}</span>
        </li>
      ))}
    </ul>
  )
}
