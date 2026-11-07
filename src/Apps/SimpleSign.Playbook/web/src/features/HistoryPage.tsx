import { useEffect, useState } from "react"
import { ChevronRight, FileArchive, FileText } from "lucide-react"
import { toast } from "sonner"
import { Pill } from "@/components/parts"
import { Button } from "@/components/ui/button"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { useI18n } from "@/i18n"
import { api } from "@/lib/api"
import type { RunRecord, WorkspaceView } from "@/lib/types"
import { RunHeader } from "./RunPage"
import { StatusPill, StepDetails } from "./shared"

/** Past runs of the workspace: open one, and compare it with another step by step. */
export function HistoryPage({ workspace }: { workspace: WorkspaceView }) {
  const { t, dateTime } = useI18n()
  const [selected, setSelected] = useState<string | null>(workspace.runs[0]?.id ?? null)
  const [compareId, setCompareId] = useState<string>("none")
  const [run, setRun] = useState<RunRecord | null>(null)
  const [other, setOther] = useState<RunRecord | null>(null)

  useEffect(() => {
    if (selected) api.run(selected).then(setRun).catch((e: Error) => toast.error(e.message))
  }, [selected])
  useEffect(() => {
    if (compareId === "none") setOther(null)
    else api.run(compareId).then(setOther).catch((e: Error) => toast.error(e.message))
  }, [compareId])

  if (workspace.runs.length === 0) return <p className="text-muted-foreground text-sm">{t("history.empty")}</p>
  return (
    <div className="grid gap-6 lg:grid-cols-[300px_1fr]">
      <ul className="divide-y self-start rounded-md border">
        {workspace.runs.map((r) => (
          <li key={r.id}>
            <button type="button" onClick={() => setSelected(r.id)}
              className={`hover:bg-muted/50 w-full space-y-1 px-3 py-2 text-left ${selected === r.id ? "bg-muted" : ""}`}>
              <div className="flex items-center gap-2"><StatusPill status={r.status} /><span className="text-xs">{dateTime(r.startedAt)}</span></div>
              <div className="text-muted-foreground text-xs">{t("run.summary", { passed: r.summary.passed, failed: r.summary.failed, errors: r.summary.errors, skipped: r.summary.skipped })}</div>
            </button>
          </li>
        ))}
      </ul>
      {run && (
        <div className="min-w-0 space-y-4">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-muted-foreground text-sm">{t("history.compare")}</span>
            <Select value={compareId} onValueChange={setCompareId}>
              <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="none">{t("history.compareNone")}</SelectItem>
                {workspace.runs.filter((r) => r.id !== run.id).map((r) => <SelectItem key={r.id} value={r.id}>{dateTime(r.startedAt)} · {r.status}</SelectItem>)}
              </SelectContent>
            </Select>
            <div className="ml-auto flex gap-2">
              <Button variant="outline" size="sm" asChild><a href={api.fileUrl(run.id, "report.html")} target="_blank" rel="noreferrer"><FileText /> {t("run.report")}</a></Button>
              <Button variant="outline" size="sm" asChild><a href={api.fileUrl(run.id, "report.md", true)}><FileText /> .md</a></Button>
              <Button variant="outline" size="sm" asChild><a href={api.zipUrl(run.id)}><FileArchive /> {t("run.zip")}</a></Button>
            </div>
          </div>
          <RunHeader run={run} />
          <ul className="divide-y rounded-md border">
            {run.steps.map((step) => {
              const before = other?.steps.find((s) => s.stepId === step.stepId)
              const changed = !!before && before.status !== step.status
              return (
                <li key={step.stepId}>
                  <Collapsible>
                    <CollapsibleTrigger className="group flex w-full items-center gap-2 px-3 py-2 text-left text-sm">
                      <ChevronRight className="size-4 shrink-0 transition-transform group-data-[state=open]:rotate-90" />
                      <span className="text-muted-foreground w-32 shrink-0 truncate text-xs">{step.sectionTitle}</span>
                      <span className="min-w-0 flex-1 truncate">{step.title}</span>
                      {before && <StatusPill status={before.status} />}
                      {before && <span className="text-muted-foreground">→</span>}
                      <StatusPill status={step.status} />
                      {changed && <Pill tone="warning">{t("history.changed")}</Pill>}
                    </CollapsibleTrigger>
                    <CollapsibleContent className="border-t px-4 py-3">
                      <StepDetails runId={run.id} step={step} />
                    </CollapsibleContent>
                  </Collapsible>
                </li>
              )
            })}
          </ul>
        </div>
      )}
    </div>
  )
}
