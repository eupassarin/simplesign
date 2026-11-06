import { useEffect, useRef, useState } from "react"
import { Check, FileUp, ListChecks, Loader2, ShieldCheck, TriangleAlert } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { useT } from "@/i18n"
import { api } from "@/lib/api"
import { cn } from "@/lib/utils"
import { Indication } from "../shared/results"
import { Pill } from "../shared/ui"
import { UploadButton } from "../shared/UploadButton"
import { OptionField, OptionScope } from "../workbench/fields"
import { ResultPanel } from "../workbench/ResultPanel"
import type { RunView, ValidationSampleView } from "../workbench/schema"
import { useWorkbench } from "../workbench/state"
import { DssControl, HistoryDrawer } from "../workbench/WorkbenchPage"

interface ConformanceRow {
  sample: ValidationSampleView
  status: "pending" | "running" | "done"
  run?: RunView
}

/**
 * The Validate task: any signed file (PDF, CMS or XML, told apart by its content), the trust to
 * validate it with, and the same result as a signing run: verdicts of SimpleSign and DSS,
 * what is inside the file, the log and the code.
 */
export function ValidatePage() {
  const { schema, frameworks, validateTarget, setValidateTarget, validateOptions, setValidateOption, validate, running, run, dss, openRun } = useWorkbench()
  const t = useT()
  const [samples, setSamples] = useState<ValidationSampleView[]>([])
  const [rows, setRows] = useState<ConformanceRow[] | null>(null)
  const [checking, setChecking] = useState(false)
  const [showConformance, setShowConformance] = useState(false)
  const stop = useRef(false)
  const input = useRef<HTMLInputElement>(null)
  useEffect(() => {
    api.workbench.samples().then(setSamples).catch(() => setSamples([]))
  }, [schema])

  const choose = (target: { fileId: string; name: string; dataId?: string | null; dataName?: string | null }) => {
    setShowConformance(false)
    setValidateTarget(target)
    void validate(target)
  }
  const upload = async (file: File) => {
    const uploaded = await api.uploadFile(file)
    choose({ fileId: uploaded.id, name: uploaded.fileName })
  }

  // Validates every sample and lines the verdicts up with what each sample should get.
  const checkAll = async () => {
    const list = samples
    stop.current = false
    setChecking(true)
    setShowConformance(true)
    setRows(list.map((sample) => ({ sample, status: "pending" })))
    try {
      for (const sample of list) {
        if (stop.current) break
        setRows((current) => current && current.map((r) => (r.sample === sample ? { ...r, status: "running" } : r)))
        const { id } = await api.workbench.start("", { fileId: sample.fileId, dataId: sample.dataId ?? null, settings: validateOptions.validation }, dss.enabled, "validate")
        let result: RunView | undefined
        while (!result) {
          await new Promise((resolve) => setTimeout(resolve, 200))
          result = await api.workbench.run(id)
        }
        const done = result
        setRows((current) => current && current.map((r) => (r.sample === sample ? { ...r, status: "done", run: done } : r)))
      }
    } finally {
      setChecking(false)
    }
  }

  const trust = schema.options.filter((o) => o.id.startsWith("common.validation.") && (!o.framework || frameworks.has(o.framework)))
  const groups = schema.formats.map((f) => ({ format: f, samples: samples.filter((s) => s.format === f.id) })).filter((g) => g.samples.length > 0)
  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-2 border-b px-4 py-3">
        <span className="text-sm">
          {validateTarget
            ? <><span className="font-medium">{validateTarget.name}</span>{validateTarget.dataName && <span className="text-muted-foreground"> + {validateTarget.dataName}</span>}</>
            : <span className="text-muted-foreground">{t("val.noFile")}</span>}
        </span>
        {run && validateTarget?.fileId === run.outputId && <Pill>{schema.formats.find((f) => f.id === run.format)?.title}</Pill>}
        <div className="ml-auto flex items-center gap-2">
          <Button variant="outline" size="sm" className="h-8" onClick={checking ? () => { stop.current = true } : checkAll} disabled={samples.length === 0}>
            {checking ? <Loader2 className="animate-spin" /> : <ListChecks />} {t(checking ? "matrix.stop" : "val.validateAll")}
          </Button>
          <DssControl />
          <HistoryDrawer />
          <Button className="min-w-36" disabled={!validateTarget || running} onClick={() => { setShowConformance(false); void validate() }}>
            {running ? <Loader2 className="animate-spin" /> : <ShieldCheck />} {t("val.validate")}
          </Button>
        </div>
      </div>
      <div className="grid min-h-0 flex-1 lg:grid-cols-[minmax(400px,5fr)_7fr]">
        <div className="min-h-0 space-y-3 overflow-y-auto border-r p-4">
          <section className="bg-card space-y-3 rounded-lg border p-3">
            <div>
              <p className="text-sm font-semibold">{t("val.file")}</p>
              <p className="text-muted-foreground text-xs">{t("val.fileHint")}</p>
            </div>
            <div className="hover:border-foreground/30 hover:bg-accent/30 flex cursor-pointer flex-col items-center gap-1.5 rounded-lg border border-dashed p-5 text-center transition-colors"
              onClick={() => input.current?.click()} onDragOver={(e) => e.preventDefault()}
              onDrop={(e) => { e.preventDefault(); const file = e.dataTransfer.files[0]; if (file) void upload(file) }}>
              <FileUp className="text-muted-foreground size-5" />
              <p className="text-sm font-medium">{t("val.drop")}</p>
              <p className="text-muted-foreground text-xs">PDF · .p7s · .p7m · XML</p>
              <input ref={input} type="file" hidden onChange={(e) => { const file = e.target.files?.[0]; if (file) void upload(file); e.target.value = "" }} />
            </div>
            {validateTarget && (
              <div className="flex flex-wrap items-center gap-2">
                <UploadButton label={t("val.data")} accept="*/*" onUploaded={(f) => choose({ ...validateTarget, dataId: f.id, dataName: f.fileName })} />
                <span className="text-muted-foreground text-xs">{validateTarget.dataName ?? t("val.dataHint")}</span>
              </div>
            )}
          </section>

          <section className="bg-card rounded-lg border">
            <div className="px-3 py-2.5">
              <p className="text-sm font-semibold">{t("val.samples")}</p>
              <p className="text-muted-foreground text-xs">{t("val.samplesHint")}</p>
            </div>
            {groups.map((group) => (
              <div key={group.format.id} className="border-t">
                <p className="text-muted-foreground px-3 pt-2 text-[10px] font-semibold tracking-wide uppercase">{group.format.title}</p>
                <ul className="pb-1">
                  {group.samples.map((s) => (
                    <li key={s.format + s.id}>
                      <button type="button" onClick={() => choose({ fileId: s.fileId, name: s.fileName, dataId: s.dataId })}
                        className={cn("hover:bg-accent/50 flex w-full items-start gap-2 px-3 py-1.5 text-left", validateTarget?.fileId === s.fileId && (validateTarget.dataId ?? null) === (s.dataId ?? null) && "bg-accent/60")}>
                        <span className="min-w-0 flex-1">
                          <span className="block text-sm">{s.title}</span>
                          <span className="text-muted-foreground block text-xs leading-snug">{s.description}</span>
                        </span>
                        {s.expectedIndication && <Indication value={s.expectedIndication as "Valid"} />}
                      </button>
                    </li>
                  ))}
                </ul>
              </div>
            ))}
          </section>

          <section className="bg-card rounded-lg border">
            <div className="px-3 py-2.5">
              <p className="text-sm font-semibold">{t("val.trust")}</p>
              <p className="text-muted-foreground text-xs">{t("val.trustHint")}</p>
            </div>
            <div className="divide-y border-t px-3">
              <OptionScope.Provider value={{ options: validateOptions, set: setValidateOption }}>
                {trust.map((o) => <OptionField key={o.id} option={o} />)}
              </OptionScope.Provider>
            </div>
          </section>
        </div>
        <div className="min-h-0 overflow-y-auto p-4">
          <ResultPanel extra={rows ? {
            id: "conformance",
            open: showConformance,
            label: <>{t("val.conformance")}{checking && <Loader2 className="ml-1 size-3 animate-spin" />}</>,
            content: <Conformance rows={rows} onOpen={(id) => { setShowConformance(false); void openRun(id) }} />,
          } : undefined} />
        </div>
      </div>
    </div>
  )
}

/** Each sample with the verdict it should get, the one SimpleSign gives and the one DSS gives. */
function Conformance({ rows, onOpen }: { rows: ConformanceRow[]; onOpen: (id: string) => void }) {
  const { schema } = useWorkbench()
  const t = useT()
  const done = rows.filter((r) => r.status === "done")
  const matching = done.filter((r) => !r.sample.expectedIndication || r.run?.overall === r.sample.expectedIndication).length
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2 text-sm">
        <Pill tone={done.length > 0 && matching === done.length ? "success" : done.length === 0 ? "default" : "warning"}>{t("val.conformanceSummary", { ok: matching, total: rows.length })}</Pill>
        <span className="text-muted-foreground text-xs">{t("wb.variants.hint")}</span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead /><TableHead>{t("val.sample")}</TableHead><TableHead>{t("val.expected")}</TableHead><TableHead>SimpleSign</TableHead><TableHead>DSS</TableHead><TableHead />
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const ok = row.run && (!row.sample.expectedIndication || row.run.overall === row.sample.expectedIndication)
            const cross = row.run?.crossValidation
            return (
              <TableRow key={row.sample.format + row.sample.id} className={cn(row.run && "hover:bg-accent/50 cursor-pointer", row.run && !ok && "bg-warning/5")}
                onClick={() => row.run && onOpen(row.run.id)}>
                <TableCell className="text-muted-foreground text-xs font-semibold">{schema.formats.find((f) => f.id === row.sample.format)?.title}</TableCell>
                <TableCell className="text-sm whitespace-normal">{row.sample.title}</TableCell>
                <TableCell>{row.sample.expectedIndication ? <Indication value={row.sample.expectedIndication as "Valid"} /> : "—"}</TableCell>
                <TableCell>{row.status === "running" ? <Loader2 className="size-4 animate-spin" /> : row.run?.overall ? <Indication value={row.run.overall} /> : row.run ? <span className="text-destructive text-xs">{row.run.error ?? "—"}</span> : "—"}</TableCell>
                <TableCell className="text-xs">{cross?.available ? cross.signatures.map((s) => s.subIndication ?? s.indication).join(", ") || "—" : "—"}</TableCell>
                <TableCell>{row.run && (ok ? <Check className="text-success size-4" /> : <TriangleAlert className="text-warning size-4" />)}</TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </div>
  )
}
